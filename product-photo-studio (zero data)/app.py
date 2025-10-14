import os
import base64
import uuid
from io import BytesIO
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    current_user, login_required
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image, ImageOps
from dotenv import load_dotenv
from google import genai
from google.genai import types
import stripe
from sqlalchemy import text
import qrcode

# --- Env & Google GenAI client ---
load_dotenv()
client = genai.Client(api_key=os.getenv("GOOGLE_API_KEY"))

# --- Stripe config (env) ---
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
APP_BASE_URL = os.getenv("APP_BASE_URL", "http://localhost:5000")

# New pricing structure with multiple tiers
STRIPE_PRICE_ID_STARTER = os.getenv("STRIPE_PRICE_ID_STARTER", "price_starter_monthly")
STRIPE_PRICE_ID_CREATOR = os.getenv("STRIPE_PRICE_ID_CREATOR", "price_creator_monthly")
STRIPE_PRICE_ID_ENTERPRISE = os.getenv("STRIPE_PRICE_ID_ENTERPRISE", "price_enterprise_monthly")
STRIPE_PRICE_ID_STARTER_ANNUAL = os.getenv("STRIPE_PRICE_ID_STARTER_ANNUAL", "price_starter_annual")
STRIPE_PRICE_ID_CREATOR_ANNUAL = os.getenv("STRIPE_PRICE_ID_CREATOR_ANNUAL", "price_creator_annual")
STRIPE_PRICE_ID_ENTERPRISE_ANNUAL = os.getenv("STRIPE_PRICE_ID_ENTERPRISE_ANNUAL", "price_enterprise_annual")

STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")

# Creator tier 50% off first month coupon
STRIPE_CREATOR_COUPON = os.getenv("STRIPE_CREATOR_COUPON", "FIRSTMONTH50")

# --- Flask setup ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-change-this')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['OUTPUT_FOLDER'] = 'static/outputs'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['OUTPUT_FOLDER'], exist_ok=True)
app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024  # 20MB max

# Sessions are NOT permanent by default; be explicit:
app.config['SESSION_PERMANENT'] = False
# Harden remember-cookie when (and only when) user opts in:
app.config['REMEMBER_COOKIE_SECURE'] = True       # serve over HTTPS
app.config['REMEMBER_COOKIE_HTTPONLY'] = True
app.config['REMEMBER_COOKIE_SAMESITE'] = "Lax"

# --- DB & Login ---
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to continue.'
login_manager.login_message_category = 'info'

# --- Credit allocation by tier ---
CREDITS_PER_IMAGE = 500  # Updated from 250 to 500

PLAN_CREDITS = {
    'free': 10000,        # 20 images
    'starter': 120000,    # 240 images
    'creator': 300000,    # 600 images
    'enterprise': 800000, # 1600 images
    'legacy_pro': 200000  # Grandfathered old Pro users (400 images at 500 credits)
}

# Map Stripe price IDs to plan tiers
PRICE_ID_TO_TIER = {
    STRIPE_PRICE_ID_STARTER: 'starter',
    STRIPE_PRICE_ID_CREATOR: 'creator',
    STRIPE_PRICE_ID_ENTERPRISE: 'enterprise',
    STRIPE_PRICE_ID_STARTER_ANNUAL: 'starter',
    STRIPE_PRICE_ID_CREATOR_ANNUAL: 'creator',
    STRIPE_PRICE_ID_ENTERPRISE_ANNUAL: 'enterprise',
}

# --- User Model ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    generation_count = db.Column(db.Integer, default=0)

    # Paywall fields
    is_subscribed = db.Column(db.Boolean, default=False, nullable=False)
    stripe_customer_id = db.Column(db.String(120), nullable=True)
    plan_tier = db.Column(db.String(20), default='free')  # 'free', 'starter', 'creator', 'enterprise', 'legacy_pro'
    
    # Credit system fields
    credits_remaining = db.Column(db.Integer, default=10000)  # Free tier gets 10,000 credits (20 images)
    credits_limit = db.Column(db.Integer, default=10000)
    credits_reset_date = db.Column(db.DateTime, nullable=True)
    
    # Relationship to generations
    generations = db.relationship('Generation', backref='user', lazy=True, order_by='Generation.created_at.desc()')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# --- Generation Model ---
class Generation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    input_image_path = db.Column(db.String(255), nullable=False)
    output_image_path = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# --- Mobile upload token model (QR flow) ---
class MobileUploadToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(64), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    used = db.Column(db.Boolean, default=False, nullable=False)
    image_path = db.Column(db.String(255), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Single white background prompt ---
WHITE_BACKGROUND_PROMPT = """Using the provided image, identify the product in the photo and isolate it from all other objects
around it. Place it on a white studio background with soft professional lighting. The product should be shot on a 50 mm lens and face directly 
towards the lens. If and only when the product is a shoe, the product can be placed sideways with the lens."""

## Prompt 2 - Remove BKGRD only (cutout): """Using the provided image, identify the product in the photo and isolate it from all other objects around it. Place the product on a white background. Keep the product’s original size, color, shape, and lighting unchanged. Add a soft, neutral shadow directly beneath the product for realism. Do not enhance, retouch, or alter the product in any way.""" ##

## Prompt 3 - MAKEUP: "Identify the single primary product in the uploaded photo, disregard and remove all other objects and the original background, and place the product on a pure white seamless studio backdrop. Light it dramatically with a directional key and a subtle rim light to create crisp yet realistic contrast, maintaining accurate color, fine surface texture, and a natural contact shadow (with a faint floor reflection if appropriate). Compose as a straight-on 50 mm–equivalent shot at eye level; preserve true proportions and label legibility, add nothing (no props/text/watermarks), eliminate artifacts or halos, and deliver a hyper-photorealistic, high-resolution result." ##

## Prompt 4 - for 2 packs ##

## Lay Flat prompt

## invivible mannequin prompt

## product staging prompt

##custom background font (this should not be 100% user-generated, it should be paired with the standard StudioSix system prompt as a prefix it should have the best 100% prefic as the best)


# --- Stripe helpers ---
def ensure_stripe_customer(user: User):
    if user.stripe_customer_id:
        return user.stripe_customer_id
    customer = stripe.Customer.create(email=user.email)
    user.stripe_customer_id = customer.id
    db.session.commit()
    return user.stripe_customer_id

# --- lightweight auto-migration for SQLite ---
def _column_exists(table: str, column: str) -> bool:
    res = db.session.execute(text(f"PRAGMA table_info({table})")).fetchall()
    return any(row[1] == column for row in res)

def _table_exists(table: str) -> bool:
    res = db.session.execute(text("SELECT name FROM sqlite_master WHERE type='table' AND name=:table"), {"table": table}).fetchall()
    return len(res) > 0

def ensure_paywall_columns():
    added = False
    if not _column_exists("user", "is_subscribed"):
        db.session.execute(text("ALTER TABLE user ADD COLUMN is_subscribed BOOLEAN NOT NULL DEFAULT 0"))
        added = True
    if not _column_exists("user", "stripe_customer_id"):
        db.session.execute(text("ALTER TABLE user ADD COLUMN stripe_customer_id VARCHAR(120)"))
        added = True
    if not _column_exists("user", "plan_tier"):
        db.session.execute(text("ALTER TABLE user ADD COLUMN plan_tier VARCHAR(20) DEFAULT 'free'"))
        added = True
    if not _column_exists("user", "credits_remaining"):
        db.session.execute(text("ALTER TABLE user ADD COLUMN credits_remaining INTEGER DEFAULT 10000"))
        added = True
    if not _column_exists("user", "credits_limit"):
        db.session.execute(text("ALTER TABLE user ADD COLUMN credits_limit INTEGER DEFAULT 10000"))
        added = True
    if not _column_exists("user", "credits_reset_date"):
        db.session.execute(text("ALTER TABLE user ADD COLUMN credits_reset_date DATETIME"))
        added = True
    if added:
        db.session.commit()

# --- Jinja filters ---
@app.template_filter('format_number')
def format_number(value):
    """Format number with commas for thousands"""
    try:
        return "{:,}".format(int(value))
    except (ValueError, TypeError):
        return value

# -----------------------
# Marketing Pages
# -----------------------
@app.route("/resources")
def resources():
    """Resources page with use cases and best practices"""
    return render_template("resources.html")

@app.route("/pricing")
def pricing():
    """Pricing page with subscription tiers"""
    return render_template("pricing.html")

# -----------------------
# Auth Routes
# -----------------------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        if not email or not password:
            flash("Email and password are required.", "error")
            return render_template("signup.html")

        existing = User.query.filter_by(email=email).first()
        if existing:
            flash("Email already registered. Please log in.", "error")
            return redirect(url_for('login', next=request.args.get('next') or url_for('index')))

        user = User(email=email)
        user.set_password(password)
        user.plan_tier = 'free'
        user.credits_remaining = PLAN_CREDITS['free']
        user.credits_limit = PLAN_CREDITS['free']
        db.session.add(user)
        db.session.commit()

        login_user(user)
        next_page = request.args.get('next') or request.form.get('next') or url_for('index')
        return redirect(next_page)

    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(request.args.get('next') or url_for('index'))

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        next_page = request.args.get('next') or request.form.get('next') or url_for('index')

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            remember = bool(request.form.get("remember"))
            login_user(user, remember=remember)
            return redirect(next_page)

        flash("Invalid email or password", "error")

    return render_template("login.html")

@app.route("/logout")
def logout():
    if current_user.is_authenticated:
        logout_user()
        flash("You have been logged out.", "info")
    return redirect(url_for('index'))

# -----------------------
# Account Page
# -----------------------
@app.route("/account")
@login_required
def account():
    """Account dashboard showing plan, credits, and usage"""
    return render_template("account.html", user=current_user)

# -----------------------
# Billing
# -----------------------
@app.route("/upgrade")
def upgrade():
    """
    Upgrade to a paid plan. Accepts ?plan=starter|creator|enterprise
    Default to 'creator' (most popular) if not specified
    """
    if not current_user.is_authenticated:
        return redirect(url_for('signup', next=url_for('upgrade')))

    if current_user.is_subscribed:
        return redirect(url_for('index'))

    # Get requested plan from query param
    plan = request.args.get('plan', 'creator').lower()
    billing = request.args.get('billing', 'monthly').lower()  # 'monthly' or 'annual'
    
    # Map plan to Stripe price ID
    price_id_map = {
        'starter': STRIPE_PRICE_ID_STARTER if billing == 'monthly' else STRIPE_PRICE_ID_STARTER_ANNUAL,
        'creator': STRIPE_PRICE_ID_CREATOR if billing == 'monthly' else STRIPE_PRICE_ID_CREATOR_ANNUAL,
        'enterprise': STRIPE_PRICE_ID_ENTERPRISE if billing == 'monthly' else STRIPE_PRICE_ID_ENTERPRISE_ANNUAL,
    }
    
    price_id = price_id_map.get(plan)
    if not price_id or not stripe.api_key:
        flash("Billing is not configured. Please contact support.", "error")
        return redirect(url_for('index'))

    customer_id = ensure_stripe_customer(current_user)
    
    # For Creator monthly plan, auto-apply 50% off first month coupon
    discounts = []
    if plan == 'creator' and billing == 'monthly' and STRIPE_CREATOR_COUPON:
        discounts = [{'coupon': STRIPE_CREATOR_COUPON}]
    
    session = stripe.checkout.Session.create(
        mode="subscription",
        customer=customer_id,
        line_items=[{"price": price_id, "quantity": 1}],
        discounts=discounts,
        success_url=f"{APP_BASE_URL}/post-checkout?session_id={{CHECKOUT_SESSION_ID}}",
        cancel_url=f"{APP_BASE_URL}/",
        allow_promotion_codes=True,
        billing_address_collection="auto",
    )
    return redirect(session.url, code=303)

@app.get("/post-checkout")
def post_checkout():
    """
    Land here after Stripe Checkout success.
    Verify session and activate subscription immediately.
    """
    session_id = request.args.get("session_id")
    if not session_id:
        flash("Missing checkout session.", "error")
        return redirect(url_for('index'))

    try:
        sess = stripe.checkout.Session.retrieve(session_id, expand=['line_items'])
        customer_id = sess.get("customer")
        if not customer_id:
            raise ValueError("No Stripe customer on session")

        # Get the price ID to determine which tier was purchased
        price_id = None
        if sess.get('line_items') and sess['line_items'].get('data'):
            price_id = sess['line_items']['data'][0]['price']['id']

        # Determine tier from price ID
        tier = PRICE_ID_TO_TIER.get(price_id, 'creator')  # Default to creator if unknown

        user = User.query.filter_by(stripe_customer_id=customer_id).first()
        if user:
            user.is_subscribed = True
            user.plan_tier = tier
            user.credits_remaining = PLAN_CREDITS[tier]
            user.credits_limit = PLAN_CREDITS[tier]
            db.session.commit()
        elif current_user.is_authenticated:
            current_user.stripe_customer_id = customer_id
            current_user.is_subscribed = True
            current_user.plan_tier = tier
            current_user.credits_remaining = PLAN_CREDITS[tier]
            current_user.credits_limit = PLAN_CREDITS[tier]
            db.session.commit()

        return redirect(url_for('index', upgraded=1))

    except Exception as e:
        flash("Thanks! Your payment succeeded. Access will unlock momentarily.", "info")
        return redirect(url_for('index'))

@app.route("/billing-portal")
@login_required
def billing_portal():
    customer_id = ensure_stripe_customer(current_user)
    session = stripe.billing_portal.Session.create(
        customer=customer_id,
        return_url=f"{APP_BASE_URL}/account",
    )
    return redirect(session.url, code=303)

@app.post("/stripe/webhook")
def stripe_webhook():
    payload = request.get_data(as_text=True)
    sig_header = request.headers.get("Stripe-Signature", "")
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except Exception as e:
        return jsonify(success=False, error=str(e)), 400

    if event["type"] == "checkout.session.completed":
        data = event["data"]["object"]
        customer_id = data.get("customer")
        
        # Get price ID from line items
        if customer_id:
            try:
                session = stripe.checkout.Session.retrieve(data['id'], expand=['line_items'])
                price_id = None
                if session.get('line_items') and session['line_items'].get('data'):
                    price_id = session['line_items']['data'][0]['price']['id']
                
                tier = PRICE_ID_TO_TIER.get(price_id, 'creator')
                
                user = User.query.filter_by(stripe_customer_id=customer_id).first()
                if user:
                    user.is_subscribed = True
                    user.plan_tier = tier
                    user.credits_remaining = PLAN_CREDITS[tier]
                    user.credits_limit = PLAN_CREDITS[tier]
                    db.session.commit()
            except Exception as e:
                print(f"Error processing checkout.session.completed: {e}")

    if event["type"] in ("customer.subscription.updated", "customer.subscription.deleted"):
        data = event["data"]["object"]
        customer_id = data.get("customer")
        status = data.get("status")
        
        if customer_id:
            # Get price ID from subscription items
            price_id = None
            if data.get('items') and data['items'].get('data'):
                price_id = data['items']['data'][0]['price']['id']
            
            tier = PRICE_ID_TO_TIER.get(price_id, 'creator')
            
            user = User.query.filter_by(stripe_customer_id=customer_id).first()
            if user:
                is_active = status in ("active", "trialing")
                user.is_subscribed = is_active
                if is_active:
                    user.plan_tier = tier
                    user.credits_remaining = PLAN_CREDITS[tier]
                    user.credits_limit = PLAN_CREDITS[tier]
                else:
                    # Subscription cancelled - revert to free
                    user.plan_tier = 'free'
                    user.credits_remaining = PLAN_CREDITS['free']
                    user.credits_limit = PLAN_CREDITS['free']
                db.session.commit()

    return jsonify(success=True), 200

# -----------------------
# Unified Page
# -----------------------
@app.get("/")
def index():
    if request.args.get("upgraded") == "1":
        flash("Thanks for upgrading! Your subscription is now active.", "success")

    is_authed = bool(current_user.is_authenticated) if current_user else False
    is_subscribed = bool(getattr(current_user, "is_subscribed", False)) if is_authed else False

    # Free tier gets 1 free generation for trial (20 images worth of credits = 10,000)
    free_cap = 1
    used = int(getattr(current_user, "generation_count", 0)) if is_authed else 0
    free_uses_left = max(0, free_cap - used) if not is_subscribed and is_authed else None
    
    user_generations = []
    if is_authed:
        user_generations = current_user.generations

    return render_template(
        "index.html",
        user=current_user,
        input_image=None,
        output_image=None,
        error=None,
        is_authed=is_authed,
        is_subscribed=is_subscribed,
        free_uses_left=free_uses_left,
        user_generations=user_generations,
    )

# -----------------------
# Load a previous generation
# -----------------------
@app.get("/generation/<int:generation_id>")
def view_generation(generation_id):
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    
    generation = Generation.query.filter_by(id=generation_id, user_id=current_user.id).first()
    if not generation:
        flash("Generation not found.", "error")
        return redirect(url_for('index'))
    
    user_generations = current_user.generations
    
    return render_template(
        "index.html",
        user=current_user,
        input_image=generation.input_image_path,
        output_image=generation.output_image_path,
        error=None,
        is_authed=True,
        is_subscribed=current_user.is_subscribed,
        free_uses_left=None,
        user_generations=user_generations,
        selected_generation_id=generation_id,
    )

# -----------------------
# Transform Action
# -----------------------
@app.post("/transform")
def transform():
    if not current_user.is_authenticated:
        return redirect(url_for('signup', next=url_for('index')))

    # Check credits
    if current_user.credits_remaining < CREDITS_PER_IMAGE:
        if current_user.is_subscribed:
            flash("You've used all your monthly credits. They'll reset at the start of next month.", "info")
        else:
            flash("You've used all your free credits. Upgrade to continue.", "info")
        return redirect(url_for('upgrade'))

    input_image = None
    output_image = None
    error = None

    file = request.files.get("image")
    if not file or not file.filename:
        flash("Please choose an image to upload.", "error")
        return redirect(url_for('index'))

    try:
        filename = secure_filename(file.filename)
        if not filename:
            raise ValueError("Invalid filename.")
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        filename = f"{timestamp}_{filename}"
        input_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(input_path)
        input_image = "/" + input_path.replace("\\", "/")

        # Resize: keep aspect ratio; longest side = 1024 px
        with Image.open(input_path) as img:
            img = ImageOps.exif_transpose(img).convert("RGB")
            w, h = img.size
            longest = max(w, h)
            scale = 1024.0 / float(longest) if longest != 0 else 1.0
            new_w = max(1, int(round(w * scale)))
            new_h = max(1, int(round(h * scale)))
            img = img.resize((new_w, new_h), Image.LANCZOS)

            # Use Google Generative AI
            response = client.models.generate_content(
                model="gemini-2.5-flash-image-preview",
                contents=[img, WHITE_BACKGROUND_PROMPT],
            )
            
            image_parts = [
                part.inline_data.data
                for part in response.candidates[0].content.parts
                if part.inline_data
            ]
            
            if not image_parts:
                raise ValueError("No image was generated in the response")
            
            generated_image = Image.open(BytesIO(image_parts[0]))
            base_name, _ = os.path.splitext(filename)
            safe_base = secure_filename(base_name) or "output"
            output_filename = f"genai_white_{safe_base}.png"
            output_path = os.path.join(app.config['OUTPUT_FOLDER'], output_filename)
            generated_image.save(output_path, format="PNG")
            output_image = "/" + output_path.replace("\\", "/")

        generation = Generation(
            user_id=current_user.id,
            input_image_path=input_image,
            output_image_path=output_image,
        )
        db.session.add(generation)
        
        # Deduct credits
        current_user.credits_remaining = max(0, current_user.credits_remaining - CREDITS_PER_IMAGE)
        current_user.generation_count = (current_user.generation_count or 0) + 1
        db.session.commit()

    except Exception as e:
        error = f"Error generating image: {str(e)}"
        flash(error, "error")

    is_authed = True
    is_subscribed = bool(getattr(current_user, "is_subscribed", False))
    free_cap = 1
    used = int(getattr(current_user, "generation_count", 0))
    free_uses_left = max(0, free_cap - used) if not is_subscribed else None
    
    user_generations = current_user.generations

    return render_template(
        "index.html",
        user=current_user,
        input_image=input_image,
        output_image=output_image,
        error=error,
        is_authed=is_authed,
        is_subscribed=is_subscribed,
        free_uses_left=free_uses_left,
        user_generations=user_generations,
    )

# -----------------------
# Mobile Upload (QR flow)
# -----------------------
@app.post("/mobile/start")
def mobile_start():
    t = MobileUploadToken(
        token=uuid.uuid4().hex,
        user_id=current_user.id if current_user.is_authenticated else None
    )
    db.session.add(t)
    db.session.commit()

    upload_url = f"{APP_BASE_URL}/mobile/upload/{t.token}"
    return jsonify({
        "token": t.token,
        "upload_url": upload_url,
        "qrcode_url": url_for("mobile_qrcode", token=t.token, _external=True)
    })

@app.get("/mobile/qrcode/<token>")
def mobile_qrcode(token):
    url = f"{APP_BASE_URL}/mobile/upload/{token}"
    img = qrcode.make(url)
    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png")

@app.get("/mobile/upload/<token>")
def mobile_upload_get(token):
    t = MobileUploadToken.query.filter_by(token=token).first()
    if not t or t.used:
        return "Link expired or already used.", 410
    return render_template("mobile_upload.html", token=token)

@app.post("/mobile/upload/<token>")
def mobile_upload_post(token):
    t = MobileUploadToken.query.filter_by(token=token).first()
    if not t or t.used:
        return "Link expired or already used.", 410

    f = request.files.get("image")
    if not f or not f.filename:
        flash("Please choose a photo.", "error")
        return render_template("mobile_upload.html", token=token)

    filename = secure_filename(f.filename) or f"{token}.jpg"
    path = os.path.join(app.config['UPLOAD_FOLDER'], f"mobile_{token}_{filename}")
    f.save(path)
    t.image_path = "/" + path.replace("\\", "/")
    t.used = True
    db.session.commit()
    return render_template("mobile_upload.html", token=token, success=True)

@app.get("/mobile/status/<token>")
def mobile_status(token):
    t = MobileUploadToken.query.filter_by(token=token).first()
    if not t:
        return jsonify({"ok": False, "error": "not_found"}), 404
    if t.used and t.image_path:
        return jsonify({"ok": True, "ready": True, "image_url": t.image_path})
    return jsonify({"ok": True, "ready": False})

# --- Initialize DB ---
with app.app_context():
    db.create_all()
    ensure_paywall_columns()
    
    # Grandfather existing Pro users to 'legacy_pro' tier
    legacy_users = User.query.filter_by(is_subscribed=True).filter(
        (User.plan_tier == None) | (User.plan_tier == '')
    ).all()
    for user in legacy_users:
        if user.credits_limit == 200000:  # Old Pro plan
            user.plan_tier = 'legacy_pro'
    if legacy_users:
        db.session.commit()

if __name__ == "__main__":
    app.run(debug=True)