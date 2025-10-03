import os
import base64
import uuid
from io import BytesIO
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    current_user
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
STRIPE_PRICE_ID = os.getenv("STRIPE_PRICE_ID")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")

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
    
    # Credit system fields
    credits_remaining = db.Column(db.Integer, default=12500)  # Free tier gets 12,500 credits (50 images)
    credits_limit = db.Column(db.Integer, default=12500)
    credits_reset_date = db.Column(db.DateTime, nullable=True)
    
    # Relationship to generations
    generations = db.relationship('Generation', backref='user', lazy=True, order_by='Generation.created_at.desc()')

    def set_password(self, password):
        # pbkdf2:sha256 works well on older Python too
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
    prompt_style = db.Column(db.String(100), default='white')  # Stores which style was used

# --- Mobile upload token model (QR flow) ---
class MobileUploadToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(64), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    used = db.Column(db.Boolean, default=False, nullable=False)
    image_path = db.Column(db.String(255), nullable=True)
    # Optional: associate to the current user if logged in when starting the flow
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Style-specific prompts ---
STYLE_PROMPTS = {
    'white': """Using the provided image, identify the product in the photo and isolate it from all other objects
around it. Place it on a white studio background with soft professional lighting. The product should be shot on a 50 mm lens and face directly 
towards the lens. If and only when the product is a shoe, the product can be placed sideways with the lens.""",
    
    'studio': """Using the provided image, identify the product in the photo and isolate it from all other objects
around it. Place it on a professional studio background with gradient lighting from light gray to white. Add subtle shadows beneath the product
for depth. The product should be shot on a 50mm lens with professional studio lighting that highlights the product features.""",
    
    'realestate': """Stage this empty living room with a cohesive set of modern, minimalist furniture—low-profile sofa, area rug, coffee table, 1–2 accent chairs, and a slender floor lamp—scaled to the room and leaving clear walkways. Fill the room with an appropriate amount of furiture, do not leave odd empty space on the edges. Preserve the existing architecture, perspective, and daylight direction, and render materials (linen/bouclé, oak/walnut, stone, matte metal) with physically correct contact shadows, subtle reflections, and fine texture for a hyper-photorealistic editorial look. Use a warm-neutral palette with one muted accent color and avoid text, logos, clutter, distortions, or floating objects."""
}

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
    return any(row[1] == column for row in res)  # row[1] is the column name

def _table_exists(table: str) -> bool:
    res = db.session.execute(text("SELECT name FROM sqlite_master WHERE type='table' AND name=:table"), {"table": table}).fetchall()
    return len(res) > 0

def ensure_paywall_columns():
    # Add columns if missing (safe for SQLite; run once on startup)
    added = False
    if not _column_exists("user", "is_subscribed"):
        db.session.execute(text("ALTER TABLE user ADD COLUMN is_subscribed BOOLEAN NOT NULL DEFAULT 0"))
        added = True
    if not _column_exists("user", "stripe_customer_id"):
        db.session.execute(text("ALTER TABLE user ADD COLUMN stripe_customer_id VARCHAR(120)"))
        added = True
    if not _column_exists("user", "credits_remaining"):
        db.session.execute(text("ALTER TABLE user ADD COLUMN credits_remaining INTEGER DEFAULT 12500"))
        added = True
    if not _column_exists("user", "credits_limit"):
        db.session.execute(text("ALTER TABLE user ADD COLUMN credits_limit INTEGER DEFAULT 12500"))
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
    # If already logged in, go back to the unified page
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
        user.credits_remaining = 12500  # Free tier: 50 images * 250 credits
        user.credits_limit = 12500
        db.session.add(user)
        db.session.commit()

        # Signup is intentionally non-persistent (no remember)
        login_user(user)
        next_page = request.args.get('next') or request.form.get('next') or url_for('index')
        return redirect(next_page)

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    # Already logged in? honor ?next=, else go to unified page
    if current_user.is_authenticated:
        return redirect(request.args.get('next') or url_for('index'))

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        next_page = request.args.get('next') or request.form.get('next') or url_for('index')

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            # Only persist if "Remember me" was checked
            remember = bool(request.form.get("remember"))
            login_user(user, remember=remember)
            return redirect(next_page)

        flash("Invalid email or password", "error")

    return render_template("login.html")


@app.route("/logout")
def logout():
    if current_user.is_authenticated:
        logout_user()  # clears both session and remember cookie if present
        flash("You have been logged out.", "info")
    return redirect(url_for('index'))

# -----------------------
# Billing
# -----------------------
@app.route("/upgrade")
def upgrade():
    if not current_user.is_authenticated:
        return redirect(url_for('signup', next=url_for('upgrade')))

    if current_user.is_subscribed:
        return redirect(url_for('index'))

    if not STRIPE_PRICE_ID or not stripe.api_key:
        flash("Billing is not configured. Please contact support.", "error")
        return redirect(url_for('index'))

    customer_id = ensure_stripe_customer(current_user)
    session = stripe.checkout.Session.create(
        mode="subscription",
        customer=customer_id,
        line_items=[{"price": STRIPE_PRICE_ID, "quantity": 1}],
        # Send users to a post-checkout route that marks them active immediately
        success_url=f"{APP_BASE_URL}/post-checkout?session_id={{CHECKOUT_SESSION_ID}}",
        cancel_url=f"{APP_BASE_URL}/",
        allow_promotion_codes=True,
        billing_address_collection="auto",
    )
    return redirect(session.url, code=303)

@app.get("/post-checkout")
def post_checkout():
    """
    Land here after Stripe Checkout success (client-side redirect).
    We verify the session, mark the matching user as subscribed, then
    send them to the app with ?upgraded=1 so the UI reflects paid status.
    """
    session_id = request.args.get("session_id")
    if not session_id:
        flash("Missing checkout session.", "error")
        return redirect(url_for('index'))

    try:
        sess = stripe.checkout.Session.retrieve(session_id)
        customer_id = sess.get("customer")
        if not customer_id:
            raise ValueError("No Stripe customer on session")

        # Try to find the user by the customer ID we attached at /upgrade.
        user = User.query.filter_by(stripe_customer_id=customer_id).first()

        if user:
            user.is_subscribed = True
            # Allocate Pro tier credits (since all buttons point to $19/mo for now)
            user.credits_remaining = 200000  # 800 images * 250 credits
            user.credits_limit = 200000
            db.session.commit()
        elif current_user.is_authenticated:
            # As a fallback, attach the customer to the current user
            current_user.stripe_customer_id = customer_id
            current_user.is_subscribed = True
            current_user.credits_remaining = 200000
            current_user.credits_limit = 200000
            db.session.commit()
        # else: nothing to do; webhook will catch up and flip the flag soon

        # Let the main page show the "Thanks for upgrading" banner via ?upgraded=1
        return redirect(url_for('index', upgraded=1))

    except Exception as e:
        # If we can't verify now, the webhook will still mark them active shortly.
        flash("Thanks! Your payment succeeded. Access will unlock momentarily.", "info")
        return redirect(url_for('index'))

@app.route("/billing-portal")
def billing_portal():
    if not current_user.is_authenticated:
        return redirect(url_for('login', next=url_for('billing_portal')))
    customer_id = ensure_stripe_customer(current_user)
    session = stripe.billing_portal.Session.create(
        customer=customer_id,
        return_url=f"{APP_BASE_URL}/",
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
        if customer_id:
            user = User.query.filter_by(stripe_customer_id=customer_id).first()
            if user:
                user.is_subscribed = True
                # Allocate Pro tier credits (800 images * 250 credits)
                user.credits_remaining = 200000
                user.credits_limit = 200000
                db.session.commit()

    if event["type"] in ("customer.subscription.updated", "customer.subscription.deleted"):
        data = event["data"]["object"]
        customer_id = data.get("customer")
        status = data.get("status")
        if customer_id:
            user = User.query.filter_by(stripe_customer_id=customer_id).first()
            if user:
                is_active = status in ("active", "trialing")
                user.is_subscribed = is_active
                if is_active:
                    # Allocate credits when subscription becomes active
                    user.credits_remaining = 200000
                    user.credits_limit = 200000
                else:
                    # Revert to free tier
                    user.credits_remaining = 12500
                    user.credits_limit = 12500
                db.session.commit()

    return jsonify(success=True), 200

# -----------------------
# Unified Page
# -----------------------
@app.get("/")
def index():
    # Optional success message after Stripe upgrade
    if request.args.get("upgraded") == "1":
        flash("Thanks for upgrading! Your subscription is now active.", "success")

    # Compute paywall context for the template
    is_authed = bool(current_user.is_authenticated) if current_user else False
    is_subscribed = bool(getattr(current_user, "is_subscribed", False)) if is_authed else False

    # 1 free successful generation for non-subscribed
    free_cap = 1
    used = int(getattr(current_user, "generation_count", 0)) if is_authed else 0
    free_uses_left = max(0, free_cap - used) if not is_subscribed and is_authed else None
    
    # Load user's generation history if logged in
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
    
    # Load all generations for the sidebar
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
# Transform Action (server authority)
# -----------------------
CREDITS_PER_IMAGE = 250

@app.post("/transform")
def transform():
    # 1) Require login: redirect to signup (not login) by default
    if not current_user.is_authenticated:
        return redirect(url_for('signup', next=url_for('index')))

    # 2) PAYWALL: Check credits instead of generation_count
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
    
    # Get the selected style (default to 'white' if not provided)
    style = request.form.get("style", "white")
    if style not in STYLE_PROMPTS:
        style = "white"
    
    selected_prompt = STYLE_PROMPTS[style]

    try:
        # Save uploaded image
        filename = secure_filename(file.filename)
        if not filename:
            raise ValueError("Invalid filename.")
        # Add timestamp to avoid conflicts
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        filename = f"{timestamp}_{filename}"
        input_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(input_path)
        input_image = "/" + input_path.replace("\\", "/")

        # --------- RESIZE: keep aspect ratio; longest side = 1024 px ---------
        with Image.open(input_path) as img:
            img = ImageOps.exif_transpose(img).convert("RGB")
            w, h = img.size
            longest = max(w, h)
            # Scale so that the longest side becomes 1024 px (upscale if needed)
            scale = 1024.0 / float(longest) if longest != 0 else 1.0
            new_w = max(1, int(round(w * scale)))
            new_h = max(1, int(round(h * scale)))
            img = img.resize((new_w, new_h), Image.LANCZOS)
            # ------------------------------------------------------------------

            # Use Google Generative AI to transform the image with selected style prompt
            response = client.models.generate_content(
                model="gemini-2.5-flash-image-preview",
                contents=[img, selected_prompt],
            )
            
            # Extract the generated image from response
            image_parts = [
                part.inline_data.data
                for part in response.candidates[0].content.parts
                if part.inline_data
            ]
            
            if not image_parts:
                raise ValueError("No image was generated in the response")
            
            # Save the generated image
            generated_image = Image.open(BytesIO(image_parts[0]))
            base_name, _ = os.path.splitext(filename)
            safe_base = secure_filename(base_name) or "output"
            output_filename = f"genai_{style}_{safe_base}.png"
            output_path = os.path.join(app.config['OUTPUT_FOLDER'], output_filename)
            generated_image.save(output_path, format="PNG")
            output_image = "/" + output_path.replace("\\", "/")

        # Save generation to database with style information
        generation = Generation(
            user_id=current_user.id,
            input_image_path=input_image,
            output_image_path=output_image,
            prompt_style=style  # Store which style was used
        )
        db.session.add(generation)
        
        # Deduct credits on success
        current_user.credits_remaining = max(0, current_user.credits_remaining - CREDITS_PER_IMAGE)
        current_user.generation_count = (current_user.generation_count or 0) + 1
        db.session.commit()

    except Exception as e:
        error = f"Error generating image: {str(e)}"
        flash(error, "error")

    # Recompute paywall context when returning the page with results
    is_authed = True
    is_subscribed = bool(getattr(current_user, "is_subscribed", False))
    free_cap = 1
    used = int(getattr(current_user, "generation_count", 0))
    free_uses_left = max(0, free_cap - used) if not is_subscribed else None
    
    # Load user's generation history
    user_generations = current_user.generations

    # Re-render unified page with results
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
    """
    Create a one-time token for a phone upload session.
    Returns JSON with:
      - token
      - upload_url (phone page)
      - qrcode_url (PNG for QR image)
    """
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
    """Return a QR PNG that points to the mobile upload URL."""
    url = f"{APP_BASE_URL}/mobile/upload/{token}"
    img = qrcode.make(url)
    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png")

@app.get("/mobile/upload/<token>")
def mobile_upload_get(token):
    """Minimal phone page to take/upload a photo."""
    t = MobileUploadToken.query.filter_by(token=token).first()
    if not t or t.used:
        return "Link expired or already used.", 410
    return render_template("mobile_upload.html", token=token)

@app.post("/mobile/upload/<token>")
def mobile_upload_post(token):
    """Receive the phone's photo, store it, mark token used."""
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
    """Desktop polls this to learn when the phone upload is done."""
    t = MobileUploadToken.query.filter_by(token=token).first()
    if not t:
        return jsonify({"ok": False, "error": "not_found"}), 404
    if t.used and t.image_path:
        return jsonify({"ok": True, "ready": True, "image_url": t.image_path})
    return jsonify({"ok": True, "ready": False})

# --- Initialize DB ---
with app.app_context():
    db.create_all()
    # one-time lite migration if needed (adds paywall columns if missing)
    ensure_paywall_columns()

if __name__ == "__main__":
    app.run(debug=True)