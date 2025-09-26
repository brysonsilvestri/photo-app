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
from PIL import Image, ImageDraw
from dotenv import load_dotenv
from openai import OpenAI
import stripe
from sqlalchemy import text
import qrcode

# --- Env & OpenAI client ---
load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

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
    prompt_style = db.Column(db.String(100), default='default')  # For future style options

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

# --- Fixed prompt ---
FIXED_PROMPT = (
    "Identify the main product in this image and isolate it from all nearby objects or distractions. "
    "Place only the product on a clean, professional studio background with soft, realistic lighting. "
    "Maintain the original proportions and dimensions of the product exactly as they appear, including its shape, angle, and size. "
    "It is critically important to maintain the same texture of the original product. "
    "Retain all visible text, logos, and label details with photorealistic clarity, as if the image were shot for a luxury brand ad like Sephora or Estée Lauder."
)

def save_b64_png_to(path: str, b64: str):
    img_bytes = base64.b64decode(b64)
    with open(path, "wb") as f:
        f.write(img_bytes)

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
    if added:
        db.session.commit()

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
            db.session.commit()
        elif current_user.is_authenticated:
            # As a fallback, attach the customer to the current user
            current_user.stripe_customer_id = customer_id
            current_user.is_subscribed = True
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
                db.session.commit()

    if event["type"] in ("customer.subscription.updated", "customer.subscription.deleted"):
        data = event["data"]["object"]
        customer_id = data.get("customer")
        status = data.get("status")
        if customer_id:
            user = User.query.filter_by(stripe_customer_id=customer_id).first()
            if user:
                user.is_subscribed = (status in ("active", "trialing"))
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
@app.post("/transform")
def transform():
    # 1) Require login: redirect to signup (not login) by default
    if not current_user.is_authenticated:
        return redirect(url_for('signup', next=url_for('index')))

    # 2) PAYWALL: 1 free successful generation for non-subscribed accounts
    if not current_user.is_subscribed and (current_user.generation_count or 0) >= 1:
        flash("You've used your free image. Upgrade to continue.", "info")
        return redirect(url_for('upgrade'))

    input_image = None
    output_image = None
    error = None

    file = request.files.get("image")
    if not file or not file.filename:
        flash("Please choose an image to upload.", "error")
        return redirect(url_for('index'))

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

        # Prepare 1024x1024 PNG
        resized_path = os.path.join(app.config['UPLOAD_FOLDER'], f"resized_{timestamp}.png")
        with Image.open(input_path) as img:
            img = img.convert("RGBA")
            img = img.resize((1024, 1024), Image.LANCZOS)
            img.save(resized_path, format="PNG")

        # Build mask (top 5% editable)
        mask_path = os.path.join(app.config['UPLOAD_FOLDER'], f"mask_{timestamp}.png")
        mask = Image.new("RGBA", (1024, 1024), (0, 0, 0, 255))
        draw = ImageDraw.Draw(mask)
        edit_height = int(1024 * 0.05)
        draw.rectangle([0, 0, 1024, edit_height], fill=(0, 0, 0, 0))
        mask.save(mask_path, format="PNG")

        # OpenAI call
        with open(resized_path, "rb") as image_file, open(mask_path, "rb") as mask_file:
            result = client.images.edit(
                model="gpt-image-1",
                prompt=FIXED_PROMPT,
                image=image_file,
                mask=mask_file,
                size="1024x1024"
            )

        # Save result
        base_name, _ = os.path.splitext(filename)
        safe_base = secure_filename(base_name) or "output"
        output_filename = f"gptimg_out_{safe_base}.png"
        output_path = os.path.join(app.config['OUTPUT_FOLDER'], output_filename)
        save_b64_png_to(output_path, result.data[0].b64_json)
        output_image = "/" + output_path.replace("\\", "/")

        # Save generation to database
        generation = Generation(
            user_id=current_user.id,
            input_image_path=input_image,
            output_image_path=output_image
        )
        db.session.add(generation)
        
        # Count only on success
        current_user.generation_count = (current_user.generation_count or 0) + 1
        db.session.commit()

    except Exception as e:
        error = str(e)

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