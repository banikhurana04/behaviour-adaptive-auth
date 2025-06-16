from src.utils import get_b64encoded_qr_image
from .forms import LoginForm, RegisterForm, TwoFactorForm
from src.accounts.models import User, LoginHistory
from src import db, bcrypt, mail
from flask_login import current_user, login_required, login_user, logout_user
from flask import Blueprint, flash, redirect, render_template, request, url_for, current_app, session
from flask_mail import Message
import requests
import geoip2.database

accounts_bp = Blueprint("accounts", __name__)

HOME_URL = "core.home"
SETUP_2FA_URL = "accounts.setup_two_factor_auth"
VERIFY_2FA_URL = "accounts.verify_two_factor_auth"

# Registration Route
@accounts_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        flash("You are already registered and logged in.", "info")
        return redirect(url_for(HOME_URL))

    form = RegisterForm(request.form)
    if form.validate_on_submit():
        try:
            import os
            salt = os.urandom(16)
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode("utf-8")
            user = User(
                username=form.username.data,
                password=hashed_password,
                email=form.email.data,
                salt=salt
            )
            db.session.add(user)
            db.session.commit()

            # ✅ Automatically log in user after registration, but redirect to 2FA setup
            login_user(user)
            flash("Account created successfully. Please set up 2FA to continue.", "success")
            return redirect(url_for(SETUP_2FA_URL))
        except Exception as e:
            db.session.rollback()
            flash(f"Registration failed: {str(e)}", "danger")

    elif request.method == "POST":
        flash("Form validation failed.", "danger")
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"{field}: {error}", "danger")

    return render_template("accounts/register.html", form=form)

# Login Route
@accounts_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        flash("You are already logged in.", "info")
        return redirect(url_for(HOME_URL))

    form = LoginForm(request.form)
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            if not user.is_two_factor_authentication_enabled:
                flash("Please complete 2FA setup.", "info")
                return redirect(url_for(SETUP_2FA_URL))
            return redirect(url_for(VERIFY_2FA_URL))
        else:
            flash("Invalid username or password.", "danger")

    return render_template("accounts/login.html", form=form)

# Logout Route
@accounts_bp.route("/logout")
@login_required
def logout():
    session.pop("otp_verified", None)
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("accounts.login"))

# 2FA Setup Route
@accounts_bp.route("/setup-2fa")
@login_required
def setup_two_factor_auth():
    secret = current_user.secret_token
    uri = current_user.get_authentication_setup_uri()
    base64_qr_image = get_b64encoded_qr_image(uri)
    return render_template("accounts/setup-2fa.html", secret=secret, qr_image=base64_qr_image)

# 2FA Verification Route
@accounts_bp.route("/verify-2fa", methods=["GET", "POST"])
@login_required
def verify_two_factor_auth():
    form = TwoFactorForm(request.form)
    if form.validate_on_submit():
        if current_user.is_otp_valid(form.otp.data):
            session["otp_verified"] = True

            if not current_user.is_two_factor_authentication_enabled:
                try:
                    current_user.is_two_factor_authentication_enabled = True
                    db.session.commit()
                    flash("2FA setup successful!", "success")
                except Exception:
                    db.session.rollback()
                    flash("Failed to enable 2FA. Please try again.", "danger")
                    return redirect(url_for(VERIFY_2FA_URL))

            log_login(current_user.username)
            flash("2FA verification successful. You are logged in!", "success")
            return redirect(url_for(HOME_URL))
        else:
            flash("Invalid OTP. Please try again.", "danger")
            return redirect(url_for(VERIFY_2FA_URL))

    return render_template("accounts/verify-2fa.html", form=form)

# Login History
@accounts_bp.route("/login-history")
@login_required
def login_history():
    history = LoginHistory.query.filter_by(user_id=current_user.id).order_by(LoginHistory.timestamp.desc()).limit(20).all()
    return render_template("accounts/login_history.html", history=history)

# Suspicious Alerts
@accounts_bp.route("/suspicious-alerts")
@login_required
def suspicious_alerts():
    suspicious_entries = LoginHistory.query.filter_by(
        user_id=current_user.id, is_suspicious=True
    ).order_by(LoginHistory.timestamp.desc()).limit(20).all()
    return render_template("accounts/suspicious_alerts.html", history=suspicious_entries)

# Helper Functions: Suspicious login detection
def get_location(ip):
    try:
        response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=3)
        data = response.json()
        city = data.get("city", "")
        country = data.get("country_name", "")
        return f"{city}, {country}".strip(", ")
    except Exception:
        return "Unknown"

def send_alert_email(to_email, username, ip, location, user_agent):
    subject = "⚠️ Suspicious Login Detected"
    body = f"""Hi {username},

A suspicious login was detected:

IP Address: {ip}
Location: {location}
Device: {user_agent}

If this wasn't you, please secure your account immediately.

Best regards,
{current_app.config.get('APP_NAME', 'Security Team')}
"""
    msg = Message(subject=subject, recipients=[to_email], body=body)
    mail.send(msg)

def log_login(username):
    ip = request.remote_addr
    user_agent = request.headers.get('User-Agent')
    location = get_location(ip)

    try:
        with geoip2.database.Reader('./GeoLite2-City.mmdb') as reader:
            response = reader.city(ip)
            location = f"{response.city.name}, {response.country.name}"
    except Exception:
        pass

    user = User.query.filter_by(username=username).first()
    if not user:
        return

    previous = LoginHistory.query.filter_by(user_id=user.id).order_by(LoginHistory.timestamp.desc()).first()
    is_suspicious = False

    if previous and (previous.ip_address != ip or previous.user_agent != user_agent or previous.location != location):
        is_suspicious = True
        if user.email:
            send_alert_email(user.email, username, ip, location, user_agent)
        current_app.logger.warning(f"Suspicious login detected for {username} from {ip} ({location})")

    history = LoginHistory(
        user_id=user.id,
        ip_address=ip,
        user_agent=user_agent,
        location=location,
        is_suspicious=is_suspicious
    )
    db.session.add(history)
    db.session.commit()

    if is_suspicious:
        flash("⚠️ Suspicious login detected.", "warning")
