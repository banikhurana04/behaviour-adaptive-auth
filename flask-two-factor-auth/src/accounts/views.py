from src.utils import get_b64encoded_qr_image
from .forms import LoginForm, RegisterForm, TwoFactorForm
from src.accounts.models import User, LoginHistory
from src import db, bcrypt, mail
from flask_login import current_user, login_required, login_user, logout_user
from flask import Blueprint, flash, redirect, render_template, request, url_for, current_app
from flask_mail import Message
import requests
import geoip2.database
from flask import session

accounts_bp = Blueprint("accounts", __name__)

HOME_URL = "core.home"
SETUP_2FA_URL = "accounts.setup_two_factor_auth"
VERIFY_2FA_URL = "accounts.verify_two_factor_auth"


@accounts_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        if current_user.is_two_factor_authentication_enabled:
            flash("You are already registered.", "info")
            return redirect(url_for(HOME_URL))
        else:
            flash("You have not enabled 2-Factor Authentication. Please enable it first to login.", "info")
            return redirect(url_for(SETUP_2FA_URL))
    form = RegisterForm(request.form)
    if form.validate_on_submit():
        try:
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode("utf-8")
            user = User(
                username=form.username.data,
                password=hashed_password,
                email=form.email.data,
            )
            db.session.add(user)
            db.session.commit()
            login_user(user)
            flash("You are registered. You have to enable 2-Factor Authentication first to login.", "success")
            return redirect(url_for(SETUP_2FA_URL))
        except Exception as e:
            db.session.rollback()
            flash(f"Registration failed. Please try again. Error: {str(e)}", "danger")
    elif request.method == "POST":
        flash("Registration form validation failed.", "danger")
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"{field}: {error}", "danger")
    return render_template("accounts/register.html", form=form)


@accounts_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        if current_user.is_two_factor_authentication_enabled:
            flash("You are already logged in.", "info")
            return redirect(url_for(HOME_URL))
        else:
            flash("You have not enabled 2-Factor Authentication. Please enable it first to login.", "info")
            return redirect(url_for(SETUP_2FA_URL))

    form = LoginForm(request.form)
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            if not user.is_two_factor_authentication_enabled:
                flash("You have not enabled 2-Factor Authentication. Please enable it first to login.", "info")
                return redirect(url_for(SETUP_2FA_URL))
            return redirect(url_for(VERIFY_2FA_URL))
        elif not user:
            flash("You are not registered. Please register.", "danger")
        else:
            flash("Invalid username and/or password.", "danger")

    return render_template("accounts/login.html", form=form)

@accounts_bp.route("/logout")
@login_required
def logout():
    session.pop("otp_verified", None)  # ✅ Clear the OTP verification session
    logout_user()
    flash("You were logged out.", "success")
    return redirect(url_for("accounts.login"))

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

A suspicious login to your account was detected:

IP Address: {ip}
Location: {location}
Device Info: {user_agent}

If this was you, you can ignore this message.
If not, please change your password immediately.

Best,
{current_app.config.get('APP_NAME', 'Security Team')}
"""
    msg = Message(subject=subject, recipients=[to_email], body=body)
    mail.send(msg)


def send_suspicious_login_email(user, ip, location):
    msg = Message(
        subject="Suspicious Login Detected",
        sender=current_app.config['MAIL_USERNAME'],
        recipients=[user.email]
    )
    msg.body = f"""
    Hello {user.email},

    A suspicious login to your account was detected.

    IP Address: {ip}
    Location: {location}

    If this was not you, please secure your account immediately.
    """
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
        pass  # Fall back to ipapi

    previous = LoginHistory.query.filter_by(username=username).order_by(LoginHistory.timestamp.desc()).first()
    is_suspicious = False

    if previous:
        if previous.ip_address != ip or previous.user_agent != user_agent or previous.location != location:
            is_suspicious = True
            user = User.query.filter_by(username=username).first()
            if user and user.email:
                send_alert_email(user.email, username, ip, location, user_agent)
            current_app.logger.warning(f"Suspicious login detected for {username} from {ip} ({location})")

    history = LoginHistory(
        username=username,
        ip_address=ip,
        user_agent=user_agent,
        location=location,
        is_suspicious=is_suspicious
    )
    db.session.add(history)
    db.session.commit()

    if is_suspicious:
        flash("⚠️ Suspicious login detected. Please check your recent activity.", "warning")


@accounts_bp.route("/setup-2fa")
@login_required
def setup_two_factor_auth():
    secret = current_user.secret_token
    uri = current_user.get_authentication_setup_uri()
    base64_qr_image = get_b64encoded_qr_image(uri)
    return render_template("accounts/setup-2fa.html", secret=secret, qr_image=base64_qr_image)


@accounts_bp.route("/verify-2fa", methods=["GET", "POST"])
@login_required
def verify_two_factor_auth():
    form = TwoFactorForm(request.form)
    if form.validate_on_submit():
        if current_user.is_otp_valid(form.otp.data):
            # ✅ Mark OTP as verified in session
            session["otp_verified"] = True

            if current_user.is_two_factor_authentication_enabled:
                log_login(current_user.username)
                flash("2FA verification successful. You are logged in!", "success")
                return redirect(url_for(HOME_URL))
            else:
                try:
                    current_user.is_two_factor_authentication_enabled = True
                    db.session.commit()
                    log_login(current_user.username)
                    flash("2FA setup successful. You are logged in!", "success")
                    return redirect(url_for(HOME_URL))
                except Exception:
                    db.session.rollback()
                    flash("2FA setup failed. Please try again.", "danger")
                    return redirect(url_for(VERIFY_2FA_URL))
        else:
            flash("Invalid OTP. Please try again.", "danger")
            return redirect(url_for(VERIFY_2FA_URL))
    else:
        if not current_user.is_two_factor_authentication_enabled:
            flash("You have not enabled 2-Factor Authentication. Please enable it first.", "info")
        return render_template("accounts/verify-2fa.html", form=form)


@accounts_bp.route("/login-history")
@login_required
def login_history():
    history = LoginHistory.query.filter_by(username=current_user.username).order_by(LoginHistory.timestamp.desc()).limit(20).all()
    return render_template("accounts/login_history.html", history=history)


@accounts_bp.route("/suspicious-alerts")
@login_required
def suspicious_alerts():
    suspicious_entries = LoginHistory.query.filter_by(
        username=current_user.username, is_suspicious=True
    ).order_by(LoginHistory.timestamp.desc()).limit(20).all()
    return render_template("accounts/suspicious_alerts.html", history=suspicious_entries)
