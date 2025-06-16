from flask import Blueprint, render_template, request, jsonify, abort, session, redirect, url_for
from flask_login import login_required, current_user
import numpy as np
from functools import wraps   # ✅ add this
from src.accounts.models import BehaviorProfile, LoginHistory
from src import db

core_bp = Blueprint("core", __name__)

# ✅ OTP verification decorator (inside this file itself)
def otp_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("otp_verified"):
            return redirect(url_for('accounts.verify_two_factor_auth'))
        return f(*args, **kwargs)
    return decorated_function

# ✅ Home route
@core_bp.route('/')
@login_required
@otp_required
def home():
    return render_template("core/index.html")

# ✅ Behavior Alerts
@core_bp.route('/behavior-alerts')
@login_required
@otp_required
def behavior_alerts():
    profiles = BehaviorProfile.query.all()
    return render_template('core/behavior_alerts.html', profiles=profiles)

# ✅ Behavior Data receiving
@core_bp.route('/behavior-data', methods=['POST'])
@login_required
def receive_behavior_data():
    if not current_user.is_authenticated:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    print("Received behavior data:", data) 

    movement_count = data.get("movements", 0)
    keystroke_count = data.get("keystrokes", 0)
    scroll_count = data.get("scrolls", 0)

    profile = BehaviorProfile.query.filter_by(user_id=current_user.id).first()
    if not profile:
        profile = BehaviorProfile(
            user_id=current_user.id,
            avg_movements=movement_count,
            avg_keystrokes=keystroke_count,
            avg_scrolls=scroll_count
        )
        db.session.add(profile)
    else:
        profile.avg_movements += movement_count
        profile.avg_keystrokes += keystroke_count
        profile.avg_scrolls += scroll_count

    db.session.commit()
    return jsonify({"status": "Profile Created"}), 200

# ✅ Login Alerts
@core_bp.route('/login-alerts')
@login_required
@otp_required
def login_alerts():
    if current_user.username != 'admin':
        abort(403)
    alerts = LoginHistory.query.filter_by(is_suspicious=True).order_by(LoginHistory.timestamp.desc()).all()
    return render_template('core/login_alerts.html', alerts=alerts)
