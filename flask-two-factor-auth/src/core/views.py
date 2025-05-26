from flask import Blueprint, render_template, request, jsonify, abort
from flask_login import login_required, current_user
import numpy as np
from src.accounts.models import BehaviorProfile, LoginHistory  # Import both models
from src import db

core_bp = Blueprint("core", __name__)


@core_bp.route('/')
@login_required
def home():
    return render_template("core/index.html")


@core_bp.route('/behavior-alerts')
@login_required
def behavior_alerts():
    profiles = BehaviorProfile.query.all()
    return render_template('core/behavior_alerts.html', profiles=profiles)


@core_bp.route('/behavior-data', methods=['POST'])
def receive_behavior_data():
    if not current_user.is_authenticated:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    user = current_user.username

    movement_count = len(data.get("movements", []))
    keystroke_count = len(data.get("keystrokes", []))
    scroll_count = len(data.get("scrolls", []))

    profile = BehaviorProfile.query.filter_by(username=user).first()
    if not profile:
        profile = BehaviorProfile(
            username=user,
            avg_movements=movement_count,
            avg_keystrokes=keystroke_count,
            avg_scrolls=scroll_count
        )
        db.session.add(profile)
        db.session.commit()
        return jsonify({"status": "Profile Created"}), 200

    dist = np.linalg.norm([
        movement_count - profile.avg_movements,
        keystroke_count - profile.avg_keystrokes,
        scroll_count - profile.avg_scrolls
    ])

    threshold = 100
    if dist > threshold:
        return jsonify({"alert": "Anomalous behavior detected!"}), 200
    return jsonify({"status": "Normal behavior"}), 200


@core_bp.route('/login-alerts')
@login_required
def login_alerts():
    if current_user.username != 'admin':  # Ideally use current_user.is_admin
        abort(403)
    alerts = LoginHistory.query.filter_by(is_suspicious=True).order_by(LoginHistory.timestamp.desc()).all()
    return render_template('core/login_alerts.html', alerts=alerts)
