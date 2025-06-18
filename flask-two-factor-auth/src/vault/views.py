from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_login import login_required, current_user
from src import bcrypt
from src.db import db
from .utils import encrypt_password, decrypt_password  
from .forms import VaultForm, RevealPasswordForm
from .models import VaultEntry
from src.accounts.models import User
from datetime import datetime, timedelta

vault_bp = Blueprint("vault", __name__, template_folder="../templates")

@vault_bp.route('/vault', methods=['GET', 'POST'])
@login_required
def password_vault():
    form = VaultForm()

    show_passwords = False
    reveal_time = session.get('reveal_time')

    if reveal_time:
        expire_time = datetime.fromtimestamp(reveal_time) + timedelta(minutes=2) 
        if datetime.utcnow() < expire_time:
            show_passwords = True
        else:
            session.pop('show_passwords', None)
            session.pop('reveal_time', None)

    if form.validate_on_submit():
        
        encrypted_password = encrypt_password(form.app_password.data)
        new_entry = VaultEntry(
            user_id=current_user.id,
            app_name=form.app_name.data,
            app_username=form.app_username.data,
            encrypted_password=encrypted_password   # ✅ Corrected!
        )
        db.session.add(new_entry)
        db.session.commit()
        flash("Password saved successfully!", "success")
        return redirect(url_for('vault.password_vault'))

    entries = VaultEntry.query.filter_by(user_id=current_user.id).all()
    decrypted_entries = []
    if show_passwords:
        decrypted_entries = [
            {
                'app_name': e.app_name,
                'app_username': e.app_username,
                'app_password': decrypt_password(e.encrypted_password)
            } for e in entries
        ]
    else:
        decrypted_entries = [
            {
                'app_name': e.app_name,
                'app_username': e.app_username,
                'app_password': "********"
            } for e in entries
        ]

    return render_template('vault/vault_home.html', form=form, entries=decrypted_entries, show_passwords=show_passwords)


@vault_bp.route('/vault/reveal', methods=['GET', 'POST'])
@login_required
def reveal_passwords():
    form = RevealPasswordForm()
    
    if form.validate_on_submit():
        password = form.password.data
        user = User.query.get(current_user.id)
        if user and bcrypt.check_password_hash(user.password, password):
            session['show_passwords'] = True
            session['reveal_time'] = datetime.utcnow().timestamp()  
            flash("Passwords revealed for 2 minutes.", "success")
            return redirect(url_for('vault.password_vault'))
        else:
            flash("Incorrect password.", "danger")
            return redirect(url_for('vault.reveal_passwords'))

    return render_template('vault/reveal.html', form=form)
