from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from app.models import User, APIKey
from app.extensions import db, bcrypt
from app.forms import LoginForm, ChangePasswordForm, CreateUserForm, GenerateAPIKeyForm
from app.utils import admin_required, log_security_event
import secrets
import hashlib
from datetime import datetime

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            user.last_login_at = datetime.utcnow()
            user.failed_login_attempts = 0 # Reset failed attempts
            db.session.commit()

            # Log Login
            session_id = request.cookies.get('session', 'unknown')
            log_security_event(
                'Login',
                user.username,
                request.remote_addr,
                'info',
                is_admin=user.is_admin,
                session_id=session_id
            )

            if user.password_expired:
                flash('Your password has expired. Please change it.', 'warning')
                return redirect(url_for('auth.change_password'))

            return redirect(url_for('index'))
        else:
            if user:
                user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
                db.session.commit()

                log_security_event(
                    'Password Failure',
                    user.username,
                    request.remote_addr,
                    'warning',
                    failed_attempts=user.failed_login_attempts
                )

                if user.failed_login_attempts >= 3:
                     log_security_event(
                        '3 or more failed authentication attempts',
                        user.username,
                        request.remote_addr,
                        'warning'
                    )
            else:
                 # Log failure for unknown user
                 log_security_event(
                    'Password Failure',
                    form.username.data,
                    request.remote_addr,
                    'warning',
                    reason="Unknown user"
                )

            flash('Login Unsuccessful. Please check username and password', 'danger')

    return render_template('login.html', form=form)

@auth.route('/logout')
@login_required
def logout():
    # Calculate duration
    duration = 0
    if current_user.last_login_at:
        duration = (datetime.utcnow() - current_user.last_login_at).total_seconds()

    log_security_event(
        'Logoff',
        current_user.username,
        request.remote_addr,
        'info',
        session_duration_seconds=duration
    )

    logout_user()
    return redirect(url_for('auth.login'))

@auth.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if not bcrypt.check_password_hash(current_user.password_hash, form.current_password.data):
            flash('Current password is incorrect.', 'danger')
        else:
            hashed_password = bcrypt.generate_password_hash(form.new_password.data).decode('utf-8')
            current_user.password_hash = hashed_password
            current_user.password_expired = False
            db.session.commit()

            log_security_event('Password Change', current_user.username, request.remote_addr, 'info')

            flash('Your password has been updated!', 'success')
            return redirect(url_for('index'))

    return render_template('change_password.html', form=form)

@auth.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    new_key = None
    new_secret = None
    form = GenerateAPIKeyForm()

    if form.validate_on_submit():
        # Generate new API Key
        access_key = secrets.token_hex(32)
        secret_key = secrets.token_hex(32)
        secret_hash = hashlib.sha256(secret_key.encode()).hexdigest()

        # Deactivate/Remove old keys if we only want one per user
        # For now, let's just add a new one or replace existing
        existing_key = APIKey.query.filter_by(user_id=current_user.id).first()
        if existing_key:
            db.session.delete(existing_key)

        new_api_key = APIKey(
            user_id=current_user.id,
            access_key=access_key,
            secret_hash=secret_hash
        )
        db.session.add(new_api_key)
        db.session.commit()

        new_key = access_key
        new_secret = secret_key
        flash('New API Key generated. Please copy the Secret Key now, it will not be shown again.', 'success')

    api_key = APIKey.query.filter_by(user_id=current_user.id).first()
    return render_template('profile.html', user=current_user, api_key=api_key, new_secret=new_secret, form=form)

@auth.route('/admin/create_user', methods=['GET', 'POST'])
@login_required
@admin_required
def create_user():
    form = CreateUserForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(
            username=form.username.data,
            password_hash=hashed_password,
            password_expired=True,
            is_admin=form.is_admin.data
        )
        db.session.add(user)
        db.session.commit()

        # Generate initial API Key for the user
        access_key = secrets.token_hex(32)
        secret_key = secrets.token_hex(32)
        secret_hash = hashlib.sha256(secret_key.encode()).hexdigest()

        new_api_key = APIKey(
            user_id=user.id,
            access_key=access_key,
            secret_hash=secret_hash
        )
        db.session.add(new_api_key)
        db.session.commit()

        log_security_event('User Created', current_user.username, request.remote_addr, 'info', target_user=user.username, is_admin_created=user.is_admin)

        flash(f'User {user.username} created. API Key generated. Access: {access_key}, Secret: {secret_key}', 'success')
        return redirect(url_for('auth.create_user'))

    return render_template('admin_create_user.html', form=form)
