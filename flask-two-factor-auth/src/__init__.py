from decouple import config
from flask import Flask
from src.db import db
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_mail import Mail
from flask_migrate import Migrate
import sqlite3
from sqlalchemy import event
from sqlalchemy.engine import Engine

bcrypt = Bcrypt()
mail = Mail()
login_manager = LoginManager()
migrate = Migrate()

def create_app():
    app = Flask(__name__)
    app_settings = config("APP_SETTINGS", default="config.DevelopmentConfig")
    app.config.from_object(app_settings)

    bcrypt.init_app(app)
    db.init_app(app)
    migrate.init_app(app, db)
    mail.init_app(app)
    login_manager.init_app(app)

    login_manager.login_view = "accounts.login"
    login_manager.login_message_category = "danger"

    # Enable foreign key constraints for SQLite
    @event.listens_for(Engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        if isinstance(dbapi_connection, sqlite3.Connection):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON;")
            cursor.close()

    from src.accounts.views import accounts_bp
    from src.core.views import core_bp
    from src.vault.views import vault_bp

    app.register_blueprint(accounts_bp)
    app.register_blueprint(core_bp)
    app.register_blueprint(vault_bp)

    from src.accounts.models import User

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    return app
