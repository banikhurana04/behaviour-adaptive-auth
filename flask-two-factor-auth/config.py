from decouple import config

# Fix Heroku-style DATABASE_URL for SQLAlchemy compatibility
DATABASE_URI = config("DATABASE_URL")
if DATABASE_URI.startswith("postgres://"):
    DATABASE_URI = DATABASE_URI.replace("postgres://", "postgresql://", 1)

class Config(object):
    DEBUG = False
    TESTING = False
    CSRF_ENABLED = True
    
    SECRET_KEY = config("SECRET_KEY")  
    ENCRYPTION_KEY = config("ENCRYPTION_KEY")  # ✅ This already correctly added
    SQLALCHEMY_DATABASE_URI = DATABASE_URI
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    BCRYPT_LOG_ROUNDS = 13
    WTF_CSRF_ENABLED = True
    DEBUG_TB_ENABLED = False
    DEBUG_TB_INTERCEPT_REDIRECTS = False
    APP_NAME = config("APP_NAME", default="My Flask App")

    # Flask-Mail configuration
    MAIL_SERVER = config("MAIL_SERVER", default="localhost")
    MAIL_PORT = config("MAIL_PORT", default=25, cast=int)
    MAIL_USE_TLS = config("MAIL_USE_TLS", default=False, cast=bool)
    MAIL_USERNAME = config("MAIL_USERNAME", default=None)
    MAIL_PASSWORD = config("MAIL_PASSWORD", default=None)
    MAIL_DEFAULT_SENDER = config("MAIL_DEFAULT_SENDER", default=None)


class DevelopmentConfig(Config):
    DEVELOPMENT = True
    DEBUG = True
    WTF_CSRF_ENABLED = False  
    DEBUG_TB_ENABLED = True


class TestingConfig(Config):
    TESTING = True
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///testdb.sqlite"
    BCRYPT_LOG_ROUNDS = 1  
    WTF_CSRF_ENABLED = False


class ProductionConfig(Config):
    DEBUG = False
    DEBUG_TB_ENABLED = False
