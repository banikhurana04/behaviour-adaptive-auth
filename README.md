# Behavior-Based Adaptive Authentication System with Secure Password Vault

A secure Flask-based authentication system that not only adapts to suspicious login behavior using 2FA and risk detection, but also provides a **zero-knowledge encrypted password vault** for users to safely store their personal passwords. 

All sensitive data is encrypted client-side, meaning **even the server or database cannot read it** — ensuring privacy and security even if the backend is compromised.

---

## Key Features

### 🔐 Authentication
- User registration and login
- TOTP-based Two-Factor Authentication (Google Authenticator compatible)
- Device and IP fingerprinting
- Behavioral anomaly detection
- Suspicious login alerts with email notifications
- Adaptive re-authentication logic
- Login history tracking

### 🧰 Encrypted Password Vault
- Users can store personal credentials (e.g., Gmail, bank, social media)
- Each password is **encrypted before storage** using user-specific keys
- **Zero-Knowledge Guarantee**:
  - Server cannot decrypt stored passwords
  - Only the logged-in user can view their vault using their encryption key
  - If the database is leaked, attackers get only encrypted blobs
- **Auto-Expire Reveal**:
  - Revealed passwords auto-disappear after 2 minutes to reduce exposure risk

---

## Tech Stack

- **Backend**: Flask
- **ORM**: SQLAlchemy
- **2FA**: PyOTP
- **Encryption**: Fernet (symmetric key encryption)
- **Geo Data**: GeoIP2, Geocoder
- **Email**: Flask-Mail
- **Database**: SQLite (can be switched to PostgreSQL/MySQL)
- **Migrations**: Alembic

---

## Setup Instructions

### 1. Clone the repository
    
    ```bash
    git clone https://github.com/your-username/behavior-adaptive-auth.git
    cd flask-two-factor-auth
    
2. Set up the environment
   
    python -m venv venv
    venv\Scripts\activate    # On Windows
    source venv/bin/activate  # On Unix/Mac
   
3. Install dependencies
    pip install -r requirements.txt
   
Environment Configuration
    Create a .env file in the root directory:

      DATABASE_URL=sqlite:///app.db
      
      # Generate your own secret key:
      # >>> import secrets; secrets.token_hex(32)
      SECRET_KEY=your-generated-secret-key
      
      # Generate encryption key:
      # >>> from cryptography.fernet import Fernet; Fernet.generate_key().decode()
      ENCRYPTION_KEY=your-generated-encryption-key
      
      APP_NAME=Behaviour Adaptive Auth
      
      MAIL_SERVER=smtp.gmail.com
      MAIL_PORT=587
      MAIL_USE_TLS=True
      MAIL_USERNAME=your-email@gmail.com
      MAIL_PASSWORD=your-app-password
      MAIL_DEFAULT_SENDER=your-email@gmail.com
      
      DEBUG=True
      APP_SETTINGS=config.DevelopmentConfig
      FLASK_APP=src
      FLASK_DEBUG=1

Database Setup
    flask db init
    flask db migrate -m "Initial"
    flask db upgrade
    
Run the Application
    flask run

Visit http://localhost:5000 in your browser.

