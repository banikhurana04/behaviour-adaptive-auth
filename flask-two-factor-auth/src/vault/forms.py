from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, Length

class VaultForm(FlaskForm):
    app_name = StringField("App Name", validators=[DataRequired(), Length(max=100)])
    app_username = StringField("App Username", validators=[DataRequired(), Length(max=100)])
    app_password = PasswordField("App Password", validators=[DataRequired(), Length(max=255)])

class RevealPasswordForm(FlaskForm):
    password = PasswordField("Enter your account password", validators=[DataRequired()])
