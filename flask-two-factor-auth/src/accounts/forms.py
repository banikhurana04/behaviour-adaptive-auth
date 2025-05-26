from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, EqualTo, Length, InputRequired, Email
from src.accounts.models import User


class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=6, max=40)])
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6, max=25)])
    confirm = PasswordField("Repeat password", validators=[
        DataRequired(),
        EqualTo("password", message="Passwords must match.")
    ])

    def validate(self, extra_validators=None):
        if not super().validate(extra_validators):
            return False

        user = User.query.filter_by(username=self.username.data).first()
        if user:
            self.username.errors.append("Username already registered.")
            return False

        email_user = User.query.filter_by(email=self.email.data).first()
        if email_user:
            self.email.errors.append("Email already registered.")
            return False

        return True


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])


class TwoFactorForm(FlaskForm):
    otp = StringField('Enter OTP', validators=[InputRequired(), Length(min=6, max=6)])
