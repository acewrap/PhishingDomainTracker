from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, FileField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from app.models import User

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Update Password')

class CreateUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=150)])
    password = PasswordField('Initial Password', validators=[DataRequired(), Length(min=6)])
    is_admin = BooleanField('Is Admin')
    submit = SubmitField('Create User')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is already taken.')

class GenerateAPIKeyForm(FlaskForm):
    submit = SubmitField('Generate API Key')

class AddDomainForm(FlaskForm):
    domain_name = StringField('Domain Name')
    file_upload = FileField('Upload Email (.eml / .msg)')
    auto_enrich = BooleanField('Auto Enrich')
    submit = SubmitField('Submit')

    def validate(self, extra_validators=None):
        if not super().validate(extra_validators):
            return False
        if not self.domain_name.data and not self.file_upload.data:
            self.domain_name.errors.append('Please provide either a Domain Name or an Email file.')
            return False
        return True

class UpdateDomainForm(FlaskForm):
    action_taken = StringField('Action Taken')
    date_remediated = StringField('Date Remediated')
    is_active = BooleanField('Is Active')
    has_login_page = BooleanField('Has Login Page')
    manual_status = StringField('Manual Status')
    # Since the update form in domain_detail is split/complex, we might need flexible validation or multiple forms.
    # For now, we will handle CSRF protection primarily.

class BulkActionForm(FlaskForm):
    # This form handles bulk enrichment and deletion
    # Since checkbox values are dynamic (domain_ids), we might just rely on the CSRF token
    pass
