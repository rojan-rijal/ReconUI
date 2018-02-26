from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, IntegerField, PasswordField, BooleanField
from wtforms.validators import DataRequired, URL
class ManualForm(FlaskForm):
    """
    Form for admin to add or edit a s3bucket
    """
    company = StringField('Company', validators=[DataRequired()])
    url = StringField('URL (Make sure to have either http:// or https://)', validators=[DataRequired(), URL(require_tld=True, message='Wrong Domain')])
    beta_key = PasswordField('Private key', validators=[DataRequired()])
    agreement = BooleanField('By checking this, you agree to the <a href="http://scan.bugbounty.site/agreement" target="_blank">Terms of Agreement</a>', validators=[DataRequired()])
    submit = SubmitField('Submit')

