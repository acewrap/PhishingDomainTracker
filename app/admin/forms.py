from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import SubmitField, StringField, BooleanField
from wtforms.validators import DataRequired

class CSVUploadForm(FlaskForm):
    file = FileField('CSV File', validators=[
        FileRequired(),
        FileAllowed(['csv'], 'CSV files only!')
    ])
    auto_enrich = BooleanField('Auto Enrich?', default=True)
    submit = SubmitField('Import CSV')

class RestoreForm(FlaskForm):
    file = FileField('Backup JSON File', validators=[
        FileRequired(),
        FileAllowed(['json'], 'JSON files only!')
    ])
    submit = SubmitField('Restore Database')

class ThreatTermForm(FlaskForm):
    term = StringField('Threat Term', validators=[DataRequired()])
    submit = SubmitField('Add Term')

class ParkingNameserverForm(FlaskForm):
    ns = StringField('Parking Nameserver', validators=[DataRequired()])
    submit = SubmitField('Add Nameserver')

class SubdomainToCheckForm(FlaskForm):
    subdomain = StringField('Subdomain', validators=[DataRequired()])
    submit = SubmitField('Add Subdomain')

class PathToCheckForm(FlaskForm):
    path = StringField('Path', validators=[DataRequired()])
    submit = SubmitField('Add Path')

from wtforms import IntegerField

class ScheduleConfigForm(FlaskForm):
    purple_mins = IntegerField('Purple (Takedown Requested) Interval (minutes)', validators=[DataRequired()])
    red_mins = IntegerField('Red (Active/Login) Interval (minutes)', validators=[DataRequired()])
    orange_mins = IntegerField('Orange (MX Record) Interval (minutes)', validators=[DataRequired()])
    yellow_mins = IntegerField('Yellow (Monitoring) Interval (minutes)', validators=[DataRequired()])
    brown_mins = IntegerField('Brown (For Sale) Interval (minutes)', validators=[DataRequired()])
    grey_mins = IntegerField('Grey (Remediated) Interval (minutes)', validators=[DataRequired()])
    submit = SubmitField('Update Schedule')
