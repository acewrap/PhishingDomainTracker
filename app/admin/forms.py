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
