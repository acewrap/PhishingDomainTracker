from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import SubmitField

class CSVUploadForm(FlaskForm):
    file = FileField('CSV File', validators=[
        FileRequired(),
        FileAllowed(['csv'], 'CSV files only!')
    ])
    submit = SubmitField('Import CSV')

class RestoreForm(FlaskForm):
    file = FileField('Backup JSON File', validators=[
        FileRequired(),
        FileAllowed(['json'], 'JSON files only!')
    ])
    submit = SubmitField('Restore Database')
