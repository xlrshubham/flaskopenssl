from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, FileField, IntegerField
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo
from wtforms import StringField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Length
from flask import flash
from wtforms import validators as myvals


class SignCertFrom(FlaskForm):
	cakey = StringField('cakey')
	cacert = StringField('cacert')
	csr = TextAreaField('csr',validators=[])
	days = IntegerField('days',[myvals.optional()] )
	csrfile=FileField('csrfile',validators=[]) 		
	submit = SubmitField('Get Cert')


class UploadCaForm(FlaskForm):
	cakey=FileField('cakey',validators=[]) 	
	cacert=FileField('cacert',validators=[])
	submit = SubmitField('Upload')
