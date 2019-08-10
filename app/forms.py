from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, FileField, IntegerField
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo
from wtforms import StringField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Length
from flask import flash
from wtforms import validators as myvals


class SignCertFrom(FlaskForm):
	cakey = StringField('Name of CA Private Key File(Default: "ca.key" )')
	cacert = StringField('Name of Ca CA Certificate File(Default: "ca.crt")')
	days = IntegerField('Validity in Days (Default 365x10 Days)',[myvals.optional()] )
	csr = TextAreaField('CSR Base64 Encoded',validators=[])
	csrfile=FileField('CSR from File',validators=[]) 		
	submit = SubmitField('SIGN CSR')


class UploadCaForm(FlaskForm):
	password = StringField('What is admin password ? You have to enter password before uploading certificates Directly',validators=[])
	cakey=FileField('CA Private Key',validators=[]) 	
	cacert=FileField('CA Public Certificate',validators=[])
	submit = SubmitField('Upload CA Files')
	def validate_password(form,password):
		if not password.data == "123456":
			raise ValidationError("Please Input Valid Password for Uploading CA Key or Certificate")
 
