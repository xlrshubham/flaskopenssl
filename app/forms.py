from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, FileField, IntegerField, SelectField
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
	password = StringField('Admin Password',validators=[])
	cakey=FileField('CA Private Key',validators=[]) 	
	cacert=FileField('CA Public Certificate',validators=[])
	submit = SubmitField('Upload CA Files')
	def validate_password(form,password):
		if not password.data == "123456":
			raise ValidationError("Please Input Valid Password for Uploading CA Key or Certificate")

class EncryptSymmetric(FlaskForm):
	text=TextAreaField('Text')
	password=PasswordField('password')
	salt=StringField('Salt (Optional)')
	option=SelectField('Select Operation', choices=[('enc', 'Encryption'), ('dec', 'Decryption')]  )
	submit = SubmitField('Perform Operation')

class KeyGenerator(FlaskForm):
	#algo=SelectField('Algorithm',choices=[('dsasha1','DSA with SHA1'),('dsasha256','DSA with SHA 256'),('rsasha1','RSA with SHA-1'),('rsasha256','RSA with SHA-256'),('rsasha384','RSA with SHA-384'),('rsasha512','RSA with SHA-512')], default='rsasha256')
	algo=SelectField('Algorithms', choices=[('rsa', 'RSA'), ('dsa', 'DSA')])
	keylength=SelectField('Key Length',choices=[('1024','1024'),('2048','2048'),('3072','3072'),('4096','4096')], default='2048')
	filename=StringField('File Name(optional)')
	priv=TextAreaField('RSA Private Key',render_kw={('readonly', True), ('rows',"20"), ('cols','70')})
	priv2=TextAreaField('Private Key PKCS8',render_kw={('readonly', True), ('rows',"20"), ('cols','70')})
	pub=TextAreaField('Public Key', render_kw={('readonly', True),('rows','15')})
	pubssh=TextAreaField('SSH RSA Public Key', render_kw={('readonly', True),('rows','15')})
	submit = SubmitField('Generate Keys')
