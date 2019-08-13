from flask import render_template, flash, redirect, url_for, request, send_file
from app import app
from flask import request
from werkzeug.urls import url_parse
from werkzeug import secure_filename
from datetime import datetime
import datetime as datetime1
from app.forms import SignCertFrom, UploadCaForm, EncryptSymmetric , KeyGenerator
from OpenSSL import crypto
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, dsa

@app.route('/')
@app.route('/index')
def index():
	return render_template('index.html', title='Home')


@app.route('/sign',methods=['GET', 'POST'])
def sign():
	form=SignCertFrom()
	if form.validate_on_submit():
		cakey = form.cakey.data or 'ca.key'
		cacert= form.cacert.data or 'ca.crt'
		if(form.days.data):
			days=int(form.days.data)
		else:
			days=3652
		csr1 = form.csr.data
		csr2=request.files['csrfile'].read()
		csr2=str(csr2.decode("utf-8"))
		#csr2=regex.sub(" ", csr2).lower() 
		print(csr2)
		filename="404"
		filedata=""
		if not csr1 and not csr2:
			flash('Please provide valid csr')
		if csr2:
			csr1=csr2
		cakey=os.path.join(app.config['PRIVPATH'],cakey)
		cacert=os.path.join(app.config['CERTPATH'],cacert)
		if not ( os.path.exists(cakey) and os.path.exists(cacert)):
			return # Handle error here
		try:
			counter_f=open(app.config['COUNTER'],'a+')
			counter=int(len(counter_f.read()))
			counter_f.write('1')
			counter_f.close()
			cakey_read=open(cakey).read()
			cacert_read=open(cacert).read()
			ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, cakey_read)
			ca_crt = crypto.load_certificate(crypto.FILETYPE_PEM, cacert_read)
			csr = crypto.load_certificate_request(crypto.FILETYPE_PEM,csr1)
			cert=crypto.X509()
			cert.set_serial_number(counter)
			starttime= int((datetime.utcnow() - datetime(1970,1,1)).total_seconds())
			starttime=0
			endtime= int((datetime.utcnow() + datetime1.timedelta(days=365) - datetime(1970,1,1)).total_seconds())
			endtime=days*24*60*60
			cert.gmtime_adj_notBefore(starttime)
			cert.gmtime_adj_notAfter(endtime)
			cert.set_issuer(ca_crt.get_subject())
			cert.set_subject(csr.get_subject())
			cert.set_pubkey(csr.get_pubkey())
			cert.sign(ca_key, 'sha1')
			e=crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
			filedata=e
			filename='client'+str(counter)+'.crt'
			f=open(os.path.join(app.config['CERTPATH'],filename),'a')
			f.write(e)
			f.close()
#			cert.sign(cakey, hashes.SHA256())
#			with open("output.crt","wb") as f:
#				f.write(cert.public_bytes(serialization.Encoding.PEM))
		except Exception as e:
			flash("Please Store valid base 64 key and cert in folder  " +  cacert  +"   " +  cakey)
		return render_template('sign.html', title='Sign a certificate', form=form, file=url_for('download',file=filename))
	return render_template('sign.html', title='Sign a certificate', form=form)

@app.route('/upload',methods=['GET','POST'])
def upload():
	form=UploadCaForm()
	if form.validate_on_submit():
		cakey = request.files['cakey']
		cacert=request.files['cacert']
		if(cakey):
			cakey.save(os.path.join(app.config['PRIVPATH'],secure_filename(cakey.filename)))
			flash(os.path.join(app.config['PRIVPATH'],cakey.filename))
		if(cacert):
			cacert.save(os.path.join(app.config['CERTPATH'],secure_filename(cacert.filename)))
		flash("File has been Uploaded")
		return redirect(url_for('sign'))
	return render_template('upload.html',title='Upload CA Key and Cert',form=form)

@app.route('/keygen',methods=['GET','POST'])
def keygen():
	form=KeyGenerator()
	if form.validate_on_submit():
		algo=form.algo.data
		keylength=int(form.keylength.data)
		filepath1=os.path.join(app.config['CERTPATH'], secure_filename("private-"+str(datetime.now().strftime("%y%B%d%H%M%S")+".PME")))
		filepath2=os.path.join(app.config['CERTPATH'], secure_filename("private-"+str(datetime.now().strftime("%y%B%d%H%M%S")+"_PKCS8.PME")))
		filename1=secure_filename("private-"+str(datetime.now().strftime("%y%B%d%H%M%S")+".PME"))
		filename2=secure_filename("private-"+str(datetime.now().strftime("%y%B%d%H%M%S")+"_PKCS8.PME"))
		if algo=='rsa':
			private_key = rsa.generate_private_key(public_exponent=65537,key_size=keylength,backend=default_backend())
			priv_text=private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL,encryption_algorithm=serialization.NoEncryption())
			priv_text2=private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.NoEncryption())
		if algo=='dsa':
			private_key = dsa.generate_private_key(key_size=keylength,backend=default_backend())
			priv_text=private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL,encryption_algorithm=serialization.NoEncryption())
			priv_text2=private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.NoEncryption())
		if not private_key:
			flash("Some error occured. Please notify System Admin. ")
			return render_template('keygen.html',title='Key Generator', form=form)	
			
		pub_text=private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
		pubssh_text=private_key.public_key().public_bytes(encoding=serialization.Encoding.OpenSSH,format=serialization.PublicFormat.OpenSSH)
		form.priv.data=priv_text
		if priv_text2:
			form.priv2.data=priv_text2
		form.pub.data=pub_text
		form.pubssh.data=pubssh_text
		flash("Keys Created")
		completefile=priv_text2 + priv_text + pub_text + pubssh_text
		#form.priv.data=completefile
		f = open(filepath1, "a")
		f.write(priv_text)
		f.close()
		f = open(filepath2, "a")
		f.write(priv_text2)
		f.close()
		
		files=[url_for('download',file=filename1) , url_for('download',file=filename2)] 
		return render_template('keygen.html',title='Key Generator', form=form, keys=1, files=files)
	else:
		pass
		#flash("Validation incomplete")
	return render_template('keygen.html',title='Key Generator', form=form)	


@app.route('/encsym',methods=['GET','POST'])
def encsym():
	form=EncryptSymmetric()
	if form.validate_on_submit():
		text=form.text.data.encode('utf-8')
		password=form.password.data.encode('utf-8')
		salt=form.salt.data.encode('utf-8')
		option=form.option.data
		if not salt:
			salt="****__SECRET___***".encode()
		kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend() )
		key = base64.urlsafe_b64encode(kdf.derive(password))
		f = Fernet(key)
		if option == 'enc':
			token = f.encrypt(text)
		else:
			try:
				token = f.decrypt(text)
			except Exception  as e:
				flash("Either Password or Salt is wrong !!! Decryption Not Possible")
				return redirect(url_for('encsym'))
			token = unicode(token, "utf-8")
		return render_template('encsym.html',title='Symetric Encryption', form=form, token=token, operation=option)
	return render_template('encsym.html',title='Symmetric Encryption', form=form)	
	
@app.route("/download/<file>")
def download(file = None):
	if file is None:
		flash("ERROR")
	try:
		path=os.path.join(app.config['CERTPATH'],file)
		return send_file(path, as_attachment=True)
	except Exception as e:
		flash(e)
	return redirect(url_for('sign'))
