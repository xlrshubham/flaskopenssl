from flask import render_template, flash, redirect, url_for, request, send_file
from app import app
from flask import request
from werkzeug.urls import url_parse
from werkzeug import secure_filename
from datetime import datetime
import datetime as datetime1
from app.forms import SignCertFrom, UploadCaForm
from OpenSSL import crypto
from cryptography.hazmat.primitives import hashes
import os

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
		cakey.save(os.path.join(app.config['PRIVPATH'],secure_filename(cakey.filename)))
		flash(os.path.join(app.config['PRIVPATH'],cakey.filename))
		cacert.save(os.path.join(app.config['CERTPATH'],secure_filename(cacert.filename)))
		flash("File has been Uploaded")
		return redirect(url_for('sign'))
	return render_template('upload.html',title='Upload CA Key and Cert',form=form)


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
