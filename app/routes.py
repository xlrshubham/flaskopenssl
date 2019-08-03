from flask import render_template, flash, redirect, url_for
from app import app
from flask import request
from werkzeug.urls import url_parse
from datetime import datetime
import datetime as datetime1
from app.forms import SignCertFrom
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
		csr1 = form.csr.data
		if not csr1:
			flash('Please provide valid csr')
		cakey=os.path.join(app.config['PRIVPATH'],cakey)
		cacert=os.path.join(app.config['CERTPATH'],cacert)
		if not ( os.path.exists(cakey) and os.path.exists(cacert)):
			return # Handle error here
		try:
			cakey_read=open(cakey).read()
			cacert_read=open(cacert).read()
			ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, cakey_read)
			ca_crt = crypto.load_certificate(crypto.FILETYPE_PEM, cacert_read)
			csr = crypto.load_certificate_request(crypto.FILETYPE_PEM,csr1)
			cert=crypto.X509()
			cert.set_serial_number(1)
			starttime= int((datetime.utcnow() - datetime(1970,1,1)).total_seconds())
			endtime= int((datetime.utcnow() + datetime1.timedelta(days=365) - datetime(1970,1,1)).total_seconds())
			cert.gmtime_adj_notBefore(starttime)
			cert.gmtime_adj_notAfter(endtime)
			cert.set_issuer(ca_crt.get_subject())
			cert.set_subject(csr.get_subject())
			cert.set_pubkey(csr.get_pubkey())
			cert.sign(cakey, 'sha1')
			e=crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
			f=open(os.path.join(app.config['CERTPATH'],'client'+starttime+'.crt'),'a')
			f.write(e)
			f.close()
#			cert.sign(cakey, hashes.SHA256())
#			with open("output.crt","wb") as f:
#				f.write(cert.public_bytes(serialization.Encoding.PEM))
		except Exception as e:
			flash(e)
			flash("Please Store valid base 64 key and cert in folder  " +  cacert  +"   " +  cakey)
		flash(csr1)
		return redirect(url_for('index'))

	return render_template('sign.html', title='Sign a certificate', form=form)
