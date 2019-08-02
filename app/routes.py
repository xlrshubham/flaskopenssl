from flask import render_template, flash, redirect, url_for
from app import app
from flask import request
from werkzeug.urls import url_parse
from datetime import datetime
from app.forms import SignCertFrom
from OpenSSL import crypto
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
		csr = form.csr.data
		if not csr:
			flash('Please provide valid csr')
		cakey=os.path.join(app.config['PRIVPATH'],cakey)
		cacert=os.path.join(app.config['CERTPATH'],cacert)
		if not ( os.path.exists(cakey) and os.path.exists(cacert)):
			return # Handle error here
		try:
			cakey_read=open(cakey).read()
			cacert_read=open(cacert).read()
			ca_key = crypto.load_certificate(crypto.FILETYPE_PEM, cakey_read)
			ca_crt = crypto.load_certificate(crypto.FILETYPE_PEM, cacert_read)
			#ca_csr = crypto.load_certificate_request(crypto.
		except:
			flash("Please Store valid base 64 key and cert in folder  " +  cacert  +"   " +  cakey)
		flash(cacert_read)
		return redirect(url_for('index'))

	return render_template('sign.html', title='Sign a certificate', form=form)
