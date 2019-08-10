import os
basedir = os.path.abspath(os.path.dirname(__file__))

class Config(object):
	SECRET_KEY=os.environ.get('SECRET_KEY') or 'you-will-never-guess'
	PRIVPATH=os.path.join(basedir,'keys/private/')
	CERTPATH=os.path.join(basedir,'keys/certs/')
	COUNTER=os.path.join(basedir,'keys/counter.txt')
	
