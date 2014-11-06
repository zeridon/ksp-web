#!/usr/bin/env python
#
# Desc     : Simple HKP server for collecting PGP keys for keysigning parties
# Author   : Vladimir vitkov <vvitkov@linux-bg.org>
# License  : Apache 2.0
# Version  : 1.0
# Changelog: 2014.11.05 - Initial version

from flask import Flask, request, render_template
import os

app = Flask(__name__)

## Some vars
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
GPG_HOME = os.path.join(BASE_DIR, 'keysigning', 'gpg-home')
KEY_STORE = os.path.join(BASE_DIR, 'keysigning', 'keys')

# check and fix
if not os.path.exists(GPG_HOME):
	print '%s does not exist. Creating...' % GPG_HOME
	os.makedirs(GPG_HOME, 0700)

if not os.path.exists(KEY_STORE):
	print '%s does not exist. Creating...' % KEY_STORE
	os.makedirs(KEY_STORE, 0700)

def get_file_path(keyid=u''):
	"""
	return the full path to a file containing the key
	"""
	return os.path.join(KEY_STORE, str(keyid[0:4]), str(keyid[4:8]), keyid).lower()

@app.route('/pks/lookup', methods=['GET'])
def search_key():
	machine_readable = False

	operation = request.args.get('op')
	# valid operations
	# get - send the keys (html wrapping possible) or 404
	# index - list matching keys or 501 if not supported
	# vindex - verbose list or 501
	# x-<...> - custom
	if operation == 'get':
		pass
	elif operation == 'index' or operation == 'vindex':
		return render_template(
				'50x.html',
				error_num = 501,
				error_txt = 'Operation not supported. Only get and x-get-bundle supported.',
				), 501
	elif operation == 'x-get-bundle':
		pass
	else:
		pass

	search = request.args.get('search')
	# valid keyid's (spacing added for readability)
	# 0x12345678 - 32bit keyid
	# 0x12345678 12345678 - 64bit
	# 0x12345678 12345678 12345678 12345678 - v3 fingerprint
	# 0x12345678 12345678 12345678 12345678 12345678 - v4 fingerprint
	if search.startswith('0x'):
		search = search[2:]
		if len(search) in (8, 16, 40):
			try:
				int(search, 16)
			except:
				return render_template(
						'50x.html',
						error_num = 404,
						error_txt = 'ID/Fingerprint incomplete',
						), 404
			
			# now get the key and dump it
			if len(search) == 40:
				# v4 fingerprint - keyid is last 16 digits
				search = search[-16:]

			keyfile = get_file_path(search)
			
			# now dump it
			fp = open(keyfile, 'r')
			return fp.read(), 200, {'Content-Type': 'application/pgp-keys'}
			#return keyfile
		else:
			return render_template(
					'50x.html',
					error_num = 404,
					error_txt = 'ID/Fingerprint incomplete',
					), 404
	else:
		return render_template(
				'50x.html',
				error_num = 501,
				error_txt = 'Search type not suported. Only ID or V4 fingerprint supported',
				), 501

	options = request.args.get('options')
	# valid options (comma separated list
	# mr - machine readable
	# nm - no modify - usefull for adding keys
	# x-<...> - site speciffic
	#for opt in split(options):
	#	if opt == 'mr':
	#		machine_readable=True
	#	else:
	#		pass

	fingerprint = request.args.get('fingerprint')
	# on/off - display fingerprint on index/vindex

	exact = request.args.get('exact')
	# on/off - exact matches

	# x- ... - local

	#sample http://keys.example.com:11371/pks/lookup?op=get&search=0x99242560

@app.route('/pks/add', methods=['POST'])
def add_key():
	"""
	Add keys that we were sent
	"""

	import gnupg
	from tempfile import mkdtemp
	from shutil import rmtree

	# build a temporary place for empty keyring
	_gpghome = mkdtemp(prefix = os.path.join(GPG_HOME, 'ksp'))

	# Init the GPG
	gpg = gnupg.GPG(gnupghome = _gpghome)

	# Blindly try to import and check result. If we have count we are fine
	import_result = gpg.import_keys(request.form['keytext'])
	if import_result.count <= 0:
		return render_template(
				'50x.html',
				error_num = 501,
				error_txt = 'Invalid key sent'
				), 501
	
	# Now list the keys in the keyring and store it on the FS
	imported_keys = gpg.list_keys()
	for key in imported_keys:
		# Create a keypath (and dirs if needed)
		_path = get_file_path(key['keyid'])
		import subprocess
		subprocess.Popen("ls %s"%os.path.dirname(_path), shell=True)
		if not os.path.exists(_path):
			print _path
			os.makedirs(os.path.dirname(_path), 0700)

		# Store the file in path/12/1234567812345678
		fp = open(_path, 'w')
		fp.write(gpg.export_keys(key['keyid']))
		fp.close()
	
	# Nuke the temp gpg home
	rmtree(_gpghome)

	return '101'

@app.route('/', methods=['GET'])
@app.route('/about', methods=['GET'])
def show_about_page():
	return render_template('about.html')

if __name__ == '__main__':
	app.run(debug=True)
