#!/usr/bin/env python
#
# Desc     : Simple HKP server for collecting PGP keys for keysigning parties
# Author   : Vladimir vitkov <vvitkov@linux-bg.org>
# License  : Apache 2.0
# Version  : 1.0
# Changelog: 2014.11.18 - first stable release
#	2014.11.05 - Initial version

from flask import Flask, request, render_template, redirect
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

def get_file_path(keyid=''):
	"""
	return the full path to a file containing the key
	"""
	keyid = keyid.lower()
	return str(os.path.join(KEY_STORE, keyid[0:4], keyid[4:8], keyid))

def return_error(code = 501, text = 'Not supported'):
	return render_template(
			'50x.html',
			error_num = code,
			error_txt = text,
			), code

@app.route('/pks/lookup', methods=['GET'])
def search_key():
	'''
	Handle searching of keys and creating final bundles
	'''
	operation = request.args.get('op')
	# valid operations
	# get - send the keys (html wrapping possible) or 404
	# index - list matching keys or 501 if not supported
	# vindex - verbose list or 501
	# x-<...> - custom
	if operation == 'get':
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
					return return_error(404, 'ID/Fingerprint incomplete')
				
				# now get the key and dump it
				if len(search) == 40:
					# v4 fingerprint - keyid is last 16 digits
					search = search[-16:]
	
				keyfile = get_file_path(search)
				
				# now dump it
				if os.path.exists(keyfile):
					fp = open(keyfile, 'r')
					return fp.read(), 200, {'Content-Type': 'application/pgp-keys'}
				else:
					return return_error(404, 'Key not found on this server')
			else:
				return return_error(501, 'Search type not suported. Only ID or V4 fingerprint supported')
		else:
			return return_error(501, 'Search type not suported. Only ID or V4 fingerprint supported')
	elif operation == 'x-get-bundle':
		# find all keys, add them to keyring, then armor dump them
		# first init gpg
		import gnupg
		from tempfile import mkdtemp
		from shutil import rmtree

		_gpghome = mkdtemp(prefix = os.path.join(GPG_HOME, 'bundler'))
		gpg = gnupg.GPG(gnupghome = _gpghome, options = [
			'--with-colons',
			'--keyid-format=LONG',
			'--export-options=export-minimal,export-clean,no-export-attributes',
			'--import-options=import-minimal,import-clean'
			], verbose = False)
		for root, dirs, files in os.walk(KEY_STORE):
			for fname in files:
				if not os.path.islink(os.path.join(root, fname)):
					keydata = open(os.path.join(root, fname), 'r').read()
					gpg.import_keys(keydata)

		keys = gpg.list_keys()
		_export = []
		for key in keys:
			_export.append(key['keyid'])

		if len(_export) > 0:
			armoured = gpg.export_keys(_export)
		else:
			return return_error(404, 'No keys found on server')

		rmtree(_gpghome)
		return armoured, 200, {'Content-Type': 'application/pgp-keys'}

	else:
		return return_error(501, 'Operation not supported. Only get and x-get-bundle supported.')

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

	# now we have the op and search .. let's boogie


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
	gpg = gnupg.GPG(gnupghome = _gpghome, options = [
		'--with-colons',
		'--keyid-format=LONG',
		'--export-options=export-minimal,export-clean,no-export-attributes',
		'--import-options=import-minimal,import-clean'
		], verbose = False)

	# Blindly try to import and check result. If we have count we are fine
	import_result = gpg.import_keys(request.form['keytext'])
	if import_result.count <= 0:
		return return_error(501, 'Invalid key sent')
	
	# Now list the keys in the keyring and store it on the FS
	imported_keys = gpg.list_keys()
	for key in imported_keys:
		# Create a keypath (and dirs if needed)
		_path = get_file_path(key['keyid'])
		if not os.path.exists(os.path.dirname(_path)):
			os.makedirs(os.path.dirname(_path), 0700)

		if not os.path.exists(os.path.dirname(get_file_path(key['keyid'][-8:]))):
			os.makedirs(os.path.dirname(get_file_path(key['keyid'][-8:])), 0700)

		# Store the file in path/1234/5678/1234567812345678
		if not os.path.exists(_path):
			fp = open(_path, 'w')
			fp.write(gpg.export_keys(key['keyid']))
			fp.close()

			# and symlink it to the short ID
			if not os.path.exists(get_file_path(key['keyid'][-8:])):
				os.symlink(_path, get_file_path(key['keyid'][-8:]))
	
	# Nuke the temp gpg home
	rmtree(_gpghome)
	return key['keyid'], 200

@app.route('/', methods=['GET'])
@app.route('/about', methods=['GET'])
@app.route('/help', methods=['GET'])
@app.route('/instructions', methods=['GET'])
def show_instructions_page():
    return render_template('instructions.html')

@app.route('/all-keys', methods=['GET'])
def get_all_keys():
    return redirect("/pks/lookup?op=x-get-bundle", 302)

if __name__ == '__main__':
	app.run(debug=True)
