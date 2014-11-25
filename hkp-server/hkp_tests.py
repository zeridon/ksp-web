#!/usr/bin/env python

import os
import hkp_server as tap
import unittest

class FlaskrTestCase(unittest.TestCase):

	def setUp(self):
		tap.app.config['TESTING'] = True
		self.app = tap.app.test_client()
	
	def tearDown(self):
		pass

	def test_main_page(self):
		rv = self.app.get('/')
		assert 'This is a HKP compliant keyserver used for organizing keysigning parties' in rv.data
	
	def test_publish_key(self):
		rv = self.app.post('/pks/add', data=dict(keytext='invalid'))
		assert 'Invalid key sent' in rv.data

		fdata = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'testdata', 'valid-key.asc'), 'r').read()
		rv = self.app.post('/pks/add', data=dict(keytext=fdata))
		assert '9DF08D79CB8BB8BE' in rv.data
	
	def test_search_key(self):
		fdata = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'testdata', 'valid-key.asc'), 'r').read()
		rv = self.app.post('/pks/add', data=dict(keytext=fdata))
		assert '9DF08D79CB8BB8BE' in rv.data

		# v4 id
		rv = self.app.get('/pks/lookup?op=get&search=0x9DF08D79CB8BB8BE')
		assert '-----BEGIN PGP PUBLIC KEY BLOCK-----' in rv.data

		# v3 id
		rv = self.app.get('/pks/lookup?op=get&search=0xCB8BB8BE')
		assert '-----BEGIN PGP PUBLIC KEY BLOCK-----' in rv.data

		# v4 fingerprint
		rv = self.app.get('/pks/lookup?op=get&search=0xB09E58EEB5B7885B06C330A69DF08D79CB8BB8BE')
		assert '-----BEGIN PGP PUBLIC KEY BLOCK-----' in rv.data

		# missing 0x
		rv = self.app.get('/pks/lookup?op=get&search=9DF08D79CB8BB8BE')
		assert 'Search type not suported. Only ID or V4 fingerprint supported' in rv.data

		# v3 fingerprint
		rv = self.app.get('/pks/lookup?op=get&search=0xB09E58EEB5B7885B06C330A69DF08D79')
		assert 'Search type not suported. Only ID or V4 fingerprint supported' in rv.data

		# non hex
		rv = self.app.get('/pks/lookup?op=get&search=0x9DF08D79CB8BB8BZ')
		assert 'ID/Fingerprint incomplete' in rv.data

		# bundle
		rv = self.app.get('/pks/lookup?op=x-get-bundle')
		assert '-----BEGIN PGP PUBLIC KEY BLOCK-----' in rv.data

if __name__ == '__main__':
	unittest.main()
