HKP Keyserver
=============
A simple HKP compliant (partly) server for use in keysigning parties

What this is
------------
This is a simplistic HKP compliant server for use in keysigning parties. Main duties in handling a keysigning party are:

 * Receive GPG/PGP keys
 * Return requested GPG/PGP keys

Additional functionality:

 * Return all keys currently known to the server in a single bundle
 * Some optimisations for speed
 * A bit of a paranoid design

Requirements
------------
 * Flask
 * python-gnupg

How to run this software
------------------------

```
virtualenv --no-site-packages venv
source ./venv/bin/activate
pip install -r requirements.txt

# how hit the party
./hkp-server.py
```

As this is still considered development it is running on port 5000

How to use
----------

 * Point your gpg client to it
```
 gpg --keyserver ... --send-keys
 gpg --keyserver ... --recv-keys
```
 * Get all participating keys
```
 curl http://...:5000/pks/lookup?op=x-get-bundle -o keysigning-party-bundle.asc
```
or
```
 curl http://...:5000/all-keys -o keysigning-party-bundle.asc
```
and import it in a fresh keyring (not to polute yours).
