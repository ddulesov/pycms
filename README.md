# pycms
python CMS library with gost cryptography validation support

## *alpha* version! 

[![Build Status](https://travis-ci.com/ddulesov/pycms.svg?branch=master)](https://travis-ci.com/ddulesov/pycms) 

## Features
- dynamic linking with system openssl lib
- python 3.x and python 2.7
- small size (<25Kb) and footprint. _pycms is thin wrapper over openssl libcrypto library. 
- Windows , Linux , OSx supported
- openssl 1.1.x compatible
- can use openssl extension modules via OpenSSL engine api [gost (34.11-94, 34.10-2001, 34.10-2012)](http://wiki.rosalab.ru/ru/index.php/OpenSSL_%D0%B8_%D0%93%D0%9E%D0%A1%D0%A2)
- validate CMS using build-in openssl cryptograpy algorithm 
- validate CMS SignedData signing time , content, signers certificates using  provided ca store. 
- support openssl hashed local issued  [ certificates store (CA)](https://www.openssl.org/docs/man1.1.0/man1/rehash.html)

## Issues
- only PEM encoding CMS and certificate supported 
- only SignedData  type CMS
- (see [TODO.md](TODO.md) )

## Requirements
- python 2.7 or python 3.6+ 
- openssl 1.1.x 
- openssl gost engine (optional)

## Building and Installation
```console
sudo apt-get install -y openssl libengine-gost-openssl1.1  
#in development machine if required
#sudo apt-get install -y build-essential python3 python3-dev libssl-dev
git clone --depth 1  https://github.com/ddulesov/pycms.git

cd pycms
python3 setup.py build install
#run tests
python3 pycms_test.py
```
## Quickstart
```python

import _pycms
import datetime
import sys

#initialize openssl and gost engine
_pycms.init() 
e = _pycms.engine("gost")

store = _pycms.X509Store()

#single CA
#ca = _pycms.X509.load("./tests/caef9f6a.0")
#store.add(ca)

#configure local issued CA certificate store
store.load(path="./tests/")
cms = _pycms.CMS.load("./tests/cms.pem")

#validation process
res = cms.verify(caStore=store, content=b'test string\x0A', 
        notBefore = datetime.datetime( 2019, 8, 12, 10, 59, 50),
        notAfter = datetime.datetime( 2019, 8, 23, 23, 40, 10)
)

print("./tests/cms.pem validation status", res )
signer = cms.signers[0]

print("signer ", signer.serialNumber )
```
