# pycms
python CMS library with gost cryptography validation support

*pre-alpha* release. 

## Futures
- dynamic linking with system openssl lib
- small size and footprint. _pycms is C extension module over openssl libcrypto library
- Windows , Linux , OSx supported
- openssl 1.1.x compatible
- can use openssl extensions module via engine api [gost](http://wiki.rosalab.ru/ru/index.php/OpenSSL_%D0%B8_%D0%93%D0%9E%D0%A1%D0%A2)
- validate CMS using build-in openssl cryptograpy , + validate signing time , content, signers certificates over provided ca chain. 
- openssl hashed local issued (CA) [directory suppoted](https://www.openssl.org/docs/man1.1.0/man1/rehash.html)

## Issues
- only PEM encoding CMS and certificate supported 
- only SignedData  type CMS validation realized

## Requirements
- python >3.6
- openssl 1.1.x 
- openssl gost engine (optiona)

## Building and Installation

```sh
sudo apt-get install openssl libengine-gost-openssl1.1 python3 python3-dev  libssl-dev
git clone --depth 1  https://github.com/ddulesov/pycms.git

cd pycms
python3 setup.py build
python3 setup.py install
```

#
```python

import _pycms
import datetime
import sys

_pycms.init() 
e = _pycms.engine_by_id("gost")

store = _pycms.X509Store()

#single CA
#ca = _pycms.x509_from_file("./tests/caef9f6a.0")
#store.add(ca)

#configure local issued CA certificate store
store.load(path="./tests/")

cms = _pycms.CMS_from_file("./tests/cms.pem")

res = cms.verify(caStore=store, content=b'test string\x0A', 
        notBefore = datetime.datetime( 2019, 8, 12, 10, 59, 50),
        notAfter = datetime.datetime( 2019, 8, 23, 23, 40, 10)
)

print("./tests/cms.pem validation status", res )

signer = cms.signers[0]

print("signer ", signer.serialNumber )
```
