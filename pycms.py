import _pycms
import datetime
import sys

__doc__ = _pycms.__doc__
__license__ = "LGPL"
__version__="1.0.0"
__author__="Dmitry Dulesov"
__email__="dmitry.dulesov@gmail.com"

def run():
    print("openssl version", _pycms.init() )
    print("pycms doc", __doc__ )
    
    l = _pycms.engine_by_id("gost")
    print("engine_by_id returns", l)

    ca = _pycms.x509_from_file("./tests/caef9f6a.0")

    subject = ca.subject
    issuer = ca.issuer

    print("ca", ca)
    print("ca sn=",ca.serialNumber)
    print("ca notbefore", ca.notBefore)
    print("ca notafter", ca.notAfter)
    del ca
    print("subject", subject)
    print("issuer", issuer)
    
    store = _pycms.X509Store()
    store.load(path="./tests/")
    print("store", store)

    ca = _pycms.x509_from_file("./tests/caef9f6a.0")
    #store.add( ca )

    cms = _pycms.CMS_from_file("./tests/cms.pem")
    print("cms", cms)    
    print("cms verify")
    
    del ca

    res = cms.verify(caStore=store, content=b'test string\x0A', 
        notBefore = datetime.datetime( 2019, 8, 12, 10, 59, 50),
        notAfter = datetime.datetime( 2019, 8, 23, 23, 40, 10)
    )
    #del store

    print("result", res)

    cms = _pycms.CMS_from_file("./tests/cms_2001.pem")
    res = cms.verify(caStore=store, content=b'test string\x0A', 
        notBefore = datetime.datetime( 2019, 8, 12, 10, 59, 50),
        notAfter = datetime.datetime( 2019, 8, 23, 23, 40, 10)
    )
    print("result", res)

    cms = _pycms.CMS_from_file("./tests/cms_rsa.pem")
    res = cms.verify(caStore=store, content=b'test string\x0A', 
        notBefore = datetime.datetime( 2019, 8, 12, 10, 59, 50),
        notAfter = datetime.datetime( 2019, 8, 23, 23, 40, 10)
    )
    print("result", res)

    o = cms.signers
    #print("signers",o )
    print(sys.getrefcount(o))

    print("signed time", cms.signedtime )
    print("content", cms.content)
    print("verify signer certificate")
    print( store.verify( o[0] ))

if __name__=="__main__":
    print( dir(_pycms) )
    run()