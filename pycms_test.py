import unittest
import datetime
from datetime import timedelta, timezone

try:
    from datetime import timezone
    utc = timezone.utc
except:
    utc = None

import _pycms

DEF_CONTENT = b'test string\n'

class TestModuleMethods(unittest.TestCase):
    def setUp(self):
        self.version = _pycms.init()
        self.e = _pycms.engine("gost")

    def test_module(self):
        print( self.version )

        self.assertTrue(isinstance(self.version,str))
        self.assertTrue( self.version.startswith("OpenSSL"))
        self.assertIsNotNone(self.e)

    def test_exceptions(self):
        self.assertRaises(_pycms.OpenSSLError, _pycms.X509.load, "" )
        self.assertRaises(_pycms.OpenSSLError, _pycms.X509.load, "./tests/cms.pem" )
        
        with self.assertRaises(_pycms.VerifyError) as cm:
            cms = _pycms.CMS.load( './tests/cms.pem' )
            cms.verify( notBefore=None, notAfter="2019.08.10" )

    def test_ca(self):
        path = './tests/a7debd4e.0'

        ca = _pycms.X509.load(path)
        self.assertTrue( isinstance(ca, _pycms.X509) )

        v = ca.serialNumber
        self.assertEqual(v, 0x8b7826da63c9792b)
        
        v = ca.subject
        self.assertEqual(v, '/CN=localhost/OU=gost2001')

        v = ca.notBefore
        self.assertEqual(v, datetime.datetime(2019, 8, 23, 16, 9, 41, tzinfo=utc) )

        v = ca.notAfter
        self.assertEqual(v, datetime.datetime(2029, 8, 20, 16, 9, 41, tzinfo=utc) )

        del ca
        path = './tests/caef9f6a.0'

        ca = _pycms.X509.load(path)
        v= ca.subject

        self.assertEqual(v, '/CN=localhost/OU=gost2012_512' )
        del ca

    def test_store(self):
        store = _pycms.X509Store()

        self.assertIsNotNone( store )
        path = './tests/caef9f6a.0'
        ca = _pycms.X509.load(path)

        store.add( ca )
        del ca
        del store

    def test_monkey(self):
        path = './tests/caef9f6a.0' 
        ca = _pycms.X509.load(path)
        store = _pycms.X509Store()
        store.add( ca )
        del ca

        path = './tests/cms.pem'
        cms = _pycms.CMS.load( path )
        signers = None

        for i in range(100):
            del signers
            signers = cms.signers

            for signer in signers:
                store.verify( signer )

            cms.verify(caStore=store, content=DEF_CONTENT )


    def test_cms_1(self):
        store = _pycms.X509Store()

        path = './tests/caef9f6a.0'  
        ca = _pycms.X509.load(path)

        store.add( ca )
        del ca

        path = './tests/cms.pem'
        cms = _pycms.CMS.load( path )

        signer = cms.signers[0]

        self.assertEqual( signer.serialNumber, 0xa85f64f55b42aa76 )
        self.assertEqual( signer.subject, '/C=RU/ST=Moscow/L=Moscow/O=Global Security/OU=IT Department/CN=dmitry.dulesov@gmail.com' )
        self.assertEqual( signer.issuer, '/CN=localhost/OU=gost2012_512' )

        self.assertEqual( signer.notAfter, datetime.datetime(2020, 8, 22, 16, 9, 41, tzinfo=utc) )
        self.assertEqual( cms.content, DEF_CONTENT )

        self.assertEqual( cms.signedtime[0] , datetime.datetime(2019, 8, 23, 16, 9, 41, tzinfo=utc) )

        v = store.verify( signer )
        self.assertTrue( v )

        v = cms.verify(caStore=store, content=DEF_CONTENT )
        self.assertTrue( v )

        v = cms.verify(caStore=store )
        self.assertTrue( v )

        v = cms.verify(caStore=store , content=DEF_CONTENT, 
            notBefore = datetime.datetime( 2019, 8, 12, 10, 59, 50, tzinfo=utc),
            notAfter = datetime.datetime( 2019, 8, 23, 23, 40, 10, tzinfo=utc)
        )
        self.assertTrue( v )

        v = cms.verify(caStore=store , content=b'other content', 
            notBefore = datetime.datetime( 2019, 8, 12, 10, 59, 50, tzinfo=utc),
            notAfter = datetime.datetime( 2019, 8, 23, 23, 40, 10, tzinfo=utc)
        )
        self.assertFalse( v )       

        v = cms.verify(caStore=store , content=DEF_CONTENT, 
            notBefore = datetime.datetime( 2019, 8, 12, 10, 59, 50, tzinfo=utc),
            notAfter = datetime.datetime( 2019, 8, 23, 16, 00, 00, tzinfo=utc)
        )
        
        self.assertFalse( v )

        v = cms.verify(caStore=store , content=DEF_CONTENT, 
            notBefore = datetime.datetime( 2019, 8, 12, 10, 59, 50, tzinfo=utc)
        )
        
        self.assertTrue( v )

        del store
        store = _pycms.X509Store()

        v = cms.verify(caStore=store , content=DEF_CONTENT, 
            notBefore = datetime.datetime( 2019, 8, 12, 10, 59, 50, tzinfo=utc),
            notAfter = datetime.datetime( 2019, 8, 23, 23, 40, 10, tzinfo=utc)
        )

        self.assertFalse( v )

    def test_cms_2(self):
        store = _pycms.X509Store()
        path = './tests/caef9f6a.0'  
        ca = _pycms.X509.load(path)

        store.add( ca )

        path = './tests/cms_2001.pem'
        cms = _pycms.CMS.load( path )

        signer = cms.signers[0]

        self.assertFalse( cms.verify(caStore=store , content=DEF_CONTENT, 
            notBefore = datetime.datetime( 2019, 8, 12, 10, 59, 50, tzinfo=utc),
            notAfter = datetime.datetime( 2019, 8, 23, 23, 40, 10, tzinfo=utc)
        ) )

        self.assertFalse( cms.verify(caStore=store , content=DEF_CONTENT) )
        self.assertFalse( cms.verify(caStore=store ) )
        self.assertFalse( store.verify( signer ) )

    def test_cms_3(self):
        store = _pycms.X509Store()
        store.load(path="./tests/")

        path = './tests/cms.pem'
        cms = _pycms.CMS.load( path )

        self.assertTrue( cms.verify(caStore=store , content=DEF_CONTENT, 
            notBefore = datetime.datetime( 2019, 8, 12, 10, 59, 50, tzinfo=utc),
            notAfter = datetime.datetime( 2019, 8, 23, 23, 40, 10, tzinfo=utc)
        ) )

        path = './tests/cms_rsa.pem'
        cms = _pycms.CMS.load( path )

        self.assertTrue( cms.verify(caStore=store , content=DEF_CONTENT, 
            notBefore = datetime.datetime( 2019, 8, 12, 10, 59, 50, tzinfo=utc),
            notAfter = datetime.datetime( 2019, 8, 23, 23, 40, 10, tzinfo=utc)
        ) )

        path = './tests/cms_2001.pem'
        cms = _pycms.CMS.load( path )

        self.assertTrue( cms.verify(caStore=store , content=DEF_CONTENT, 
            notBefore = datetime.datetime( 2019, 8, 12, 10, 59, 50, tzinfo=utc),
            notAfter = datetime.datetime( 2019, 8, 23, 23, 40, 10, tzinfo=utc)
        ) )     

    def test_sign(self):
        key = _pycms.EVP.load("./tests/key1.pem", b"123456")
        #self-signed certificate
        cert = _pycms.X509.load("./tests/cert1.pem")

        notBefore = datetime.datetime.utcnow().replace(tzinfo = utc) - timedelta(seconds=1)

        cms = _pycms.CMS.sign(pkey=key, signer=cert, content=b'123456789')

        self.assertTrue( cms.pem.startswith(b"-----BEGIN CMS-----") )
        self.assertEqual( b'123456789', cms.content )

        notAfter = datetime.datetime.utcnow().replace(tzinfo = utc) + timedelta(seconds= 1)
        signingTime = cms.signedtime[0]

        #print("not Before", notBefore)

        self.assertTrue( signingTime>=notBefore )
        self.assertTrue( signingTime<=notAfter )

        store = _pycms.X509Store()
        store.add( cert )

        #print("python notAfter timestamp ", notAfter.timestamp() )
        #print("python notBefore timestamp ", notBefore.timestamp() )

        self.assertTrue( cms.verify(caStore=store, content=b'123456789', notAfter=notAfter, notBefore=notBefore) )


if __name__ == '__main__':
    unittest.main()