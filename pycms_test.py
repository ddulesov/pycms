import unittest
import datetime
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
        self.assertEqual(v, datetime.datetime(2019, 8, 23, 16, 9, 41) )

        v = ca.notAfter
        self.assertEqual(v, datetime.datetime(2029, 8, 20, 16, 9, 41) )

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

        for i in range(1000):
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

        self.assertEqual( signer.notAfter, datetime.datetime(2020, 8, 22, 16, 9, 41) )
        self.assertEqual( cms.content, DEF_CONTENT )

        self.assertEqual( cms.signedtime[0] , datetime.datetime(2019, 8, 23, 16, 9, 41) )

        v = store.verify( signer )
        self.assertTrue( v )

        v = cms.verify(caStore=store, content=DEF_CONTENT )
        self.assertTrue( v )

        v = cms.verify(caStore=store )
        self.assertTrue( v )

        v = cms.verify(caStore=store , content=DEF_CONTENT, 
            notBefore = datetime.datetime( 2019, 8, 12, 10, 59, 50),
            notAfter = datetime.datetime( 2019, 8, 23, 23, 40, 10)
        )
        self.assertTrue( v )

        v = cms.verify(caStore=store , content=b'other content', 
            notBefore = datetime.datetime( 2019, 8, 12, 10, 59, 50),
            notAfter = datetime.datetime( 2019, 8, 23, 23, 40, 10)
        )
        self.assertFalse( v )       

        v = cms.verify(caStore=store , content=DEF_CONTENT, 
            notBefore = datetime.datetime( 2019, 8, 12, 10, 59, 50),
            notAfter = datetime.datetime( 2019, 8, 23, 16, 00, 00)
        )
        
        self.assertFalse( v )

        v = cms.verify(caStore=store , content=DEF_CONTENT, 
            notBefore = datetime.datetime( 2019, 8, 12, 10, 59, 50)
        )
        
        self.assertTrue( v )

        del store
        store = _pycms.X509Store()

        v = cms.verify(caStore=store , content=DEF_CONTENT, 
            notBefore = datetime.datetime( 2019, 8, 12, 10, 59, 50),
            notAfter = datetime.datetime( 2019, 8, 23, 23, 40, 10)
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
            notBefore = datetime.datetime( 2019, 8, 12, 10, 59, 50),
            notAfter = datetime.datetime( 2019, 8, 23, 23, 40, 10)
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
            notBefore = datetime.datetime( 2019, 8, 12, 10, 59, 50),
            notAfter = datetime.datetime( 2019, 8, 23, 23, 40, 10)
        ) )

        path = './tests/cms_rsa.pem'
        cms = _pycms.CMS.load( path )

        self.assertTrue( cms.verify(caStore=store , content=DEF_CONTENT, 
            notBefore = datetime.datetime( 2019, 8, 12, 10, 59, 50),
            notAfter = datetime.datetime( 2019, 8, 23, 23, 40, 10)
        ) )

        path = './tests/cms_2001.pem'
        cms = _pycms.CMS.load( path )

        self.assertTrue( cms.verify(caStore=store , content=DEF_CONTENT, 
            notBefore = datetime.datetime( 2019, 8, 12, 10, 59, 50),
            notAfter = datetime.datetime( 2019, 8, 23, 23, 40, 10)
        ) )     




if __name__ == '__main__':
    unittest.main()