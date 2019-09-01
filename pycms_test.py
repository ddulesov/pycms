import unittest
import _pycms

class TestModuleMethods(unittest.TestCase):
 
    def test_isupper(self):
        self.assertTrue('FOO'.isupper())
        self.assertFalse('Foo'.isupper())
        self.assertEqual('foo'.upper(), 'FOO')



if __name__ == '__main__':
    print("run _pycms tests")
    unittest.main()