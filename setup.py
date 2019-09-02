from distutils.core import setup, Extension

module1 = Extension('_pycms',
                    define_macros = [('MAJOR_VERSION', '1'),
                                     ('MINOR_VERSION', '0')],
                    include_dirs = ['C:/Program Files/OpenSSL-Win64/include'],
                    libraries = ['libcrypto64MD'],
                    library_dirs = ['C:/Program Files/OpenSSL-Win64/lib/VC'],
                    sources = ['src/pycms.c',
                     'src/ossl.c',
                     'src/engine.c', 
                     'src/cms.c', 
                     'src/x509.c', 
                     'src/x509store.c',
                     'src/x509name.c',
                     'src/module.c' 
                     ])

                                       	
setup (name = 'PyCMS',
       version = '0.1.0',
       description = 'verify Cryptographic Message Syntax SignerInfo with GOST cryptography support',
       ext_modules = [module1])