from distutils.core import setup, Extension
from distutils.util import get_platform
from distutils.ccompiler import get_default_compiler
import sys
import os

include_dirs = []
library_dirs = []
libraries = []

#if sys.version_info.major!=3:
#	raise "require Python 3.6 at least"

def isOpenSSLDir( p ):
       ossl = os.path.join( p, 'openssl.exe')
       return os.path.isfile(ossl)

def genDirs():
       env = os.environ
       for k in env.keys():
              if k.startswith("OPENSSL") and isOpenSSLDir( env[k] ):
                     yield env[k]

       for p in env['PATH'].split(os.pathsep):
              if isOpenSSLDir(p):
                     yield p
       
       p = env.get('ProgramFiles')
       if p is None:
              return
       
       for k in ['OpenSSL', 'OpenSSL-Win64']:
              k = os.path.join( p, k )
              if isOpenSSLDir(k):
                     yield k


if sys.platform in ('linux', 'linux2'):
       libraries.append("crypto")
else:
       compiler = get_default_compiler()

       if get_platform()=="win-amd64":
              libraries.append("libcrypto64MD")
       else:
              libraries.append("libcryptoMD")

       OPENSSL_ROOT=None
       #find OPENSSL directory
       paths = []

       for path in genDirs():
              found = False
              bname = os.path.basename( path )
              if bname=='bin':
                     found = isOpenSSLDir( path )
                     path = os.path.abspath(os.path.join(path, '..' ))
              
              if not found:
                     found = isOpenSSLDir( path )
                     continue
              
              if  os.path.exists( os.path.join(path,'include') ) and os.path.exists( os.path.join(path,'lib') ):
                     OPENSSL_ROOT = path
                     break
              
       
       if OPENSSL_ROOT is None:
              raise "OpenSSL dir not found. set OPENSSL environment variable to openssl.exe "

       
       include_dirs.append( os.path.join( OPENSSL_ROOT, "include"))
       if compiler=="msvc":
              libpath = os.path.join(OPENSSL_ROOT, "lib\\VC")
       else:
              libpath = os.path.join(OPENSSL_ROOT, "lib")

       library_dirs.append( libpath )


       print("openSSL library dir:", libpath )

module_ex = Extension('_pycms',
                    include_dirs = include_dirs,
                    libraries = libraries,
                    library_dirs = library_dirs,
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
       version = '0.1.4',
       description = 'verify Cryptographic Message Syntax SignerInfo with GOST cryptography support',
       ext_modules = [module_ex])
