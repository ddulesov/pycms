# How build GOST engine in Windows  

## Requirements
 * Git  [download](https://gitforwindows.org/)
 * cmake [download](https://cmake.org/download/)
 * OpenSSL for Windows 64bit [download](https://slproweb.com/products/Win32OpenSSL.html)
 * Microsoft Visual Studio 14.0 [download](https://www.microsoft.com/ru-ru/download/details.aspx?id=48159)

## download gost-engine source code 

```bat
git clone --depth 1  https://github.com/gost-engine/engine.git  .
```

## correct CMakeList.txt

add line
```
if (MSVC)
target_link_libraries(gost_engine ws2_32.lib)
endif()
```

## create *platform.h* file 

```c
# ifndef PATH_MAX
#  define PATH_MAX _MAX_PATH
# endif

#if defined(_MSC_VER)
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#endif


#ifdef WIN32
#include <winsock.h>
#include "getopt.h"
#include <io.h>

static int setenv(const char *name, const char *value, int overwrite)
{
    int errcode = 0;
    if(!overwrite) {
        size_t envsize = 0;
        errcode = getenv_s(&envsize, NULL, 0, name);
        if(errcode || envsize) return errcode;
    }
    return _putenv_s(name, value);
}

#  if (_MSC_VER >= 1310)
#   define open _open
#   define fdopen _fdopen
#   define close _close
#   ifndef strdup
#    define strdup _strdup
#   endif
#   define unlink _unlink
#   define fileno _fileno
#  endif

#else //linux osx

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
```

file gost_keyexpimp.c

replace 
```c
#include <arpa/inet.h>
```
with
```
#include "platform.h"
```

## create Visual Studio project and build  *gost.dll*

```bat
cmake -DCMAKE_GENERATOR_PLATFORM=x64 -DOPENSSL_ENGINES_DIR="C:\Program Files\OpenSSL-Win64\bin"  -B ./amd64

cd ./amd64

MSBuild.exe gost_engine.vcxproj /p:Configuration=Release /p:Platform="x64" 
```

## copy  *gost.dll* to OPENSSL_ENGINE directory

```bat
copy   ./bin/Release/gost.dll  %OPENSSL_ENGINES_DIR%
```

## test gost-engine

add to openssl.cfg

```
[openssl_def]
engines = engine_section

[engine_section]
gost = gost_section

[gost_section]
engine_id = gost
default_algorithms = ALL
CRYPT_PARAMS = id-Gost28147-89-CryptoPro-A-ParamSet
```

run 
```bat
openssl req  -engine gost -x509 -newkey gost2012_256 -pkeyopt paramset:A  -keyout keyGOST2012_256.pem  -out certGOST2012_256.pem -nodes -days 3650   -subj "/CN=localhost/OU=gost2012_256" 

openssl x509 -engine gost  -in certGOST2012_256.pem -noout -text 
```
