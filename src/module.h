#include "common.h"
#include <time.h>

#define CHECK( e )      if(!(e)){ goto err; }

PyObject *raiseError(PyObject *ErrType, const char *message);
PyObject *raiseOsslError(void);

extern const char PEM_TYPE_CMS[];
extern const char PEM_TYPE_CERT[];
extern const char PEM_TYPE_CRL[];
extern const char PEM_TYPE_PKEY[];

typedef struct pycmsBuffer pycmsBuffer;
typedef struct pycmsError pycmsError;
typedef struct pycmsCMS pycmsCMS;
typedef struct pycmsX509 pycmsX509;
typedef struct pycmsX509Name pycmsX509Name;
typedef struct pycmsX509Store pycmsX509Store;
typedef struct pycmsEngine pycmsEngine;
typedef struct pycmsASN1 pycmsASN1;
typedef struct pycmsEVP pycmsEVP;

extern PyTypeObject pycmsPyTypeBuffer;
extern PyTypeObject pycmsPyTypeError;
extern PyTypeObject pycmsPyTypeCMS;
extern PyTypeObject pycmsPyTypeX509;
extern PyTypeObject pycmsPyTypeX509Name;
extern PyTypeObject pycmsPyTypeX509Store;
extern PyTypeObject pycmsPyTypeEngine;
extern PyTypeObject pycmsPyTypeASN1;
extern PyTypeObject pycmsPyTypeEVP;

struct pycmsBuffer {
    const char *ptr;
    uint32_t numCharacters;
    uint32_t size;
    PyObject *obj;
};

struct pycmsError {
    PyObject_HEAD
    long code;
    const char*  messages[];
};

struct pycmsCMS {
    PyObject_HEAD
    CMS_ContentInfo *ptr;
};

struct pycmsX509 {
    PyObject_HEAD
    X509 *ptr;
};

struct pycmsX509Name {
    PyObject_HEAD
    X509_NAME *ptr;
};

struct pycmsX509Store {
    PyObject_HEAD
    X509_STORE *ptr;
};

struct pycmsEngine {
    PyObject_HEAD
    ENGINE *ptr;
};

struct pycmsEVP {
    PyObject_HEAD
    EVP_PKEY *ptr;
};

struct pycmsASN1 {
    PyObject_HEAD
    const void* buff;
    Py_ssize_t  buff_len;
    const char* type;
};

pycmsEngine *ossl_init_engine(const char* engine_id);
pycmsX509 *ossl_X509_from_handle(X509* handle);
pycmsCMS *ossl_CMS_from_handle(CMS_ContentInfo* handle);
pycmsEVP *ossl_EVP_from_handle(EVP_PKEY *handle);
