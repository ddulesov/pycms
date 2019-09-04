#include "common.h"
#include "module.h"
#include <datetime.h>

PyObject *VerifyError;
PyObject *OpenSSLError;
PyObject *Empty;

static const char PROJECT_NAME[] = "_pycms";
static const char _empty[] = "";
static const char PYCMSDOC[] = "verify CMS signerinto message using openssl GOST engine";

/*
const char PEM_TYPE_CMS[] = "CMS";
const char PEM_TYPE_CERT[] = "CERTIFICATE";
const char PEM_TYPE_CRL[] = "CRL";
const char PEM_TYPE_PKEY[] = "PRIVATE KEY";
*/
ASN1_OBJECT *OidSigningTime;

PyObject *CMS_from_file(PyObject *self, PyObject *args);
PyObject *x509_from_file(PyObject *self, PyObject *args);
PyObject *_engine(PyObject *self, PyObject *args);
PyObject *_init_openssl(PyObject *self, PyObject *args);

// is obj P
int isDateTime(PyObject* obj){
    if(obj==NULL) return 0;
    return PyDateTime_CheckExact(obj);
}

#ifdef PyDateTime_TimeZone_UTC
#define UTC_TimeZone  PyDateTime_TimeZone_UTC
#else
#define UTC_TimeZone  Py_None
#endif

// convert struct tm to PY::datetime object
PyObject* DateTime_from_tm(struct tm *t){
    //PyDateTime_DateTime  *datetime = (PyDateTime_DateTime  *)PyDateTime_FromDateAndTime(t->tm_year+1900, t->tm_mon+1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec, 0);
    PyObject* res = PyDateTimeAPI->DateTime_FromDateAndTime( t->tm_year+1900, t->tm_mon+1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec, 0, 
        UTC_TimeZone,  PyDateTimeAPI->DateTimeType);

    return res;
}

//convert PY:datetime to struct tm in UTC
int DateTime_to_tm(PyObject *datetime, struct tm *t){
    PyDateTime_DateTime *dt = (PyDateTime_DateTime *)datetime;

    if(datetime==NULL)
        return -1;
    
    t->tm_hour = dt->data[4];
    t->tm_min = dt->data[5];
    t->tm_sec = dt->data[6];
    t->tm_mday = dt->data[3];
    t->tm_mon = dt->data[2]-1;

    t->tm_year = ((dt->data[0]<<8) | dt->data[1] ) - 1900;
    return 0;
}

// convert PY::datetime object to time_t
/*
time_t getDateTimeStamp(PyObject *datetime){
    struct tm   t= {0};
    PyDateTime_DateTime *dt;
    if(datetime!=NULL){
        // YY[0-1] mm[2] dd[3] HH[4] MM[5] SS[6] mS[7-9] 
        dt = (PyDateTime_DateTime*)(datetime); 
        printf("datetime:");
        for (int i = 0; i < _PyDateTime_DATETIME_DATASIZE; i++)
        {
            printf("%02i ", dt->data[i] );
        }
        printf("\n"); 
        t.tm_hour = dt->data[4];
        t.tm_min = dt->data[5];
        t.tm_sec = dt->data[6];
        t.tm_mday = dt->data[3];
        t.tm_mon = dt->data[2]-1;

        t.tm_year = ((dt->data[0]<<8) | dt->data[1] ) - 1900;
        return mktime(&t);
    }
    return (time_t)0;
}
*/
// module own method definitions
static PyMethodDef pycms_methods[] = {
    { "init",  _init_openssl, METH_VARARGS, "Init openssl." },
    { "engine", _engine, METH_VARARGS, "open dso engine." },
    { NULL, NULL, 0, NULL }        /* Sentinel */
};

#if PY_MAJOR_VERSION > 2
//clear module 
/*
static int pycms_clear(PyObject *m)
{
    printf("pycms_clear");
    return 0;
}
*/

static struct PyModuleDef pycms_module = {
    PyModuleDef_HEAD_INIT,
    PROJECT_NAME,   /* name of module */
    PYCMSDOC, /* module documentation, may be NULL */
    -1,       /* size of per-interpreter state of the module,
                 or -1 if the module keeps state in global variables. */
    pycms_methods,
    /*
    0,  
    0,  
    pycms_clear,
    0, 
    */
};
#define  INIT_FUNCTION_NAME PyInit__pycms( void )
#else
#define  INIT_FUNCTION_NAME	init_pycms( void )
#endif

PyMODINIT_FUNC INIT_FUNCTION_NAME{
    PyObject *m;
    //PyMem_SetupDebugHooks();
    OidSigningTime = OBJ_nid2obj(NID_pkcs9_signingTime);
    
#if PY_MAJOR_VERSION > 2    
    m = PyModule_Create(&pycms_module);
#else
    m = Py_InitModule(PROJECT_NAME, pycms_methods);
#endif
    if (m == NULL){ RET_MODULE; }

    //initialize DateTime CAPI
    PyDateTime_IMPORT;
    if(PyDateTimeAPI==NULL){
        RET_MODULE;
    }

    Empty = PyBytes_FromStringAndSize(_empty, 0 );

    //Exception Types
    VerifyError = PyErr_NewException("_pycms.verify.error", NULL, NULL);
    OpenSSLError = PyErr_NewException("_pycms.openssl.error", NULL, NULL);
    PYCMS_ADD_TYPE_OBJECT("VerifyError",  VerifyError );
    PYCMS_ADD_TYPE_OBJECT("OpenSSLError",  OpenSSLError );
    //OpenSSL Types
    PYCMS_MAKE_TYPE_READY(&pycmsPyTypeEngine);
    PYCMS_MAKE_TYPE_READY(&pycmsPyTypeX509);
    PYCMS_MAKE_TYPE_READY(&pycmsPyTypeX509Name);
    PYCMS_MAKE_TYPE_READY(&pycmsPyTypeX509Store);
    PYCMS_MAKE_TYPE_READY(&pycmsPyTypeCMS);
    PYCMS_MAKE_TYPE_READY(&pycmsPyTypeEVP);
    //OpenSSL module Types
    PYCMS_ADD_TYPE_OBJECT("X509Store", &pycmsPyTypeX509Store);
    PYCMS_ADD_TYPE_OBJECT("X509", &pycmsPyTypeX509);
    PYCMS_ADD_TYPE_OBJECT("CMS", &pycmsPyTypeCMS);
    PYCMS_ADD_TYPE_OBJECT("EVP", &pycmsPyTypeEVP);

#if PY_MAJOR_VERSION > 2    
    return m;	
#endif
}
