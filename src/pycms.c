#include "common.h"
#include "module.h"
#include <datetime.h>

static PyObject *FormatError;
static PyObject *ValidateError;

PyObject *Empty;

const char *_empty = "";
#define PYCMSDOC  "pycms verify CMS signerinto message using openssl GOST engine"

const char *PEM_TYPE_CMS = "CMS";
const char *PEM_TYPE_CERT = "CERTIFICATE";
const char *PEM_TYPE_CRL = "CRL";
const char *PEM_TYPE_PKEY = "PRIVATE KEY";

ASN1_OBJECT *OidSigningTime;

PyObject *CMS_from_file(PyObject *self, PyObject *args);
PyObject *x509_from_file(PyObject *self, PyObject *args);
PyObject *engine_by_id(PyObject *self, PyObject *args);
PyObject *init_openssl(PyObject *self, PyObject *args);

int isDateTime(PyObject* obj){
    if(obj==NULL) return 0;
    return PyDateTime_CheckExact(obj);
}

PyObject* fromTimeStruct(struct tm *t){
    return PyDateTime_FromDateAndTime(t->tm_year+1900, t->tm_mon+1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec, 0);
}

time_t getDateTimeStamp(PyObject *datetime){
    struct tm   t= {0};
    PyDateTime_DateTime *dt;
    if(datetime!=NULL){
        // YY[0-1] mm[2] dd[3] HH[4] MM[5] SS[6] mS[7-9] 
        dt = (PyDateTime_DateTime*)(datetime); 
        
        /* for (int i = 0; i < _PyDateTime_DATETIME_DATASIZE; i++)
        {
            printf("%02i ", dt->data[i] );
        }
        printf("\n"); */
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

static PyMethodDef pycms_methods[] = {
    { "init",  init_openssl, METH_VARARGS, "Init openssl." },
    //{ "pem2der", pem2der, METH_VARARGS, "pem decode." },
    { "x509_from_file", x509_from_file, METH_VARARGS, "load x509 certificate from file." },
    { "CMS_from_file", CMS_from_file, METH_VARARGS, "load CMS  from file." },
    { "engine_by_id", engine_by_id, METH_VARARGS, "open dso engine." },
    { NULL, NULL, 0, NULL }        /* Sentinel */
};

static struct PyModuleDef pycms_module = {
    PyModuleDef_HEAD_INIT,
    "_pycms",   /* name of module */
    PYCMSDOC, /* module documentation, may be NULL */
    -1,       /* size of per-interpreter state of the module,
                 or -1 if the module keeps state in global variables. */
    pycms_methods
};

PyMODINIT_FUNC PyInit__pycms(void){
    PyObject *m;
    //PyMem_SetupDebugHooks();
    OidSigningTime = OBJ_nid2obj(NID_pkcs9_signingTime);
    
    m = PyModule_Create(&pycms_module);
    if (m == NULL)
        return NULL;

    //initialize DateTime CAPI
    PyDateTime_IMPORT;
    if(PyDateTimeAPI==NULL){
        return NULL;
    }

    Empty = PyBytes_FromStringAndSize(_empty, 0 );

    //Exception Types
    PYCMS_ADD_TYPE_OBJECT("FormatError",  PyErr_NewException("pycms.format.error", NULL, NULL) );
    PYCMS_ADD_TYPE_OBJECT("ValidateError",  PyErr_NewException("pycms.validate.error", NULL, NULL) );
    //OpenSSL Types
    PYCMS_MAKE_TYPE_READY(&pycmsPyTypeEngine);
    PYCMS_MAKE_TYPE_READY(&pycmsPyTypeX509);
    PYCMS_MAKE_TYPE_READY(&pycmsPyTypeX509Name);
    PYCMS_MAKE_TYPE_READY(&pycmsPyTypeX509Store);
    PYCMS_MAKE_TYPE_READY(&pycmsPyTypeCMS);

    PYCMS_ADD_TYPE_OBJECT("X509Store", &pycmsPyTypeX509Store);
    PYCMS_ADD_TYPE_OBJECT("X509", &pycmsPyTypeX509);
    return m;	
}