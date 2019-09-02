#include "common.h"
#include "module.h"

pycmsX509Name *ossl_X509Name_from_handle(X509_NAME* handle);
PyObject *X509_NAME_REPR(X509_NAME* ptr);

static void pycms_free(pycmsX509 *x509)
{
    if (x509->ptr) {
        X509_free(x509->ptr);
        x509->ptr = NULL;
    }
    Py_TYPE(x509)->tp_free((PyObject*) x509);
}

static PyObject *getSerialNumber(pycmsX509 *x509, void *unused){
    ASN1_INTEGER *serial;
    
    serial =  X509_get_serialNumber(x509->ptr);
    if(serial==NULL)
        return NULL;

    return _PyLong_FromByteArray( serial->data, serial->length, 0, 0);
}
//incomplete implementation
static PyObject *getPubKey(pycmsX509 *x509, void *unused){
    //EVP_PKEY *key = X509_get_pubkey(x509->ptr);
    //X509_PUBKEY *key= X509_get_X509_PUBKEY(x509->ptr);

    return NULL;
}

static PyObject *getSubject(pycmsX509 *x509, void *unused){
    X509_NAME *handle = X509_get_subject_name(x509->ptr);
    return X509_NAME_REPR( handle );        
}

static PyObject *getIssuer(pycmsX509 *x509, void *unused){
    X509_NAME *handle = X509_get_issuer_name(x509->ptr);
    return X509_NAME_REPR( handle );       
}

static PyObject *getNotBefore(pycmsX509 *x509, void *unused){
    struct tm t;
    const ASN1_TIME *time=X509_get0_notBefore(x509->ptr);
    ASN1_TIME_to_tm(time, &t);
    return fromTimeStruct(&t);  
}

static PyObject *getNotAfter(pycmsX509 *x509, void *unused){
    struct tm t;
    const ASN1_TIME *time=X509_get0_notAfter(x509->ptr);
    ASN1_TIME_to_tm(time, &t);
    return fromTimeStruct(&t);     
}

static PyObject *pycms_repr(pycmsX509 *x509)
{
    BIO *out=NULL;
    char *ptr = NULL;
    PyObject* o=NULL;
    if(x509->ptr == NULL)
        return NULL;

    out= BIO_new(BIO_s_mem());
    
    X509_print(out, x509->ptr);
    
    BIO_flush(out);
    int len = BIO_get_mem_data(out, &ptr);
    if(len>0 && ptr!=NULL)
        o = PyUnicode_FromStringAndSize(ptr, len);
        //o = PyBytes_FromStringAndSize(ptr, len);
    BIO_free(out);

    return o;
}

static PyGetSetDef pycms_members[] = {
    { "serialNumber", (getter) getSerialNumber, 0, 0, 0 },
    { "notBefore", (getter) getNotBefore, 0, 0, 0 },
    { "notAfter", (getter) getNotAfter, 0, 0, 0 },
    { "subject", (getter) getSubject, 0, 0, 0 },
    { "issuer", (getter) getIssuer, 0, 0, 0 },
    { NULL }
};

PyTypeObject pycmsPyTypeX509 = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "pycms.X509",                       // tp_name
    sizeof(pycmsX509),                  // tp_basicsize
    0,                                  // tp_itemsize
    (destructor) pycms_free,            // tp_dealloc
    0,                                  // tp_print
    0,                                  // tp_getattr
    0,                                  // tp_setattr
    0,                                  // tp_compare
    (reprfunc) pycms_repr,              // tp_repr
    0,                                  // tp_as_number
    0,                                  // tp_as_sequence
    0,                                  // tp_as_mapping
    0,                                  // tp_hash
    0,                                  // tp_call
    0,                                  // tp_str
    0,                                  // tp_getattro
    0,                                  // tp_setattro
    0,                                  // tp_as_buffer
    Py_TPFLAGS_DEFAULT,                 // tp_flags
    0,                                  // tp_doc
    0,                                  // tp_traverse
    0,                                  // tp_clear
    0,                                  // tp_richcompare
    0,                                  // tp_weaklistoffset
    0,                                  // tp_iter
    0,                                  // tp_iternext
    0,                                  // tp_methods
    0,                                  // tp_members
    pycms_members,                      // tp_getset
    0,                                  // tp_base
    0,                                  // tp_dict
    0,                                  // tp_descr_get
    0,                                  // tp_descr_set
    0,                                  // tp_dictoffset
    0,                                  // tp_init
    0,                                  // tp_alloc
    0,                                  // tp_new
    0,                                  // tp_free
    0,                                  // tp_is_gc
    0                                   // tp_bases
};




