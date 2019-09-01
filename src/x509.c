#include "common.h"
#include "module.h"

pycmsX509Name *ossl_X509Name_from_handle(X509_NAME* handle);
PyObject *X509_NAME_REPR(X509_NAME* ptr);

static void pycmsX509_free(pycmsX509 *x509)
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

    BIGNUM *pbn = ASN1_INTEGER_to_BN(serial, NULL);
    if(pbn==NULL)
        return NULL;

    char* str = BN_bn2hex(pbn);
    PyObject *o=PyBytes_FromString(str);
    BN_free(pbn);
    OPENSSL_free(str);
    return o;
}

static PyObject *getSubject(pycmsX509 *x509, void *unused){
    X509_NAME *handle = X509_get_subject_name(x509->ptr);
    //return ossl_X509Name_from_handle(  handle);
    return X509_NAME_REPR( handle );        
}

static PyObject *getIssuer(pycmsX509 *x509, void *unused){
    X509_NAME *handle = X509_get_issuer_name(x509->ptr);
    return X509_NAME_REPR( handle );
    //return ossl_X509Name_from_handle(handle);        
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

static PyObject *x509_repr(pycmsX509 *x509)
{
    BIO *out=NULL;
    char *ptr = NULL;
    PyObject* o=NULL;
    if(x509->ptr == NULL)
        return NULL;

    //_PyBytesWriter  wrt;
    //_PyBytesWriter_Init(&wrt);    

    //s = _PyBytesWriter_Alloc(&wrt,4096);
    out= BIO_new(BIO_s_mem());
    
    //BIO_set_callback_arg(out, &wrt);
    //BIO_set_callback(out, BIO_Buff_callback);
    
    X509_print(out, x509->ptr);
    
    BIO_flush(out);
    int len = BIO_get_mem_data(out, &ptr);
    if(len>0 && ptr!=NULL)
        o = PyUnicode_FromStringAndSize(ptr, len);
        //o = PyBytes_FromStringAndSize(ptr, len);
    BIO_free(out);

    return o;
    //return _PyBytesWriter_Finish(&wrt, s);
}

static PyGetSetDef pycmsX509Members[] = {
    { "serialNumber", (getter) getSerialNumber, 0, 0, 0 },
   // { "subject", (getter) getSubject, 0, 0, 0 },
    //{ "issuer", (getter) getIssuer, 0, 0, 0 },
    { "notBefore", (getter) getNotBefore, 0, 0, 0 },
    { "notAfter", (getter) getNotAfter, 0, 0, 0 },
    { "subject", (getter) getSubject, 0, 0, 0 },
    { "issuer", (getter) getIssuer, 0, 0, 0 },
    { NULL }
};

PyTypeObject pycmsPyTypeX509 = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "pycms.X509",                     // tp_name
    sizeof(pycmsX509),                // tp_basicsize
    0,                                  // tp_itemsize
    (destructor) pycmsX509_free,            // tp_dealloc
    0,                                  // tp_print
    0,                                  // tp_getattr
    0,                                  // tp_setattr
    0,                                  // tp_compare
    (reprfunc) x509_repr,               // tp_repr
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
    pycmsX509Members,                   // tp_getset
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

pycmsX509 *ossl_X509_from_handle(X509* handle){
    pycmsX509 *o = NULL;
    CHECK(handle);

    o = (pycmsX509*) pycmsPyTypeX509.tp_alloc(&pycmsPyTypeX509, 0);
    CHECK(o);

    o->ptr = handle;
    return o;
err:
    if(handle!=NULL){
		X509_free(handle);
    }
    return NULL;
}

/* STORE */
static void pycmsX509Store_free(pycmsX509Store *x509s)
{
    if (x509s->ptr) {
        X509_STORE_free(x509s->ptr);
        x509s->ptr = NULL;
    }
    Py_TYPE(x509s)->tp_free((PyObject*) x509s);
}

static PyObject *x509Store_new(PyTypeObject *type, PyObject *args,
        PyObject *keywordArgs)
{
    return type->tp_alloc(type, 0);
}

static int x509Store_init(pycmsX509Store *x509s, PyObject *args,
        PyObject *keywordArgs)
{
    printf("x509Store init");
    x509s->ptr = X509_STORE_new();
    if(x509s->ptr==NULL)
        return -1;
    return 0;
}

static PyObject *x509Store_Add(pycmsX509Store *x509s, PyObject *args){
    PyObject *x509Obj  = NULL;

    if (!PyArg_ParseTuple(args, "O", &x509Obj))
        return NULL;

    if(x509Obj==NULL ||  Py_TYPE(x509Obj)!= &pycmsPyTypeX509){
        return raiseError(PyExc_RuntimeError, "not a X509 object");
    }
    CHECK( X509_STORE_add_cert(x509s->ptr, ((pycmsX509 *)x509Obj)->ptr) );

    Py_RETURN_NONE;

err:
    return NULL;
}


static PyObject *x509Store_Verify(pycmsX509Store *x509s, PyObject *args){
    PyObject *x509Obj  = NULL;
    X509_STORE_CTX *csc = NULL;
    X509* x=NULL;
    int i = -1;
    unsigned long vflags = 0 ;

    if (!PyArg_ParseTuple(args, "O", &x509Obj))
        return NULL;

    if(x509Obj==NULL ||  Py_TYPE(x509Obj)!= &pycmsPyTypeX509){
        return raiseError(PyExc_RuntimeError, "not a X509 object");
    }
    x = ((pycmsX509 *)x509Obj)->ptr;
    if(x==NULL)
        return NULL;

    csc = X509_STORE_CTX_new();
    if(csc==NULL)
        return NULL;

    X509_STORE_set_flags(x509s->ptr, vflags);

    if (!X509_STORE_CTX_init(csc, x509s->ptr, x, NULL)){
        goto err;
    }

    i = X509_verify_cert(csc);
    if (i > 0 && X509_STORE_CTX_get_error(csc) == X509_V_OK) {

    }else{
        i=0;
    }
    
err:
    X509_STORE_CTX_free(csc);

    if(i<0)
        return NULL;
    if(i==0)
        Py_RETURN_FALSE;

    Py_RETURN_TRUE;
}

static PyMethodDef x509StoreMethods[] = {
    { "add", (PyCFunction) x509Store_Add, METH_VARARGS  },
    { "verify", (PyCFunction) x509Store_Verify, METH_VARARGS  },
    { NULL }
};



PyTypeObject pycmsPyTypeX509Store = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "pycms.X509Store",                  // tp_name
    sizeof(pycmsX509Store),             // tp_basicsize
    0,                                  // tp_itemsize
    (destructor) pycmsX509Store_free,   // tp_dealloc
    0,                                  // tp_print
    0,                                  // tp_getattr
    0,                                  // tp_setattr
    0,                                  // tp_compare
    0,                                  // tp_repr
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
    x509StoreMethods,                                  // tp_methods
    0,                                  // tp_members
    0,                                  // tp_getset
    0,                                  // tp_base
    0,                                  // tp_dict
    0,                                  // tp_descr_get
    0,                                  // tp_descr_set
    0,                                  // tp_dictoffset
    (initproc) x509Store_init,          // tp_init
    0,                                  // tp_alloc
    (newfunc) x509Store_new,            // tp_new
    0,                                  // tp_free
    0,                                  // tp_is_gc
    0                                   // tp_bases
};

