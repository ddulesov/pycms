#include "module.h"

static PyObject *_Load(PyObject *_null, PyObject *args);

static void pycms_free(pycmsEVP *evp)
{
    if (evp->ptr) {
		EVP_PKEY_free(evp->ptr);
        evp->ptr = NULL;
    }
    Py_TYPE(evp)->tp_free((PyObject*) evp);
}

static PyMethodDef pycms_methods[] = {
    { "load", (PyCFunction) _Load, METH_VARARGS | METH_STATIC , "load private key  from file in PEM format" },
    { NULL }
};

PyTypeObject pycmsPyTypeEVP = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "pycms.EVP",                        // tp_name
    sizeof(pycmsEVP),                   // tp_basicsize
    0,                                  // tp_itemsize
    (destructor) pycms_free,            // tp_dealloc
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
    pycms_methods,                       // tp_methods
    0,                                  // tp_members
    0,                                  // tp_getset
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

struct  pwd {
    const char *password;
    int passwordLen;
};

int wrap_password_callback(char *buf, int bufsiz, int verify, void *userdata)
{

    struct pwd *p = (struct pwd *) userdata;
    if(p==NULL || p->password == NULL || p->passwordLen==0 || p->passwordLen > bufsiz)
        return -1;
    
    memmove(buf, p->password, p->passwordLen + 1);
    return p->passwordLen;
}



static PyObject *_Load(PyObject *_null, PyObject *args){
    const char *filename=NULL;
    struct pwd   password;
    BIO  *pem_bio = NULL;
    EVP_PKEY *evp=NULL;

    password.passwordLen = 0 ;

    if (!PyArg_ParseTuple(args, "s|s#", &filename, &(password.password) , &(password.passwordLen) ))
        return NULL;

    pem_bio = BIO_new_file(filename, "r");
    if( pem_bio == NULL ){
        return raiseOsslError();
    }

    //asn1 format
    //pkey = d2i_PrivateKey_bio(pem_bio, NULL);
    //pkcs12
    //if (!load_pkcs12(pem_bio, key_descrip, wrap_password_callback, &cb_data,
    //                     &pkey, NULL, NULL))
        
    evp = PEM_read_bio_PrivateKey(pem_bio, NULL, wrap_password_callback, (void*)&password );
    BIO_free(pem_bio);
    pem_bio = NULL;

    if (evp==NULL){
        return raiseOsslError();
    } 
     
    return (PyObject*) ossl_EVP_from_handle( evp ); 
}