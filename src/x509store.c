#include "module.h"

static void pycms_free(pycmsX509Store *x509s)
{
    if (x509s->ptr) {
        X509_STORE_free(x509s->ptr);
        x509s->ptr = NULL;
    }
    Py_TYPE(x509s)->tp_free((PyObject*) x509s);
}

static PyObject *pycms_new(PyTypeObject *type, PyObject *args,
        PyObject *keywordArgs)
{
    return type->tp_alloc(type, 0);
}

static int pycms_init(pycmsX509Store *x509s, PyObject *args,
        PyObject *keywordArgs)
{
    
    x509s->ptr = X509_STORE_new();
    if(x509s->ptr==NULL)
        return -1;
    return 0;
}

static PyObject *_Add(pycmsX509Store *x509s, PyObject *args){
    PyObject *x509Obj  = NULL;

    if (!PyArg_ParseTuple(args, "O", &x509Obj))
        return NULL;

    if(x509Obj==NULL ||  Py_TYPE(x509Obj)!= &pycmsPyTypeX509){
        return raiseError(VerifyError, "not a X509 object");
    }
    CHECK( X509_STORE_add_cert(x509s->ptr, ((pycmsX509 *)x509Obj)->ptr) );

    Py_RETURN_NONE;

err:
    return NULL;
}


static PyObject *_Verify(pycmsX509Store *x509s, PyObject *args){
    PyObject *x509Obj  = NULL;
    X509_STORE_CTX *csc = NULL;
    X509* x=NULL;
    int i = -1;
    unsigned long vflags = 0 ;

    if (!PyArg_ParseTuple(args, "O", &x509Obj))
        return NULL;

    if(x509Obj==NULL ||  Py_TYPE(x509Obj)!= &pycmsPyTypeX509){
        return raiseError(VerifyError, "not a X509 object");
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

static PyObject *_Load(pycmsX509Store *x509s, PyObject *args,  PyObject *keywordArgs){
    static char *keywordList[] = { "file", "path", NULL };
    const char *file, *path;

    file=NULL;
    path=NULL;
    
    if (x509s==NULL){
        return NULL;
    }

    if (!PyArg_ParseTupleAndKeywords(args, keywordArgs, "|ss",
            keywordList, &file, &path)){

        return NULL;
    }
    /*
    if(file==NULL && dir==NULL){
        return raiseError(PyExc_RuntimeError, "require 'dir' or 'file' parameters ");
    }
    */

    if( X509_STORE_load_locations(x509s->ptr, file, path) < 1 ){
        return raiseOsslError();
    }

    Py_RETURN_NONE;
}

static PyMethodDef pycms_methods[] = {
    { "add", (PyCFunction) _Add, METH_VARARGS  },
    { "verify", (PyCFunction) _Verify, METH_VARARGS  },
    { "load", (PyCFunction) _Load, METH_VARARGS | METH_KEYWORDS  },
    { NULL }
};

PyTypeObject pycmsPyTypeX509Store = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "_pycms.X509Store",                  // tp_name
    sizeof(pycmsX509Store),             // tp_basicsize
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
    pycms_methods,                      // tp_methods
    0,                                  // tp_members
    0,                                  // tp_getset
    0,                                  // tp_base
    0,                                  // tp_dict
    0,                                  // tp_descr_get
    0,                                  // tp_descr_set
    0,                                  // tp_dictoffset
    (initproc) pycms_init,          // tp_init
    0,                                  // tp_alloc
    (newfunc) pycms_new,            // tp_new
    0,                                  // tp_free
    0,                                  // tp_is_gc
    0                                   // tp_bases
};


