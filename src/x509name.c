#include "common.h"
#include "module.h"

static void pycms_free(pycmsX509Name *name)
{
    if (name->ptr) {
        //Use X509_NAME_dup( x ) in ossl_X509Name_from_handle
        //X509_NAME_free(name->ptr);
        name->ptr = NULL;
    }
    printf("pycms_free");
    Py_TYPE(name)->tp_free((PyObject*) name);
}

static PyGetSetDef pycmsMembers[] = {
    //{ "commonName", (getter) getCommonName, 0, 0, 0 },
    { NULL }
};

PyObject *X509_NAME_REPR(X509_NAME* ptr){
    char buf[512];
    char *str = X509_NAME_oneline(ptr, buf, sizeof(buf));
    
    if(str==NULL){
        return NULL;
    }

    PyObject *o = PyUnicode_FromString(buf);
    return o;
}

static PyObject *pycms_repr(pycmsX509Name *name){
    return X509_NAME_REPR(name->ptr);
}

PyTypeObject pycmsPyTypeX509Name = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "pycms.X509Name",                     // tp_name
    sizeof(pycmsX509Name),                // tp_basicsize
    0,                                  // tp_itemsize
    (destructor) pycms_free,            // tp_dealloc
    0,                                  // tp_print
    0,                                  // tp_getattr
    0,                                  // tp_setattr
    0,                                  // tp_compare
    (reprfunc) pycms_repr,               // tp_repr
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
    pycmsMembers,                       // tp_getset
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

pycmsX509Name *ossl_X509Name_from_handle(X509_NAME* handle){
    pycmsX509Name *o = NULL;
    printf("X509Name");
    CHECK(handle);

    o = (pycmsX509Name*) pycmsPyTypeX509Name.tp_alloc(&pycmsPyTypeX509Name, 0);
    CHECK(o);
    
    o->ptr = handle;
    return o;
err:
    if(handle!=NULL){
		X509_NAME_free(handle);
    }
    return NULL;
}


