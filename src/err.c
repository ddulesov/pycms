#include "common.h"

/*
static void pycmsError_free(pycmsError *error);
static PyObject *pycmsError_str(pycmsError *error);
static PyObject *pycmsError_new(PyTypeObject *type, PyObject *args, PyObject *keywordArgs);
static PyObject *pycmsError_reduce(pycmsError*);


static PyMethodDef cxoErrorMethods[] = {
    { "__reduce__", (PyCFunction) pycmsError_reduce, METH_NOARGS },
    { NULL, NULL }
};


static PyMemberDef pycmsErrorMembers[] = {
    { "message", T_OBJECT, offsetof(pycmsError, message), READONLY },

    { NULL }
};

//-----------------------------------------------------------------------------
// declaration of Python type
//-----------------------------------------------------------------------------
PyTypeObject pycmsPyTypeError = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "pycms._Error",                 // tp_name
    sizeof(pycmsError),                   // tp_basicsize
    0,                                  // tp_itemsize
    (destructor) pycmsError_free,         // tp_dealloc
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
    (reprfunc) pycmsError_str,            // tp_str
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
    pycmsErrorMethods,                    // tp_methods
    pycmsErrorMembers,                    // tp_members
    0,                                  // tp_getset
    0,                                  // tp_base
    0,                                  // tp_dict
    0,                                  // tp_descr_get
    0,                                  // tp_descr_set
    0,                                  // tp_dictoffset
    0,                                  // tp_init
    0,                                  // tp_alloc
    pycmsError_new,                       // tp_new
    0,                                  // tp_free
    0,                                  // tp_is_gc
    0                                   // tp_bases
};


//-----------------------------------------------------------------------------
//   pycmsError_free()
//   Deallocate the error.
//-----------------------------------------------------------------------------
static void pycmsError_free(pycmsError *error)
{
    Py_CLEAR(error->message);
    PyObject_Del(error);
}

static PyObject *pycmsError_new(PyTypeObject *type, PyObject *args,
        PyObject *keywordArgs)
{
    PyObject *message, *context;
    int isRecoverable, code;
    pycmsError *error;
    unsigned offset;

    isRecoverable = 0;
    if (!PyArg_ParseTuple(args, "OiIO|i", &message, &code, &offset, &context,
            &isRecoverable))
        return NULL;

    error = (cxoError*) type->tp_alloc(type, 0);
    if (!error)
        return NULL;

    error->code = code;
    error->offset = offset;
    error->isRecoverable = (char) isRecoverable;
    Py_INCREF(message);
    error->message = message;
    Py_INCREF(context);
    error->context = context;

    return (PyObject*) error;
}




static int append_error_string_cb(const char *str, size_t len, void *bp)
{
    pycmsError *error = (pycmsError *)bp ;
}


pycmsError *pycmsError_newFromOpenSSL(){
    
    pycmsError *error;
    error = (pycmsError*) pycmsPyTypeError.tp_alloc(&pycmsPyTypeError, 0);
    if (!error)
        return NULL;

    ERR_print_errors_cb(append_error_string_cb, error);
    return error;
}
*/