#ifndef _COMMON_H
#define _COMMON_H

#include <Python.h>
#include <limits.h>
#include <openssl/ossl_typ.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/cms.h>

#include <openssl/asn1.h>
#include <openssl/conf.h>

PyObject *raiseError(PyObject *ErrType, const char *message);
//datetime CAPI functions
int isDateTime(PyObject* obj);
time_t getDateTimeStamp(PyObject *datetime);
PyObject* fromTimeStruct(struct tm *t);


#ifdef TIME_MAX
#define MAX_TIME_T          TIME_MAX
#else
#define MAX_TIME_T          0x793406fff
#endif
extern PyObject *Empty;

#define PY_RETURN_EMPTY  return Py_INCREF( Empty), Empty 

#define PY_RETURN_BUF(ptr, len)  return PyBytes_FromStringAndSize(ptr, len);

#if PY_MAJOR_VERSION > 2
#define   RET_MODULE	return NULL
#else
#define   RET_MODULE    return	
#endif
// define macro for adding integer constants
#define PYCMS_ADD_INT_CONSTANT(name, value) \
    if (PyModule_AddIntConstant(m, name, value) < 0) \
        RET_MODULE;

// define macro for adding type objects
#define PYCMS_ADD_TYPE_OBJECT(name, type) \
    Py_INCREF(type); \
    if (PyModule_AddObject(m, name, (PyObject*) type) < 0) \
        RET_MODULE;

// define macro for and making types ready
#define PYCMS_MAKE_TYPE_READY(type) \
    if (PyType_Ready(type) < 0) \
        RET_MODULE;

/*
typedef struct Py_BIO_BUF {
    void            *ptr;
    _PyBytesWriter  writer;
}Py_BIO_BUF;
*/
#endif
