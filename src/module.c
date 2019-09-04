#include "module.h"

PyObject* raiseOsslError(void);
PyObject* raiseError(PyObject *ErrType, const char *message);

PyObject *_engine(PyObject *self, PyObject *args){
    const char *id;
    if (!PyArg_ParseTuple(args, "s", &id))
        return NULL;


    pycmsEngine* e = ossl_init_engine(id);
    if( e==NULL){
        Py_RETURN_NONE;
    }else{
        return (PyObject*)( e );
    }
}

PyObject *_init_openssl(PyObject *self, PyObject *args){
    const char *conf;

    if (!PyArg_ParseTuple(args, "|s", &conf))
        return NULL;
    const char *ver = OpenSSL_version(OPENSSL_VERSION);

    ERR_load_crypto_strings();
    OPENSSL_load_builtin_modules();
    ENGINE_load_builtin_engines();
    
    //sts = system(command);
    return Py_BuildValue("s", ver);                            
    Py_RETURN_NONE;
}

PyObject* raiseOsslError(void){
    const char *ptr=NULL;
    //pycmsError *error;
    //error = pycmsError_newFromOpenSSL();
    BIO *out= BIO_new(BIO_s_mem());

    ERR_print_errors(out);
    
    /* old variant 
    unsigned long e = ERR_peek_last_error();
    if(e!=0){
        PyErr_SetString(OpenSSLError, ERR_reason_error_string(e));
    }
    */
    int len = BIO_get_mem_data(out, &ptr);
    BIO_write(out,"\0",1);
    PyErr_SetString(OpenSSLError, ptr );
    BIO_free(out);
    //Py_DECREF(error);
    return NULL;
}

PyObject* raiseError(PyObject *ErrType, const char *message){
    PyErr_SetString(ErrType, message);
    return NULL;
}

