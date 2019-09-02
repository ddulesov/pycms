#include "module.h"

PyObject* raiseOsslError(void);
PyObject* raiseError(PyObject *ErrType, const char *message);

PyObject *CMS_from_file(PyObject *self, PyObject *args){
    CMS_ContentInfo *cms = NULL;
    const char *filename;
    BIO  *pem_bio = NULL;
    
    if (!PyArg_ParseTuple(args, "s", &filename))
        return NULL;

    pem_bio = BIO_new_file(filename, "r");
    if( pem_bio == NULL ){
        return raiseOsslError();
    }

    cms = PEM_read_bio_CMS(pem_bio, NULL, 0, NULL);
    
    BIO_free(pem_bio);
    pem_bio = NULL;

    if (cms==NULL){
        return raiseOsslError();
    } 

    pycmsCMS *o=ossl_CMS_from_handle( cms );
    return (PyObject*)o;

//err:
//    BIO_free(pem_bio);    
}

PyObject *x509_from_file(PyObject *self, PyObject *args){
    const char *filename;
    BIO  *pem_bio = NULL;
    X509 *cacert=NULL;

    if (!PyArg_ParseTuple(args, "s", &filename))
        return NULL;

    pem_bio = BIO_new_file(filename, "r");
    if( pem_bio == NULL ){
        return raiseOsslError();
    }

    cacert = PEM_read_bio_X509(pem_bio, NULL, 0, NULL);
    BIO_free(pem_bio);
    pem_bio = NULL;

    
    if (cacert==NULL){
        return raiseOsslError();
    } 
     
    pycmsX509 *o=ossl_X509_from_handle( cacert );

    
    return (PyObject*)o; 
//err:
//    BIO_free(pem_bio);

}

PyObject *engine_by_id(PyObject *self, PyObject *args){
    const char *id;
    if (!PyArg_ParseTuple(args, "s", &id))
        return NULL;

    //ENGINE *e = ENGINE_by_id(id);
    pycmsEngine* e = ossl_init_engine(id);
    if( e==NULL){
        Py_RETURN_NONE;
    }else{
        return (PyObject*)( e );
    }
}

PyObject *init_openssl(PyObject *self, PyObject *args){
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
    //pycmsError *error;
    //error = pycmsError_newFromOpenSSL();
    unsigned long e = ERR_peek_last_error();
    if(e!=0){
        PyErr_SetString(PyExc_RuntimeError, ERR_reason_error_string(e));
    }

    //Py_DECREF(error);
    return NULL;
}

PyObject* raiseError(PyObject *ErrType, const char *message){
    PyErr_SetString(ErrType, message);
    return NULL;
}

