#include "module.h"
#include <openssl/objects.h>

static PyObject *_Verify(pycmsCMS *cms, PyObject *args,  PyObject *keywordArgs);
static PyObject *_Sign(PyObject *_null, PyObject *args,  PyObject *keywordArgs);
static PyObject *_Load(PyObject *_null, PyObject *args);
static PyObject *getContent(pycmsCMS *cms, void *unused);
static PyObject *getSignedTime(pycmsCMS *cms, void *unused);
static PyObject *getSigners(pycmsCMS *cms, void *unused);
static PyObject *getPEM(pycmsCMS *cms, void *unused);

//signing time Object Identificator
extern ASN1_OBJECT *OidSigningTime;

static void pycms_free(pycmsCMS *cms)
{
    if (cms->ptr) {
        CMS_ContentInfo_free(cms->ptr);
        cms->ptr = NULL;
    }
    Py_TYPE(cms)->tp_free((PyObject*) cms);
}

static PyMethodDef pycms_methods[] = {
    { "load", (PyCFunction) _Load, METH_VARARGS | METH_STATIC , "load CMS from file in PEM format" },
    { "verify", (PyCFunction) _Verify, METH_VARARGS | METH_KEYWORDS , "verify CMS signedData"},
    { "sign", (PyCFunction) _Sign, METH_VARARGS | METH_STATIC | METH_KEYWORDS , "sign  string and return CMS signedData"},
    { NULL }
};

static PyGetSetDef pycms_members[] = {
    { "content", (getter) getContent, 0, 0, 0 },
    { "pem", (getter) getPEM, 0, 0, 0 },
    { "signedtime", (getter) getSignedTime, 0, 0, 0 },
    { "signers", (getter) getSigners, 0, 0, 0 },
    { NULL }
};

PyTypeObject pycmsPyTypeCMS = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "pycms.CMS",                     // tp_name
    sizeof(pycmsCMS),                // tp_basicsize
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
    pycms_members,                       // tp_getset
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

static PyObject *_Load(PyObject *_null, PyObject *args){
    CMS_ContentInfo *cms = NULL;
    const char *filename=NULL;
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

    return (PyObject*)ossl_CMS_from_handle( cms );
}
//returns content as bytes object 
static PyObject *getContent(pycmsCMS *cms, void *unused){
    ASN1_OCTET_STRING **str= CMS_get0_content(cms->ptr);
    if(str==NULL)
        return NULL;
    if(!(*str))
        PY_RETURN_EMPTY;

    PY_RETURN_BUF((const char*)(*str)->data, (*str)->length );    
    //return PyBytes_FromStringAndSize((*str)->data, (*str)->length);
}

//returns CMS pem representation as bytes object 
static PyObject *getPEM(pycmsCMS *cms, void *unused){
    int len;
    const char *ptr;
    PyObject* res = NULL;
    BIO *out= BIO_new(BIO_s_mem());

    if(! PEM_write_bio_CMS(out, cms->ptr)){
        BIO_free( out );
        return NULL;
    }
    len = BIO_get_mem_data(out, &ptr);
    res = PyBytes_FromStringAndSize(ptr, len );
    BIO_free( out );

    return res;
}

//returns signing time list
static PyObject *getSignedTime(pycmsCMS *cms, void *unused){
    struct tm t;
    const STACK_OF(CMS_SignerInfo)* sistack = CMS_get0_SignerInfos(cms->ptr);

    int n = sk_CMS_SignerInfo_num(sistack);
    PyObject *l = PyList_New(n);

    for (int i = 0; i < n; i++) {
		CMS_SignerInfo*  si= sk_CMS_SignerInfo_value(sistack, i);
        void* data = CMS_signed_get0_data_by_OBJ(si, OidSigningTime, -1, V_ASN1_UTCTIME);
			
        if(ASN1_UTCTIME_check(data)){
            ASN1_TIME_to_tm(data, &t);
            PyList_SetItem(l, i, DateTime_from_tm(&t)); 
        }else{
            Py_IncRef(Py_None);
            PyList_SetItem(l, i, Py_None);
        }
    }
    return l;
}

//returns signers certificate list
static PyObject *getSigners(pycmsCMS *cms, void *unused){
    STACK_OF(X509)*  x509 = CMS_get1_certs(cms->ptr);
    int n = sk_X509_num(x509);

    PyObject *l = PyList_New(n);
    for (int i = 0; i < n; i++) {
        X509  *h = sk_X509_value(x509, i);

        PyObject *item = (PyObject *)ossl_X509_from_handle(h);
        if(item==NULL){
            goto err;
        }
        PyList_SetItem(l, i, item);
    }

    //sk_X509_pop_free(x509, X509_free);
    return l;

err:
    sk_X509_pop_free(x509, X509_free);
    //ToDo relese x509 as well
    Py_DECREF(l);
    return NULL;
}

static PyObject *_Verify(pycmsCMS *cms, PyObject *args,  PyObject *keywordArgs){
    static char *keywordList[] = { "caStore", "notBefore", "notAfter", "content", NULL };
    BIO *cont = NULL;
    X509_STORE *st = NULL;
    int res = 0;

    PyObject *caStoreObj, *notBeforeObj, *notAfterObj;
    char *content=NULL;
    Py_ssize_t contentLength;

    struct tm  tnotBefore={0};
    struct tm  tnotAfter = {.tm_year=0xFF};

    caStoreObj = notBeforeObj = notAfterObj = NULL;

    if(cms==NULL || cms->ptr == NULL ){
        return raiseError(VerifyError, "uninitialized cms");
    }

    if (!PyArg_ParseTupleAndKeywords(args, keywordArgs, "|OOOs#",
            keywordList, &caStoreObj, &notBeforeObj, &notAfterObj, &content, &contentLength))
        return NULL;
    


    if( notBeforeObj!=NULL) {
        if( !isDateTime(notBeforeObj) )
            return raiseError(VerifyError, "notBefore parameter is not datetime");
         
        DateTime_to_tm(notBeforeObj, &tnotBefore );

    }

    if( notAfterObj!=NULL ){
        if( !isDateTime(notAfterObj) )
            return raiseError(VerifyError, "notAfter parameter is not datetime");
        
        DateTime_to_tm(notAfterObj, &tnotAfter);
    }
    
    //verify content if supplied
    if( content!=NULL ){
        cont = BIO_new_mem_buf(content, (int)contentLength);
    }

    //verify signing time
    if(notAfterObj!=NULL || notBeforeObj!=NULL){
        
        const STACK_OF(CMS_SignerInfo)* sistack = CMS_get0_SignerInfos(cms->ptr);

        int n = sk_CMS_SignerInfo_num(sistack);
        for (int i = 0; i < n; i++) {
            CMS_SignerInfo*  si= sk_CMS_SignerInfo_value(sistack, i);
            void* data = CMS_signed_get0_data_by_OBJ(si, OidSigningTime, -1, V_ASN1_UTCTIME);
                
            if(data!=NULL && ASN1_UTCTIME_check(data)){
                struct tm  ttm;
                int day, sec;
                if(ASN1_TIME_to_tm(data, &ttm)<0)
                    goto end;


                if (!OPENSSL_gmtime_diff(&day, &sec, &ttm, &tnotAfter)){
                    goto end;
                }

                if(day<0 || sec<0){
                    goto end;
                }

                if (!OPENSSL_gmtime_diff(&day, &sec, &ttm, &tnotBefore)){
                    goto end;
                }
                if(day>0 || sec>0){
                    goto end;
                }

            }else{
                
                goto end;
            }
        }
    }

    //get local issued certificates
    if( caStoreObj!=NULL ){
        if(Py_TYPE(caStoreObj) !=  &pycmsPyTypeX509Store ){
            return raiseError(VerifyError, "caStore parameter is not X509Store object");
        }
        st = ((pycmsX509Store *)caStoreObj)->ptr;
    }
    //do CMS verification 
    res = CMS_verify(cms->ptr, NULL, st, cont, NULL, CMS_BINARY );


end:
    //release temp content BIO
    if(cont!=NULL){
        BIO_free(cont);
    }

    if(res==1)
        Py_RETURN_TRUE;
    else
        Py_RETURN_FALSE;
}


static PyObject *_Sign(PyObject *_null, PyObject *args,  PyObject *keywordArgs){
    static char *keywordList[] = { "pkey", "content", "signer", NULL };

    PyObject *evpObj, *signerObj;
    evpObj = signerObj = NULL;

    char *content = NULL;
    Py_ssize_t  contentLen;

    if (!PyArg_ParseTupleAndKeywords(args, keywordArgs, "Os#O",
            keywordList, &evpObj, &content, &contentLen, &signerObj))
        return NULL;

    if(content==NULL || contentLen==0){
        return raiseError(VerifyError, "content should not be empty string");
    }

    if(Py_TYPE(signerObj) !=  &pycmsPyTypeX509 ){
        return raiseError(VerifyError, "signer parameter is not X509 object");
    }

    if(Py_TYPE(evpObj) !=  &pycmsPyTypeEVP ){
        return raiseError(VerifyError, "pkey parameter is not EVP object");
    }

    BIO* data = BIO_new_mem_buf(content, (int)contentLen);
    
    CMS_ContentInfo * handle = CMS_sign( ((pycmsX509 *)signerObj )->ptr , ((pycmsEVP *) evpObj)->ptr, NULL, data, CMS_BINARY );
                          
    BIO_free( data );

    return (PyObject *)ossl_CMS_from_handle( handle );

}
