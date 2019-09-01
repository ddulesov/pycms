#include "module.h"
#include <openssl/objects.h>

static PyObject *_Verify(pycmsCMS *cms, PyObject *args,  PyObject *keywordArgs);
static PyObject *getContent(pycmsCMS *cms, void *unused);
static PyObject *getSignedTime(pycmsCMS *cms, void *unused);
static PyObject *getSigners(pycmsCMS *cms, void *unused);

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
    { "verify", (PyCFunction) _Verify, METH_VARARGS | METH_KEYWORDS },
    { NULL }
};

static PyGetSetDef pycms_members[] = {
    { "content", (getter) getContent, 0, 0, 0 },
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

//returns content as bytes object 
static PyObject *getContent(pycmsCMS *cms, void *unused){
    ASN1_OCTET_STRING **str= CMS_get0_content(cms->ptr);
    if(str==NULL)
        return NULL;
    if(!(*str))
        PY_RETURN_EMPTY;

    PY_RETURN_BUF((*str)->data, (*str)->length );    
    //return PyBytes_FromStringAndSize((*str)->data, (*str)->length);
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
			
		//ASN1_TIME_print(std, data);
        if(ASN1_UTCTIME_check(data)){
            ASN1_TIME_to_tm(data, &t);
            PyList_SetItem(l, i, fromTimeStruct(&t)); 

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

    time_t  tnotBefore, tnotAfter;
    caStoreObj = notBeforeObj = notAfterObj = NULL;

    if(cms==NULL || cms->ptr == NULL ){
        return raiseError(PyExc_RuntimeError, "uninitialized cms");
    }

    if (!PyArg_ParseTupleAndKeywords(args, keywordArgs, "|OOOs#",
            keywordList, &caStoreObj, &notBeforeObj, &notAfterObj, &content, &contentLength))
        return NULL;

    //printf("%p ", PyDateTimeAPI);
    //printf("res %s %i %i", content, Py_TYPE(notBeforeObj), PyDateTime_CheckExact(notBeforeObj)  ); ///PyDateTime_CheckExact(notBeforeObj)
    
    tnotBefore = (time_t)(0);
    tnotAfter =  (time_t)( MAX_TIME_T );

    if( notBeforeObj!=NULL) {
        if( !isDateTime(notBeforeObj) )
            return raiseError(PyExc_RuntimeError, "notBefore parameter is not datetime");
        tnotBefore = getDateTimeStamp( notBeforeObj );
        //Py_DECREF(notBeforeObj);
    }

    if( notAfterObj!=NULL ){
        if( !isDateTime(notAfterObj) )
            return raiseError(PyExc_RuntimeError, "notAfter parameter is not datetime");
        tnotAfter = getDateTimeStamp( notAfterObj );
        //Py_DECREF( notAfterObj );
    }
    
    //verify content if supplied
    if( content!=NULL ){
        cont = BIO_new_mem_buf(content, contentLength);
    }

    //verify signing time
    if(notAfterObj!=NULL || notBeforeObj!=NULL){
        //verify signing time
        const STACK_OF(CMS_SignerInfo)* sistack = CMS_get0_SignerInfos(cms->ptr);

        int n = sk_CMS_SignerInfo_num(sistack);
        for (int i = 0; i < n; i++) {
            CMS_SignerInfo*  si= sk_CMS_SignerInfo_value(sistack, i);
            void* data = CMS_signed_get0_data_by_OBJ(si, OidSigningTime, -1, V_ASN1_UTCTIME);
                
            if(ASN1_UTCTIME_check(data)){
                if( ASN1_UTCTIME_cmp_time_t(data, tnotAfter)==1 || 
                    ASN1_UTCTIME_cmp_time_t(data, tnotBefore)==-1 ){
                        //printf("signing time verify failed");
                        goto end;
                    }
            }
        }
    }

    //get local issued certificates
    if( caStoreObj!=NULL ){
        if(Py_TYPE(caStoreObj) !=  &pycmsPyTypeX509Store ){
            return raiseError(PyExc_RuntimeError, "caStore parameter is not X509Store object");
        }
        st = ((pycmsX509Store *)caStoreObj)->ptr;
    }
    //do CMS verification 
    res = CMS_verify(cms->ptr, NULL, st, cont, NULL, CMS_BINARY );
    //ERR_print_errors_fp(stderr);

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

