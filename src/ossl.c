#include "common.h"
#include "module.h"

//load openssl dynamic module
pycmsEngine *ossl_init_engine(const char* engine_id){
    pycmsEngine *o = NULL;
    ENGINE *eng = ENGINE_by_id(engine_id);
    
    if(eng==NULL){
        return NULL;
    }

    CHECK(ENGINE_init(eng));
	CHECK(ENGINE_set_default(eng, ENGINE_METHOD_ALL));

    o = (pycmsEngine*) pycmsPyTypeEngine.tp_alloc(&pycmsPyTypeEngine, 0);
    CHECK(o);
    o->ptr = eng;

    return o;
err:
    if(eng!=NULL){
		ENGINE_finish(eng);
		ENGINE_free(eng);
    }
    return NULL;
}

pycmsX509Name *ossl_X509Name_from_handle(X509_NAME* handle){
    pycmsX509Name *o = NULL;
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

pycmsCMS *ossl_CMS_from_handle(CMS_ContentInfo* handle){
    pycmsCMS *o = NULL;

    CHECK(handle);

    o = (pycmsCMS*) pycmsPyTypeCMS.tp_alloc(&pycmsPyTypeCMS, 0);
    CHECK(o);

    o->ptr = handle;
    return o;
err:
    if(handle!=NULL){
		CMS_ContentInfo_free(handle);
    }
    return NULL;
}
