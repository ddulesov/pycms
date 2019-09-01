#include "module.h"

static void pycms_free(pycmsEngine *engine)
{
    if (engine->ptr) {
        ENGINE_finish(engine->ptr);
		ENGINE_free(engine->ptr);
        engine->ptr = NULL;
    }
    Py_TYPE(engine)->tp_free((PyObject*) engine);
}

PyTypeObject pycmsPyTypeEngine = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "pycms.Engine",                     // tp_name
    sizeof(pycmsEngine),                // tp_basicsize
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
    0,                                  // tp_methods
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