/*
#include "common.h"


static const BIO_METHOD pybytes_method = {
    BIO_TYPE_MEM,
    "python buffer",

    bwrite_conv,
    pybytes_write,

    bread_conv,
    0,
    pybytes_puts,
    0,
    pybytes_ctrl,
    pybytes_new,
    pybytes_free,
    NULL,                      
};

static int pybytes_new(BIO *b)
{
    Py_BIO_BUF *buf = OPENSSL_zalloc(sizeof(*buf));
     
    if (buf == NULL)
        return 0;
    
    printf("pybytes new\n");

    BIO_set_data(b, buf);
    BIO_set_init(b, 1);

    return 1;
}

static int pybytes_init(Py_BIO_BUF *buf, int size)
{
    printf("pybytes init\n");
    _PyBytesWriter_Init(&(buf->writer));
    buf->ptr = _PyBytesWriter_Alloc(&(buf->writer),size);
    return 1;
}

static int pybytes_free(BIO *b)
{
    Py_BIO_BUF *buf;
    printf("pybytes free\n");
    if (b == NULL)
        return 0;

    buf = BIO_get_data(b);
    if (buf == NULL)
        return 0;

    _PyBytesWriter_Dealloc( &(buf->writer));
    OPENSSL_free(buf);
    BIO_set_data(b, NULL);
    BIO_set_init(b, 0);

    return 1;
}

static int pybytes_write(BIO *b, const char *in, int inl)
{
    Py_BIO_BUF *buf;
    int  ret = -1;

    printf("pybytes write %.*s\n", inl, in);

    buf = BIO_get_data(b);
    if(buf==NULL){
        return 0;
    }

    void *p = _PyBytesWriter_Prepare( &(buf->writer), buf->ptr, inl);
    if(p==NULL){
        return -1;
    }
    buf->ptr = p;

    return inl;
}

static int pybytes_puts(BIO *b, const char *str)
{
    return pybytes_write(b, str, strlen(str));
}

static long pybytes_ctrl(BIO *b, int cmd, long arg1, void *arg2)
{
    Py_BIO_BUF *buf;
    buf = BIO_get_data(b);

    if (buf == NULL)
        return 0;

    if( cmd==BIO_CTRL_FLUSH){
        printf("pybytes ctrl\n");
        *(void **)arg2 = _PyBytesWriter_Finish(&(buf->writer), NULL );
    }

    return 0;
}
*/