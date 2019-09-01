
#include "common.h"
/*
static int mem_write(BIO *h, const char *buf, int num);
static int mem_read(BIO *h, char *buf, int size);
static int mem_puts(BIO *h, const char *str);
static int mem_gets(BIO *h, char *str, int size);
static long mem_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int mem_new(BIO *h);
static int secmem_new(BIO *h);
static int mem_free(BIO *data);
static int mem_buf_free(BIO *data);
static int mem_buf_sync(BIO *h);


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

static int asn1_bio_new(BIO *b)
{
    _PyBytesWriter *wrt = OPENSSL_zalloc(sizeof(*wrt));
    _PyBytesWriter_Init(wrt); 

    if (wrt == NULL)
        return 0;

    BIO_set_data(b, wrt);
    BIO_set_init(b, 1);

    return 1;
}

static int asn1_bio_init(_PyBytesWriter *wrt, int size)
{
    void *s = _PyBytesWriter_Alloc(&wrt,size);
    BIO_set_callback_arg(out, &wrt);
    return 1;
}

static int asn1_bio_free(BIO *b)
{
    BIO_ASN1_BUF_CTX *ctx;

    if (b == NULL)
        return 0;

    ctx = BIO_get_data(b);
    if (ctx == NULL)
        return 0;

    OPENSSL_free(ctx->buf);
    OPENSSL_free(ctx);
    BIO_set_data(b, NULL);
    BIO_set_init(b, 0);

    return 1;
}

static int asn1_bio_write(BIO *b, const char *in, int inl)
{
    BIO_ASN1_BUF_CTX *ctx;
    int wrmax, wrlen, ret;
    unsigned char *p;
    BIO *next;

    ctx = BIO_get_data(b);
  

    return (wrlen > 0) ? wrlen : ret;

}

static int asn1_bio_puts(BIO *b, const char *str)
{
    return asn1_bio_write(b, str, strlen(str));
}
static long asn1_bio_ctrl(BIO *b, int cmd, long arg1, void *arg2)
{
    return 0;
}
*/