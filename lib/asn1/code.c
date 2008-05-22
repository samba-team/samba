
#include "der_locl.h"

enum prim_opcode {
    HAP_BOOLEAN = 0
};

typedef size_t (*op_length)(const void *);
typedef int    (*op_get)(const unsigned char *, size_t, void *, size_t *);
typedef int    (*op_put)(unsigned char *, size_t, const void *, size_t *);
typedef int    (*op_release)(void *);
typedef int    (*op_parse)(const char *, void *);
typedef size_t (*op_print)(const void *, char *, size_t);

/* flags */
#define OPTIONAL 1

struct op {
    /* must implement */
    int         dertype;
    const char *name;
    size_t	datasize;
    op_length   length;
    op_get      get;
    op_put      put;
    op_release  release;
    /* may implement */
    op_parse    parse;
    op_print    print;
};

/* primitive operatators */

struct op pops[] = {
    {
	UT_EndOfContent,
	"EndOfContent"
    },
    {
	UT_Boolean,
	"boolean",
	sizeof(int),
	(op_length)der_length_boolean,
	(op_get)der_get_boolean,
	(op_put)der_put_boolean,
	(op_release)der_free_generic,
	NULL,
	NULL
    }
};

int
asn1code_decode_type(unsigned int op,
		     const unsigned char *in, size_t len,
		     void *data, size_t *size);



int
asn1code_decode_type(unsigned int op,
		     const unsigned char *in, size_t len,
		     void *data, size_t *size)
{
    if (op > sizeof(pops)/sizeof(pops[0]))
	return -1;
    return (pops[op].get)(in, len, data, size);
}
