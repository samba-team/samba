#include <der.h>

struct Buffer {
     unsigned char *buf;
     unsigned char *p;
     unsigned len;
};

typedef struct Buffer Buffer;

int  buf_getbyte (Buffer *);
void buf_init (Buffer *, char *, unsigned);
Buffer *buf_derive (Buffer *, Buffer *, int);
int  buf_bytesleft (Buffer *b);
void buf_advance (Buffer *b, int n);
int buf_length (Buffer *b);

struct Identifier {
     Der_class class;
     Der_type type;
     unsigned tag;
     int len;
};

typedef struct Identifier Identifier;

Identifier *getid (Buffer *b, Identifier *i);
