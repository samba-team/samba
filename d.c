#include <krb5_locl.h>
#include <d.h>

int
buf_getbyte (Buffer *b)
{
     if (b->p >= b->buf + b->len)
	  return EOF;
     return *b->p++;
}

void
buf_init (Buffer *b, char *ptr, unsigned len)
{
     b->buf = b->p = ptr;
     b->len = len;
}

Buffer *
buf_derive (Buffer *b, Buffer *tmp, int len)
{
     tmp->buf = tmp->p = b->p;
     if(len == -1)
	  tmp->len = buf_bytesleft (b);
     else
	  tmp->len = len;
     return tmp;
}

int
buf_bytesleft (Buffer *b)
{
     return b->len - (b->p - b->buf);
}

void
buf_advance (Buffer *b, int n)
{
     b->p += n;
}

int
buf_length (Buffer *b)
{
     return b->p - b->buf;
}

Identifier *
getid (Buffer *b, Identifier *i)
{
     int c, len;

     c = buf_getbyte (b);
     if (c == EOF)
	  return NULL;
     i->class = c >> 6;
     i->type  = (c >> 5) & 1;
     i->tag   = c & 0x1F;
     if (i->tag == 0x1F) {
	  do {
	       c = buf_getbyte (b);
	       if (c == EOF)
		    return NULL;
	       i->tag = i->tag * 0x80 + (c & 0x7F);
	  } while( c & 0x80);
     }

     c = buf_getbyte (b);
     if (c == EOF)
	  return NULL;
     len = c;
     if (len < 0x80) {
	  i->len = len;
     } else if(len > 0x80) {
	  len &= 0x7F;
	  i->len = 0;
	  while (len--) {
	       c = buf_getbyte (b);
	       if (c == EOF)
		    return NULL;
	       i->len = i->len * 0x100 + c;
	  }
     } else if (len == 0x80)
	  i->len = -1;
     return i;
}

Identifier *
matchid (Buffer *b, Identifier *i)
{
     Identifier tmp;

     if (getid (b, &tmp) == NULL)
	  return NULL;
     if (tmp.class == i->class && tmp.type == i->type && tmp.tag == i->tag) {
	  i->len = tmp.len;
	  return i;
     } else
	  return NULL;
}

static Identifier dummy;

Identifier *
matchid3 (Buffer *b, Identifier *i, Der_class class, Der_type type,
	  unsigned tag)
{
     i->class = class;
     i->type  = type;
     i->tag   = tag;
     return matchid (b, i);
}

Identifier *
matchcontextid (Buffer *b, Identifier *i, int tag)
{
     Identifier tmp;
     
     if (matchid3 (b, &tmp, CONTEXT, CONS, tag) == NULL ||
	 matchid (b, i) == NULL)
	  return NULL;
     return i;
}

Identifier *
matchcontextid3 (Buffer *b, Identifier *i, Der_class class,
		 Der_type dtype,
		 int type,
		 unsigned tag)
{
     i->class = class;
     i->type  = dtype;
     i->tag   = type;
     return matchcontextid (b, i, tag);
}

int
der_get_integer (Buffer *b, void *val)
{
     int c;
     int res;
     int len;

     res = len = 0;
     while ((c = buf_getbyte (b)) != EOF) {
	  res = res * 0x100 + c;
	  ++len;
     }
     *((int *)val) = res;
     return len;
}

int
der_get_octetstring (Buffer *b, void *val)
{
     krb5_data *str = (krb5_data *)val;
     int len, c;
     char *p;

     len = buf_bytesleft (b);
     str->length = len;
     str->data   = p = malloc (len + 1);
     while (len && (c = buf_getbyte (b)) != EOF) {
	  *p++ = c;
	  --len;
     }
     *p++ = '\0';
     return len;
}

int
der_get_generalizedtime (Buffer *b, void *val)
{
     time_t *t = (time_t *)val;
     int len;
     krb5_data str;
     struct tm tm;
     extern long timezone;

     len = der_get_octetstring (b, &str);
     sscanf (str.data, "%04d%02d%02d%02d%02d%02dZ",
	     &tm.tm_year, &tm.tm_mon, &tm.tm_mday, &tm.tm_hour,
	     &tm.tm_min, &tm.tm_sec);
     tm.tm_year -= 1900;
     tm.tm_mon -= 1;
     tm.tm_isdst = 0;

     *t = mktime (&tm);
     *t -= timezone;

     string_free (str);
     return len;
}

static int (*get_univ_funcs[])(Buffer *, void *val) = {
     NULL,			/*  0 */
     NULL,			/*  1 */
     der_get_integer,		/*  2 */
     NULL,			/*  3 */
     der_get_octetstring,	/*  4 */
     NULL,			/*  5 */
     NULL,			/*  6 */
     NULL,			/*  7 */
     NULL,			/*  8 */
     NULL,			/*  9 */
     NULL,			/* 10 */
     NULL,			/* 11 */
     NULL,			/* 12 */
     NULL,			/* 13 */
     NULL,			/* 14 */
     NULL,			/* 15 */
     NULL,			/* 16 */
     NULL,			/* 17 */
     NULL,			/* 18 */
     NULL,			/* 19 */
     NULL,			/* 20 */
     NULL,			/* 21 */
     NULL,			/* 22 */
     NULL,			/* 23 */
     der_get_generalizedtime,	/* 24 */
     NULL,			/* 25 */
     NULL,			/* 26 */
     der_get_octetstring,	/* 27 */
};

int
der_get_val (Buffer *b, int type, void *val)
{
     return (*(get_univ_funcs[type]))(b, val);
}

void
getzeros (Buffer *b, int len)
{
     if (len == -1) {
	  buf_getbyte (b);
	  buf_getbyte (b);
     }
}

int
getdata (Buffer *b, Identifier *i, void *arg)
{
     Buffer tmp;
     int res;

     buf_derive (b, &tmp, i->len);
     res = der_get_val (&tmp, i->tag, arg);
     if (i->len == -1) {
	  getzeros (b, i->len);
	  buf_advance (b, res);
     } else
	  buf_advance (b, i->len);
     return res;
}
