/* $Id$ */

#ifndef DER_H

#define DER_H

typedef enum {UNIV = 0, APPL = 1, CONTEXT = 2 , PRIVATE = 3} Der_class;

typedef enum {PRIM = 0, CONS = 1} Der_type;

/* Universal tags */

enum {
     UT_Integer = 2,	
     UT_BitString = 3,
     UT_OctetString = 4,
     UT_Null = 5,
     UT_ObjID = 6,
     UT_Sequence = 16,
     UT_Set = 17,
     UT_PrintableString = 19,
     UT_IA5String = 22,
     UT_UTCTime = 23,
     UT_GeneralizedTime = 24,
     UT_GeneralString = 27,
};

/**/

struct krb5_data {
  unsigned len;
  unsigned char *data;
};

typedef struct krb5_data krb5_data;

krb5_data string_make (char *);
krb5_data string_make_n (int len, char *);
void string_free (krb5_data);

#endif /* DER_H */
