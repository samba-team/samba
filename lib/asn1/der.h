/* $Id$ */

#ifndef DER_H

#define DER_H

#include <time.h>

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
     UT_GeneralString = 27
};

/**/

struct krb5_data {
    size_t len;
    unsigned char *data;
};

typedef struct krb5_data krb5_data;

time_t timegm (struct tm *);

void time2generalizedtime (time_t t, krb5_data *s);

krb5_data string_make (char *);
krb5_data string_make_n (int len, char *);
void string_free (krb5_data);

int der_get_int (unsigned char *p, int len, unsigned *ret);
int der_get_length (unsigned char *p, int len, int *ret);
int der_get_general_string (unsigned char *p, int len, char **str);
int der_get_octet_string (unsigned char *p, int len, krb5_data *data);
int der_get_tag (unsigned char *p, int len,
		  Der_class *class, Der_type *type, int *tag);
int der_match_tag (unsigned char *p, int len,
		   Der_class class, Der_type type, int tag);
int der_match_tag_and_length (unsigned char *p, int len,
			      Der_class class, Der_type type, int tag,
			      int *length_ret);
int decode_integer (unsigned char *p, int len, unsigned *num);
int decode_general_string (unsigned char *p, int len, char **str);
int decode_octet_string (unsigned char *p, int len, krb5_data *k);
int decode_generalized_time (unsigned char *p, int len, time_t *t);


int der_put_int (unsigned char *p, int len, unsigned val);
int der_put_length (unsigned char *p, int len, int val);
int der_put_general_string (unsigned char *p, int len, char *str);
int der_put_octet_string (unsigned char *p, int len, krb5_data *data);
int der_put_tag (unsigned char *p, int len, Der_class class, Der_type type,
		 int tag);
int der_put_length_and_tag (unsigned char *p, int len, int len_val,
			    Der_class class, Der_type type, int tag);
int encode_integer (unsigned char *p, int len, unsigned *data);
int encode_general_string (unsigned char *p, int len, char **data);
int encode_octet_string (unsigned char *p, int len, krb5_data *k);
int encode_generalized_time (unsigned char *p, int len, time_t *t);

void free_integer (unsigned *num);
void free_general_string (char **str);
void free_octet_string (krb5_data *k);
void free_generalized_time (time_t *t);

size_t length_len (int len);
size_t length_integer (unsigned *data);
size_t length_general_string (char **data);
size_t length_octet_string (krb5_data *k);
size_t length_generalized_time (time_t *t);

#endif /* DER_H */
