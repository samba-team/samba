#ifndef _KRB4_H_
#define _KRB4_H_

#include <stdarg.h>

extern int krb4_auth(char * auth);
extern int krb4_adat(char * auth);
extern int krb4_pbsz(int size);
extern int krb4_prot(char * type);
extern int krb4_ccc(void );
extern int krb4_mic(char * msg);
extern int krb4_conf(char * msg);
extern int krb4_enc(char * msg);
extern int krb4_userok(char *name);
extern int krb4_vprintf(const char *fmt, va_list ap);

#endif /* _KRB4_H_ */
