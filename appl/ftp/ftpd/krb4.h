/* $Id$ */

#ifndef __KRB4_H__
#define __KRB4_H__

#include <stdarg.h>

int krb4_auth(char *auth);
int krb4_adat(char *auth);
int krb4_pbsz(int size);
int krb4_prot(int level);
int krb4_ccc(void);
int krb4_mic(char *msg);
int krb4_conf(char *msg);
int krb4_enc(char *msg);

int krb4_read(int fd, void *data, int length);
int krb4_write(int fd, void *data, int length);

int krb4_userok(char *name);
int krb4_vprintf(const char *fmt, va_list ap);

#endif /* __KRB4_H__ */
