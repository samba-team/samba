#ifndef __KRB4_H__
#define __KRB4_H__

extern int auth_complete;

void sec_status(void);

void sec_prot(int, char**);

void kauth(int, char **);

void krb4_quit(void);

#endif /* __KRB4_H__ */
