/* $Id$ */

#ifndef __KRB4_H__
#define __KRB4_H__

extern int auth_complete;

void sec_status(void);

enum { prot_clear, prot_safe, prot_confidential, prot_private };

void sec_prot(int, char**);

void sec_set_protection_level(void);
int sec_request_prot(char *level);

void kauth(int, char **);
void klist(int, char **);

void krb4_quit(void);

#endif /* __KRB4_H__ */
