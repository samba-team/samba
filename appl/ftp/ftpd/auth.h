#ifndef _AUTH_H_
#define _AUTH_H_

#include <stdarg.h>

struct at {
  char *name;
  int (*auth)(char*);
  int (*adat)(char*);
  int (*pbsz)(int);
  int (*prot)(char*);
  int (*ccc)(void);
  int (*mic)(char*);
  int (*conf)(char*);
  int (*enc)(char*);
  int (*userok)(char*);
  int (*vprintf)(const char*, va_list);
};

struct at *ct;

enum protection_levels {
  prot_clear, prot_safe, prot_confidential, prot_private
};

extern char *ftp_command;
extern int prot_level;

int data_protection;
int buffer_size;
int auth_complete;

void auth_init(void);

void auth(char*);
void adat(char*);
void pbsz(int);
void prot(char*);
void ccc(void);
void mic(char*);
void conf(char*);
void enc(char*);

void auth_vprintf(const char *fmt, va_list ap);
void auth_printf(const char *fmt, ...);

void new_ftp_command(char *command);

#endif /* _AUTH_H_ */
