#ifndef __AUTH_H__
#define __AUTH_H__

#include <stdarg.h>

struct at {
  char *name;
  int (*auth)(char*);
  int (*adat)(char*);
  int (*pbsz)(int);
  int (*prot)(int);
  int (*ccc)(void);
  int (*mic)(char*);
  int (*conf)(char*);
  int (*enc)(char*);
  int (*read)(int, void*, int);
  int (*write)(int, void*, int);
  int (*userok)(char*);
  int (*vprintf)(const char*, va_list);
};

extern struct at *ct;

enum protection_levels {
  prot_clear, prot_safe, prot_confidential, prot_private
};

extern char *protection_names[];

extern char *ftp_command;
extern int prot_level;

extern int data_protection;
extern int buffer_size;
extern unsigned char *data_buffer;
extern int auth_complete;

void auth_init(void);

int auth_ok(void);

void auth(char*);
void adat(char*);
void pbsz(int);
void prot(char*);
void ccc(void);
void mic(char*);
void conf(char*);
void enc(char*);

int auth_read(int, void*, int);
int auth_write(int, void*, int);

void auth_vprintf(const char *fmt, va_list ap);
void auth_printf(const char *fmt, ...);

void new_ftp_command(char *command);

#endif /* __AUTH_H__ */
