#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <sys/ioctl.h>

#include <stdio.h>
#include <stdlib.h>
#include "extern.h"
#include "krb4.h"
#include "auth.h"

static struct at auth_types [] = {
  { "KERBEROS_V4", krb4_auth, krb4_adat, krb4_pbsz, krb4_prot, krb4_ccc, 
    krb4_mic, krb4_conf, krb4_enc, krb4_userok, krb4_vprintf },
  { 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};

struct at *ct;

int data_protection;
int buffer_size;
int auth_complete;


void auth_init(void)
{
}

char *ftp_command;
int prot_level;

void new_ftp_command(char *command)
{
  ftp_command = command;
}

void delete_ftp_command(void)
{
  if(ftp_command){
    free(ftp_command);
    ftp_command = NULL;
  }
}

void auth(char *auth)
{
  for(ct=auth_types; ct->name; ct++){
    if(!strcmp(auth, ct->name)){
      ct->auth(auth);
      return;
    }
  }
  reply(504, "%s is not a known security mechanism", auth);
}

void adat(char *auth)
{
  if(ct)
    ct->adat(auth);
  else
    reply(503, "Error, error");
}

void pbsz(int size)
{
  if(ct)
    ct->pbsz(size);
  else
    reply(503, "Error, error");
}

void prot(char *pl)
{
  if(ct)
    ct->prot(pl);
  else
    reply(503, "Error, error");
}

void ccc(void)
{
  if(ct)
    ct->ccc();
  else
    reply(503, "Error, error");
}

void mic(char *msg)
{
  prot_level = prot_safe;
  if(ct)
    ct->mic(msg);
  else
    reply(500, "Command unrecognized");
}

void conf(char *msg)
{
  prot_level = prot_confidential;
  if(ct)
    ct->conf(msg);
  else
    reply(500, "Command unrecognized");
}

void enc(char *msg)
{
  prot_level = prot_private;
  if(ct)
    ct->enc(msg);
  else
    reply(500, "Command unrecognized");
}

void auth_vprintf(const char *fmt, va_list ap)
{
  if(ct && auth_complete && prot_level){
    ct->vprintf(fmt, ap);
  }else
    vprintf(fmt, ap);
}

void auth_printf(const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  auth_vprintf(fmt, ap);
  va_end(ap);
}
