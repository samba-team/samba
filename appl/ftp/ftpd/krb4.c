#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/param.h>
#include <netinet/in.h>

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <krb.h>

#include "base64.h"
#include "extern.h"
#include "auth.h"

static AUTH_DAT auth_dat;
static des_key_schedule schedule;

int krb4_auth(char *auth)
{
  auth_complete = 0;
  reply(334, "Using authentication type %s; ADAT must follow", auth);
  return 0;
}

int krb4_adat(char *auth)
{
  KTEXT_ST tkt;
  char *p;
  int kerror;
  u_int32_t cs;
  char msg[35]; /* size of encrypted block */
  int len;

  char inst[INST_SZ];

  memset(&tkt, 0, sizeof(tkt));
  tkt.length = base64_decode(auth, tkt.dat);

  strcpy(inst, "*");
  kerror = krb_rd_req(&tkt, "ftp", inst, 0, &auth_dat, "");
  if(kerror == RD_AP_UNDEC){
    strcpy(inst, "*");
    kerror = krb_rd_req(&tkt, "rcmd", inst, 0, &auth_dat, "");
  }
  
  des_key_sched(&auth_dat.session, schedule);

  if(kerror != RD_AP_OK){
    reply(535, "%s", krb_err_txt[kerror]);
    return 1;
  }

  cs = htonl(auth_dat.checksum + 1);
  len = krb_mk_safe((u_char*)&cs, (u_char*)msg, sizeof(cs), 
		    &auth_dat.session, &ctrl_addr, &his_addr);
  base64_encode((unsigned char*)msg, len, &p);
  reply(235, "ADAT=%s", p);
  auth_complete = 1;
  free(p);
  return 0;
}

int krb4_pbsz(int size)
{
  buffer_size = size;
  reply(200, "OK");
  return 0;
}

int krb4_prot(char *type)
{
  if(!strcmp(type, "C")){
    data_protection = prot_clear;
  }else if(!strcmp(type, "S")){
    data_protection = prot_safe;
  }else if(!strcmp(type, "E")){
    data_protection = prot_confidential;
  }else if(!strcmp(type, "P")){
    data_protection = prot_private;
  }else{
    reply(504, "Unrecognized protection level");
    return 1;
  }
  reply(200, "OK");
  return 0;
}

int krb4_ccc(void)
{
  reply(500, "Gurka");
  return 1;
}

int krb4_mic(char *msg)
{
  char *cmd = (char*)malloc(strlen(msg));
  int len;
  int kerror;
  MSG_DAT m_data;
  char *p;
  char tmp[1024];
  unsigned char enc[1024];
  
  len = base64_decode(msg, cmd);
  kerror = krb_rd_safe(cmd, len, &auth_dat.session, 
		       &ctrl_addr, &his_addr, &m_data);
  sprintf(tmp, "%.*s\r\n", m_data.app_length, m_data.app_data);
  new_ftp_command(strdup(tmp));
  free(cmd);
  return 0;
}

int krb4_conf(char *msg)
{
  char tmp[1024];
  unsigned char enc[1024];
  int len;
  char *p;
  
  sprintf(tmp, "%d %s\r\n", 536, 
	  "Requested PROT level not supported by mechanism");
  len = krb_mk_safe((u_char*)tmp, (u_char*)enc, strlen(tmp), &auth_dat.session, 
		    &ctrl_addr, &his_addr);
  if(len > 0){
    base64_encode(enc, len, &p);
    fprintf(stdout, "631 %s\r\n", p);
    free(p);
  }
  return 1;
}

int krb4_enc(char *msg)
{
  char *cmd = (char*)malloc(strlen(msg));
  int len;
  int kerror;
  MSG_DAT m_data;
  char *p;

  char tmp[1024];
  unsigned char enc[1024];
  
  len = base64_decode(msg, cmd);
  
  kerror = krb_rd_priv(cmd, len, schedule, &auth_dat.session, 
		       &ctrl_addr, &his_addr, &m_data);
  sprintf(tmp, "%.*s\r\n", m_data.app_length, m_data.app_data);
  new_ftp_command(strdup(tmp));

  free(cmd);
  return 0;
}

int krb4_userok(char *name)
{
  if(!kuserok(&auth_dat, name)){
    do_login(232, name);
  }else{
    reply(530, "User %s access denied.", name);
  }
  return 0;
}


int krb4_vprintf(const char *fmt, va_list ap)
{
  char buf[10240];
  char *p;
  char *enc;
  int code;
  int len;
  
  vsprintf(buf, fmt, ap);
  enc = malloc(strlen(buf) + 31);
  if(prot_level == prot_safe){
    len = krb_mk_safe((u_char*)buf, (u_char*)enc, strlen(buf), &auth_dat.session, 
		      &ctrl_addr, &his_addr); 
    code = 631;
  }else if(prot_level == prot_private){
    len = krb_mk_priv((u_char*)buf, (u_char*)enc, strlen(buf), schedule, 
		      &auth_dat.session, &ctrl_addr, &his_addr); 
    code = 632;
  }else{
    len = 0; /* XXX */
    code = 631;
  }
  base64_encode(enc, len, &p);
  fprintf(stdout, "%d %s\r\n", code, p);
  free(enc);
  free(p);
  return 0;
}
