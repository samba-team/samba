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
      krb4_mic, krb4_conf, krb4_enc, krb4_read, krb4_write, krb4_userok, 
      krb4_vprintf },
    { 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};

struct at *ct;

int data_protection;
int buffer_size;
unsigned char *data_buffer;
int auth_complete;


char *protection_names[] = {
    "clear", "safe", 
    "confidential", "private"
};


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
	if(!strcasecmp(auth, ct->name)){
	    ct->auth(auth);
	    return;
	}
    }
    reply(504, "%s is not a known security mechanism", auth);
}

void adat(char *auth)
{
    if(ct && !auth_complete)
	ct->adat(auth);
    else
	reply(503, "You must (re)issue an AUTH first.");
}

void pbsz(int size)
{
    int old = buffer_size;
    if(ct && auth_complete)
	ct->pbsz(size);
    else
	reply(503, "Incomplete security data exchange.");
    if(buffer_size != old){
	if(data_buffer)
	    free(data_buffer);
	data_buffer = malloc(buffer_size + 4);
    }
}

void prot(char *pl)
{
    int p = -1;

    if(buffer_size == 0){
	reply(503, "No protection buffer size negotiated.");
	return;
    }

    if(!strcasecmp(pl, "C"))
	p = prot_clear;
    
    if(!strcasecmp(pl, "S"))
	p = prot_safe;
    
    if(!strcasecmp(pl, "E"))
	p = prot_confidential;
    
    if(!strcasecmp(pl, "P"))
	p = prot_private;
    
    if(p == -1){
	reply(504, "Unrecognized protection level.");
	return;
    }
    
    if(ct && auth_complete){
	if(ct->prot(p)){
	    reply(536, "%s does not support %s protection.", 
		  ct->name, protection_names[p]);
	}else{
	    data_protection = p;
	    reply(200, "Data protection is %s.", 
		  protection_names[data_protection]);
	}
    }else{
	reply(503, "Incomplete security data exchange.");
    }
}

void ccc(void)
{
    if(ct && auth_complete){
	if(!ct->ccc())
	    prot_level = prot_clear;
    }else
	reply(503, "Incomplete security data exchange.");
}

void mic(char *msg)
{
    if(ct && auth_complete){
	if(!ct->mic(msg))
	    prot_level = prot_safe;
    }else
	reply(503, "Incomplete security data exchange.");
}

void conf(char *msg)
{
    if(ct && auth_complete){
	if(!ct->conf(msg))
	    prot_level = prot_confidential;
    }else
	reply(503, "Incomplete security data exchange.");
}

void enc(char *msg)
{
    if(ct && auth_complete){
	if(!ct->enc(msg))
	    prot_level = prot_private;
    }else
	reply(503, "Incomplete security data exchange.");
}

int auth_read(int fd, void *data, int length)
{
    if(ct && auth_complete && data_protection)
	return ct->read(fd, data, length);
    else
	return read(fd, data, length);
}

int auth_write(int fd, void *data, int length)
{
    if(ct && auth_complete && data_protection)
	return ct->write(fd, data, length);
    else
	return write(fd, data, length);
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
