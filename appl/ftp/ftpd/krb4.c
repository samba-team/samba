#ifdef HAVE_CONFIG_H
#include <config.h>
RCSID("$Id$");
#endif

#include <sys/types.h>
#include <sys/param.h>
#include <netinet/in.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <krb.h>

#include "base64.h"
#include "extern.h"
#include "auth.h"

#include <roken.h>

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

    if(tkt.length < 0){
	reply(501, "Failed to decode base64 data.");
	return -1;
    }

    k_getsockinst(0, inst);
    kerror = krb_rd_req(&tkt, "ftp", inst, 0, &auth_dat, "");
    if(kerror == RD_AP_UNDEC){
	k_getsockinst(0, inst);
	kerror = krb_rd_req(&tkt, "rcmd", inst, 0, &auth_dat, "");
    }

    if(kerror){
	reply(535, "Error reading request: %s.", krb_get_err_text(kerror));
	return -1;
    }
  
    des_set_key(&auth_dat.session, schedule);

    cs = auth_dat.checksum + 1;
    {
	unsigned char tmp[4];
	tmp[0] = (cs >> 24) & 0xff;
	tmp[1] = (cs >> 16) & 0xff;
	tmp[2] = (cs >> 8) & 0xff;
	tmp[3] = cs & 0xff;
	len = krb_mk_safe(tmp, msg, 4, &auth_dat.session, 
			  &ctrl_addr, &his_addr);
    }
    if(len < 0){
	reply(535, "Error creating reply: %s.", strerror(errno));
	return -1;
    }
    base64_encode(msg, len, &p);
    reply(235, "ADAT=%s", p);
    auth_complete = 1;
    free(p);
    return 0;
}

int krb4_pbsz(int size)
{
    if(size > 1048576) /* XXX arbitrary number */
	size = 1048576;
    buffer_size = size;
    reply(200, "OK PBSZ=%d", buffer_size);
    return 0;
}

int krb4_prot(int level)
{
    if(level == prot_confidential)
	return -1;
    return 0;
}

int krb4_ccc(void)
{
    reply(534, "Don't event think about it.");
    return -1;
}

int krb4_mic(char *msg)
{
    int len;
    int kerror;
    MSG_DAT m_data;
    char *p;
    char *tmp, *cmd;
  
    cmd = strdup(msg);
    
    len = base64_decode(msg, cmd);
    if(len < 0){
	reply(501, "Failed to decode base 64 data.");
	free(cmd);
	return -1;
    }
    kerror = krb_rd_safe(cmd, len, &auth_dat.session, 
			 &his_addr, &ctrl_addr, &m_data);

    if(kerror){
	reply(535, "Error reading request: %s.", krb_get_err_text(kerror));
	free(cmd);
	return -1;
    }
    
    tmp = strdup(msg);
    sprintf(tmp, "%.*s", m_data.app_length, m_data.app_data);
    if(!strstr(tmp, "\r\n"))
	strcat(tmp, "\r\n");
    new_ftp_command(tmp);
    free(cmd);
    return 0;
}

int krb4_conf(char *msg)
{
    prot_level = prot_safe;

    reply(537, "Protection level not supported.");
    return -1;
}

int krb4_enc(char *msg)
{
    int len;
    int kerror;
    MSG_DAT m_data;
    char *p;
    char *tmp, *cmd;
  
    cmd = strdup(msg);
    
    len = base64_decode(msg, cmd);
    if(len < 0){
	reply(501, "Failed to decode base 64 data.");
	free(cmd);
	return -1;
    }
    kerror = krb_rd_priv(cmd, len, schedule, &auth_dat.session, 
			 &his_addr, &ctrl_addr, &m_data);

    if(kerror){
	reply(535, "Error reading request: %s.", krb_get_err_text(kerror));
	free(cmd);
	return -1;
    }
    
    tmp = strdup(msg);
    sprintf(tmp, "%.*s", m_data.app_length, m_data.app_data);
    if(!strstr(tmp, "\r\n"))
	strcat(tmp, "\r\n");
    new_ftp_command(tmp);
    free(cmd);
    return 0;
}

int krb4_read(int fd, void *data, int length)
{
    static int left;
    static char *extra;
    static int eof;
    int len, bytes, tx = 0;
    
    MSG_DAT m_data;
    int kerror;

    if(eof){ /* if we haven't reported an end-of-file, do so */
	eof = 0;
	return 0;
    }
    
    if(left){
	if(length > left)
	    bytes = left;
	else
	    bytes = length;
	memmove(data, extra, bytes);
	left -= bytes;
	if(left)
	    memmove(extra, extra + bytes, left);
	else
	    free(extra);
	length -= bytes;
	tx += bytes;
    }

    while(length){
	unsigned char tmp[4];
	if(krb_net_read(fd, tmp, 4) < 4){
	    reply(400, "Unexpected end of file.\n");
	    return -1;
	}
	len = (tmp[0] << 24) | (tmp[1] << 16) | (tmp[2] << 8) | tmp[3];
	krb_net_read(fd, data_buffer, len);
	if(data_protection == prot_safe)
	    kerror = krb_rd_safe(data_buffer, len, &auth_dat.session, 
				 &his_addr, &ctrl_addr, &m_data);
	else
	    kerror = krb_rd_priv(data_buffer, len, schedule, &auth_dat.session,
				 &his_addr, &ctrl_addr, &m_data);
	
	if(kerror){
	    reply(400, "Failed to read data: %s.", krb_get_err_text(kerror));
	    return -1;
	}
	
	bytes = m_data.app_length;
	if(bytes == 0){
	    if(tx) eof = 1;
	    return  tx;
	}
	if(bytes > length){
	    left = bytes - length;
	    bytes = length;
	    extra = malloc(left);
	    memmove(extra, m_data.app_data + bytes, left);
	}
	memmove((unsigned char*)data + tx, m_data.app_data, bytes);
	tx += bytes;
	length -= bytes;
    }
    return tx;
}

int krb4_write(int fd, void *data, int length)
{
    int len, bytes, tx = 0;

    len = buffer_size;
    if(data_protection == prot_safe)
	len -= 31; /* always 31 bytes overhead */
    else
	len -= 26; /* at most 26 bytes */
    
    do{
	if(length < len)
	    len = length;
	if(data_protection == prot_safe)
	    bytes = krb_mk_safe(data, data_buffer+4, len, &auth_dat.session,
				&ctrl_addr, &his_addr);
	else
	    bytes = krb_mk_priv(data, data_buffer+4, len, schedule, 
				&auth_dat.session,
				&ctrl_addr, &his_addr);
	if(bytes == -1){
	    reply(535, "Failed to make packet: %s.", strerror(errno));
	    return -1;
	}
	data_buffer[0] = (bytes >> 24) & 0xff;
	data_buffer[1] = (bytes >> 16) & 0xff;
	data_buffer[2] = (bytes >> 8) & 0xff;
	data_buffer[3] = bytes & 0xff;
	krb_net_write(fd, data_buffer, bytes+4);
	length -= len;
	data = (unsigned char*)data + len;
	tx += len;
    }while(length);
    return tx;
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
    char buf[10240]; /* XXX */
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
