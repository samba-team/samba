#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

RCSID("$Id$");

#include "ftp_locl.h"
#include <krb.h>

void kauth(int argc, char **argv)
{
    int ret;
    char buf[1024];
    des_cblock key;
    des_key_schedule schedule;
    KTEXT_ST tkt, tktcopy;
    char *name;
    char *p;
    int overbose;
    char passwd[100];
	
    if(argc > 2){
	printf("usage: %s [principal]\n", argv[0]);
	code = -1;
	return;
    }
    if(argc == 2)
	name = argv[1];
    else
	name = username;

    overbose = verbose;
    verbose = 0;

    ret = command("SITE KAUTH %s", name);
    if(ret != CONTINUE){
	verbose = overbose;
	code = -1;
	return;
    }
    verbose = overbose;
    p = strstr(reply_string, "T=");
    if(!p){
	printf("Bad reply from server.\n");
	code = -1;
	return;
    }
    p += 2;
    tkt.length = base64_decode(p, &tkt.dat);
    if(tkt.length < 0){
	printf("Failed to decode base64 in reply.\n");
	code = -1;
	return;
    }
    tktcopy.length = tkt.length;
    
    p = strstr(reply_string, "P=");
    if(!p){
	printf("Bad reply from server.\n");
	verbose = overbose;
	code = -1;
	return;
    }
    name = p + 2;
    for(; *p && *p != ' ' && *p != '\r' && *p != '\n'; p++);
    *p = 0;
    
    sprintf(buf, "Password for %s:", name);
    if (des_read_pw_string (passwd, sizeof(passwd)-1, buf, 0))
        *passwd = '\0';
    des_string_to_key (passwd, &key);

    des_key_sched(&key, schedule);
    
    des_pcbc_encrypt((des_cblock*)tkt.dat, (des_cblock*)tktcopy.dat,
		     tkt.length,
		     schedule, &key, DES_DECRYPT);
    if (strcmp ((char*)tktcopy.dat + 8, "krbtgt") != 0) {
        afs_string_to_key (passwd, krb_realmofhost(hostname), &key);
	des_key_sched (&key, schedule);
	des_pcbc_encrypt((des_cblock*)tkt.dat, (des_cblock*)tktcopy.dat,
			 tkt.length,
			 schedule, &key, DES_DECRYPT);
    }
    memset(key, 0, sizeof(key));
    memset(schedule, 0, sizeof(schedule));
    memset(passwd, 0, sizeof(passwd));
    base64_encode(tktcopy.dat, tktcopy.length, &p);
    memset (tktcopy.dat, 0, tktcopy.length);
    ret = command("SITE KAUTH %s %s", name, p);
    free(p);
    if(ret != COMPLETE){
	code = -1;
	return;
    }
    code = 0;
}

void klist(int argc, char **argv)
{
    int ret;
    if(argc != 1){
	printf("usage: %s\n", argv[0]);
	code = -1;
	return;
    }
    
    ret = command("SITE KLIST");
    code = (ret == COMPLETE);
}
