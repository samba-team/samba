#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "ftp_locl.h"
#include <krb.h>

void kauth(int argc, char **argv)
{
    int ret;
    char buf[1024];
    des_cblock key;
    des_key_schedule schedule;
    KTEXT_ST tkt;
    char *name;
    char *p;
	

    if(argc > 2){
	printf("usage: %s [principal]\n", argv[0]);
	code = -1;
	return;
    }
    if(argc == 2)
	name = argv[1];
    else
	name = username;
    ret = command("SITE KAUTH %s", name);
    if(ret != CONTINUE){
	code = -1;
	return;
    }
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
    
    p = strstr(reply_string, "P=");
    if(!p){
	printf("Bad reply from server.\n");
	code = -1;
	return;
    }
    name = p + 2;
    for(; *p && *p != ' ' && *p != '\r' && *p != '\n'; p++);
    *p = 0;
    
    
    sprintf(buf, "Password for %s:", name);
    des_read_password(&key, buf, 0);

    des_key_sched(&key, schedule);
    
    des_pcbc_encrypt((des_cblock*)tkt.dat, (des_cblock*)tkt.dat, tkt.length, 
		     schedule, &key, DES_DECRYPT);
    memset(key, 0, sizeof(key));
    memset(schedule, 0, sizeof(schedule));
    base64_encode(tkt.dat, tkt.length, &p);
    ret = command("SITE KAUTH %s %s", name, p);
    free(p);
    if(ret != COMPLETE){
	code = -1;
	return;
    }
    code = 0;
}
