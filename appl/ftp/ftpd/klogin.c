#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <sys/param.h>
#include <netdb.h>
#include <krb.h>
#include <kafs.h>

RCSID("$Id$");

int
klogin(char *name, char *password)
{
    int kerror;
    KTEXT_ST tkt;
    AUTH_DAT ad;
    char hostname[MaxHostNameLen];
    char realm[REALM_SZ];
    
    char *phost;
    
    struct hostent *hp;
    
    gethostname(hostname);
    phost = krb_get_phost(hostname);

    krb_get_lrealm(realm, 0);

    kerror = krb_get_pw_in_tkt(name, "", realm, 
			       "krbtgt", realm, 
			       12, password);
    if(kerror)
	return kerror;
    
    kerror = krb_mk_req(&tkt, "rcmd", phost, realm, 33);
    if (kerror){
	dest_tkt();
	return kerror;
    }
    
    hp = gethostbyname(hostname);
    
    if(!hp){
	dest_tkt();
	return -1;
    }
    
    kerror = krb_rd_req(&tkt, "rcmd", phost, *(unsigned int*)(hp->h_addr),
			&ad, "");
    
    if(kerror){
	dest_tkt();
	return kerror;
    }
    if(k_hasafs())
	k_afsklog(0, 0);
    
    return 0;
}
