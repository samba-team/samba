/* These routines are used for geting an AFS tocken from a local
   srvtab on file. Yes, user accounts with local srvtabs will be
   hacked in a root breakin, destoying the wounderfull AFS security,
   but it is a quick and dirty solution that works for a fairly secure
   Samba server machine. /Johan Hedin (johanh@fusion.kth.se)
   
   Based on kauth.c from krb-0.10.1 by
   Kungliga Tekniska Högskolan
   (Royal Institute of Technology, Stockholm, Sweden).
   */

#include "includes.h"

#ifdef RENEWABLE_AFS_TICKET

struct Srvtabinfo srvtabinfo;
int lifetime = DEFAULT_TKT_LIFE;

/* what user is current? */
extern struct current_user current_user;

extern int DEBUGLEVEL;

int get_afs_ticket_from_srvtab(void){
  BOOL isroot = current_user.uid == 0;
  int result;
  char srvtab[sizeof(pstring)] = "";
  char realm[REALM_SZ];

  if(!isroot){
    unbecome_user();
  } /* if */

  become_uid(srvtabinfo.uid);
  /* krb_set_tkt_string(tkfile); */

  pstrcat(srvtab, "/var/srvtabs/");
  pstrcat(srvtab, srvtabinfo.user);
  if (krb_get_lrealm(realm, 1) != KSUCCESS) 
    (void) strncpy(realm, KRB_REALM, REALM_SZ - 1);
  result = krb_get_svc_in_tkt(srvtabinfo.user, "", realm,
			      KRB_TICKET_GRANTING_TICKET,
			      realm, lifetime, srvtab);
  
  if(isroot){
    unbecome_user();
  } /* if */
  if(result != KSUCCESS)
    DEBUG(1,("Using file %s, error: %s\n",
	     srvtab,
	     krb_get_err_text(result)));
  else
    if((result = krb_afslog(NULL, NULL)) != KSUCCESS &&
       result != KDC_PR_UNKNOWN)
      DEBUG(1,("AFS ticket error: %s\n",
	       krb_get_err_text(result)));
  DEBUG(2,("Renewing ticket for user %s\n", srvtabinfo.user));
  return(krb_life_to_time(0, lifetime)/2 - 60);
} /* get_afs_ticket_from_srvtab */

pid_t get_renewed_ticket(void){
  pid_t child;

  DEBUG(2,("Getting ticket for user %s\n", srvtabinfo.user));
  if((child = fork()) == 0){
    /* Forking needed in order to use alarm */
    for(;;)
      sleep(get_afs_ticket_from_srvtab());
  } /* if */
  return child;
} /* get_renewed_ticket */

#endif /* RENEWABLE_AFS_TICKET */
