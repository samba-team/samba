/* 
This module is an adaption of code from the tcpd-1.4 package written
by Wietse Venema, Eindhoven University of Technology, The Netherlands.

The code is used here with permission.

The code has been considerably changed from the original. Bug reports
should be sent to samba-bugs@samba.anu.edu.au
*/

#include "includes.h"

#define ALLOW_PURE_ADDRESSES

extern int DEBUGLEVEL;

#ifndef	INADDR_NONE
#define	INADDR_NONE	((uint32)~0)
#endif


#define FROM_ADDRLEN  (4*3+3+1)
#define Good True
#define Bad False

#define CLIENT_MATCH client_match

/* Delimiters for lists of daemons or clients. */

static char sep[] = ", \t";

/* Constants to be used in assignments only, not in comparisons... */

#define	YES		1
#define	NO		0
#define	FAIL		(-1)

/* Forward declarations. */
static int list_match(char *list,char *item, int (*match_fn)());
static int client_match(char *tok,char *item);
static int string_match(char *tok,char *s);
static int masked_match(char *tok, char *slash, char *s);
static int matchname(char *remotehost,struct in_addr  addr);

/* Size of logical line buffer. */
#define	BUFLEN 2048


/* return true if access should be allowed to a service*/
BOOL check_access(int snum)
{
  extern int Client;
  extern struct from_host Client_info;
  char *denyl,*allowl;
  BOOL ret = False;

  denyl = lp_hostsdeny(snum);
  if (denyl) denyl = strdup(denyl);

  allowl = lp_hostsallow(snum);
  if (allowl) allowl = strdup(allowl);


  fromhost(Client,&Client_info);

  if ((!denyl || *denyl==0) && (!allowl || *allowl==0))
    ret = True;

  if (!ret)
    {
      if (!fromhost(Client,&Client_info))
	DEBUG(0,("ERROR: Can't get from_host info\n"));
      else
	{
	  if (allow_access(denyl,allowl,&Client_info))
	    {
	      if (snum >= 0)
		DEBUG(2,("Allowed connection from %s (%s) to %s\n",
			 Client_info.name,Client_info.addr,
			 lp_servicename(snum)));
	      ret = True;
	    }
	  else
	    if (snum >= 0)
	      DEBUG(0,("Denied connection from %s (%s) to %s\n",
		       Client_info.name,Client_info.addr,
		       lp_servicename(snum)));
	}
    }

  if (denyl) free(denyl);
  if (allowl) free(allowl);
  return(ret);
}


/* return true if access should be allowed */
BOOL allow_access(char *deny_list,char *allow_list,struct from_host *client)
{
  /* if theres no deny list and no allow list then allow access */
  if ((!deny_list || *deny_list == 0) && (!allow_list || *allow_list == 0))
    return(True);  

  /* if there is an allow list but no deny list then allow only hosts
     on the allow list */
  if (!deny_list || *deny_list == 0)
    return(list_match(allow_list,(char *)client,CLIENT_MATCH));

  /* if theres a deny list but no allow list then allow
     all hosts not on the deny list */
  if (!allow_list || *allow_list == 0)
    return(!list_match(deny_list,(char *)client,CLIENT_MATCH));

  /* if there are both type of list then allow all hosts on the allow list */
  if (list_match(allow_list,(char *)client,CLIENT_MATCH))
    return (True);

  /* if there are both type of list and it's not on the allow then
     allow it if its not on the deny */
  if (list_match(deny_list,(char *)client,CLIENT_MATCH))
    return (False);

  return (True);
}

/* list_match - match an item against a list of tokens with exceptions */
/* (All modifications are marked with the initials "jkf") */
static int list_match(char *list,char *item, int (*match_fn)())
{
    char   *tok;
    char   *listcopy;		/* jkf */
    int     match = NO;

    /*
     * jkf@soton.ac.uk -- 31 August 1994 -- Stop list_match()
     * overwriting the list given as its first parameter.
     */

    /* jkf -- can get called recursively with NULL list */
    listcopy = (list == 0) ? (char *)0 : strdup(list);

    /*
     * Process tokens one at a time. We have exhausted all possible matches
     * when we reach an "EXCEPT" token or the end of the list. If we do find
     * a match, look for an "EXCEPT" list and recurse to determine whether
     * the match is affected by any exceptions.
     */

    for (tok = strtok(listcopy, sep); tok ; tok = strtok(NULL, sep)) {
	if (strcasecmp(tok, "EXCEPT") == 0)	/* EXCEPT: give up */
	    break;
	if ((match = (*match_fn) (tok, item)))	/* YES or FAIL */
	    break;
    }
    /* Process exceptions to YES or FAIL matches. */

    if (match != NO) {
	while ((tok = strtok((char *) 0, sep)) && strcasecmp(tok, "EXCEPT"))
	     /* VOID */ ;
	if (tok == 0 || list_match((char *) 0, item, match_fn) == NO) {
	    if (listcopy != 0) free(listcopy); /* jkf */
	    return (match);
	}
    }

    if (listcopy != 0) free(listcopy); /* jkf */
    return (NO);
}


/* client_match - match host name and address against token */
static int client_match(char *tok,char *item)
{
    struct from_host *client = (struct from_host *) item;
    int     match;

    /*
     * Try to match the address first. If that fails, try to match the host
     * name if available.
     */

    if ((match = string_match(tok, client->addr)) == 0)
	if (client->name[0] != 0)
	    match = string_match(tok, client->name);
    return (match);
}

/* string_match - match string against token */
static int string_match(char *tok,char *s)
{
    int     tok_len;
    int     str_len;
    char   *cut;

    /*
     * Return YES if a token has the magic value "ALL". Return FAIL if the
     * token is "FAIL". If the token starts with a "." (domain name), return
     * YES if it matches the last fields of the string. If the token has the
     * magic value "LOCAL", return YES if the string does not contain a "."
     * character. If the token ends on a "." (network number), return YES if
     * it matches the first fields of the string. If the token begins with a
     * "@" (netgroup name), return YES if the string is a (host) member of
     * the netgroup. Return YES if the token fully matches the string. If the
     * token is a netnumber/netmask pair, return YES if the address is a
     * member of the specified subnet.
     */

    if (tok[0] == '.') {			/* domain: match last fields */
	if ((str_len = strlen(s)) > (tok_len = strlen(tok))
	    && strcasecmp(tok, s + str_len - tok_len) == 0)
	    return (YES);
    } else if (tok[0] == '@') {			/* netgroup: look it up */
#ifdef	NETGROUP
      static char *mydomain = NULL;
      char *hostname = NULL;
      BOOL netgroup_ok = False;

      if (!mydomain) yp_get_default_domain(&mydomain);

      if (!(hostname = strdup(s))) {
	DEBUG(1,("out of memory for strdup!\n"));
	return NO;
      }

      netgroup_ok = innetgr(tok + 1, hostname, (char *) 0, mydomain);

      DEBUG(5,("looking for %s of domain %s in netgroup %s gave %s\n", 
	       hostname,
	       mydomain, 
	       tok+1,
	       BOOLSTR(netgroup_ok)));

#ifdef NETGROUP_INSECURE
      /* if you really want netgroups that match non qualified names
	 then define NETGROUP_INSECURE. It can, however, be a big
	 security hole */
      {
	char        *clnt_domain;
	if (!netgroup_ok && (clnt_domain=strchr(hostname,'.'))) {
	  *clnt_domain++ = '\0';
	  netgroup_ok = innetgr(tok + 1, hostname, (char *) 0, mydomain);
	}
      }
#endif

      free(hostname);
      
      if (netgroup_ok) return(YES);
#else
      DEBUG(0,("access: netgroup support is not configured"));
      return (NO);
#endif
    } else if (strcasecmp(tok, "ALL") == 0) {	/* all: match any */
	return (YES);
    } else if (strcasecmp(tok, "FAIL") == 0) {	/* fail: match any */
	return (FAIL);
    } else if (strcasecmp(tok, "LOCAL") == 0) {	/* local: no dots */
	if (strchr(s, '.') == 0 && strcasecmp(s, "unknown") != 0)
	    return (YES);
    } else if (!strcasecmp(tok, s)) {	/* match host name or address */
	return (YES);
    } else if (tok[(tok_len = strlen(tok)) - 1] == '.') {	/* network */
	if (strncmp(tok, s, tok_len) == 0)
	    return (YES);
    } else if ((cut = strchr(tok, '/')) != 0) {	/* netnumber/netmask */
	if (isdigit(s[0]) && masked_match(tok, cut, s))
	    return (YES);
    }
    return (NO);
}

/* masked_match - match address against netnumber/netmask */
static int masked_match(char *tok, char *slash, char *s)
{
  uint32 net;
  uint32 mask;
  uint32 addr;

  if ((addr = interpret_addr(s)) == INADDR_NONE)
    return (NO);
  *slash = 0;
  net = interpret_addr(tok);
  *slash = '/';
  if (net == INADDR_NONE || (mask = interpret_addr(slash + 1)) == INADDR_NONE) {
    DEBUG(0,("access: bad net/mask access control: %s", tok));
    return (NO);
  }
  return ((addr & mask) == net);
}


/* fromhost - find out what is at the other end of a socket */
BOOL fromhost(int sock,struct from_host *f)
{
    static struct sockaddr sa;
    struct sockaddr_in *sockin = (struct sockaddr_in *) (&sa);
    struct hostent *hp;
    int     length = sizeof(sa);
    static char addr_buf[FROM_ADDRLEN];
    static char name_buf[MAXHOSTNAMELEN];
    BOOL   takeAddressAsHostname = False;

    if (getpeername(sock, &sa, &length) < 0) 
      {
	DEBUG(0,("getpeername failed\n"));
	return(False);
      }

    f->sin = sockin;
    f->addr = strcpy(addr_buf,(char *)inet_ntoa(sockin->sin_addr));

    /* Look up the remote host name. */
    if ((hp = gethostbyaddr((char *) &sockin->sin_addr,
			    sizeof(sockin->sin_addr),
			    AF_INET)) == 0) {
      DEBUG(1,("Gethostbyaddr failed for %s\n",addr_buf));
#ifdef ALLOW_PURE_ADDRESSES
      takeAddressAsHostname = True;
#else
      return(False);
#endif
    }

    /* Save the host name. A later gethostbyxxx() call may clobber it. */
    f->name = StrnCpy(name_buf,
                      takeAddressAsHostname? f->addr : hp->h_name,
                      sizeof(name_buf) - 1);

    /*
     * Verify that the host name does not belong to someone else. If host
     * name verification fails, pretend that the host name lookup failed.
     */
    if (!takeAddressAsHostname && !matchname(f->name, sockin->sin_addr))
      {
	DEBUG(0,("Matchname failed\n"));
	return(False);
      }

    return(True);	
}

/* matchname - determine if host name matches IP address */
static int matchname(char *remotehost,struct in_addr  addr)
{
  struct hostent *hp;
  int     i;
  
  if ((hp = Get_Hostbyname(remotehost)) == 0) {
    DEBUG(0,("Get_Hostbyname(%s): lookup failure", remotehost));
    return (Bad);
  } 

    /*
     * Make sure that gethostbyname() returns the "correct" host name.
     * Unfortunately, gethostbyname("localhost") sometimes yields
     * "localhost.domain". Since the latter host name comes from the
     * local DNS, we just have to trust it (all bets are off if the local
     * DNS is perverted). We always check the address list, though.
     */
  
  if (strcasecmp(remotehost, hp->h_name)
      && strcasecmp(remotehost, "localhost")) {
    DEBUG(0,("host name/name mismatch: %s != %s",
	  remotehost, hp->h_name));
    return (Bad);
  }
	
  /* Look up the host address in the address list we just got. */
  for (i = 0; hp->h_addr_list[i]; i++) {
    if (memcmp(hp->h_addr_list[i], (caddr_t) & addr, sizeof(addr)) == 0)
      return (Good);
  }

  /*
   * The host name does not map to the original host address. Perhaps
   * someone has compromised a name server. More likely someone botched
   * it, but that could be dangerous, too.
   */
  
  DEBUG(0,("host name/address mismatch: %s != %s",
	inet_ntoa(addr), hp->h_name));
  return (Bad);
}


