/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   NBT netbios routines and daemon - version 2
   Copyright (C) Andrew Tridgell 1994-1995
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
   
*/

#include "includes.h"
#include "loadparm.h"
#include "nameserv.h"


static void queue_packet(struct packet_struct *packet);
void process(void);
static void dump_names(void);
static void announce_request(char *group);
void sync_browse_lists(char *name,int name_type,char *myname,
		       char *domain,struct in_addr ip);

extern int DEBUGLEVEL;

extern pstring debugf;
pstring servicesf = CONFIGFILE;

extern pstring scope;

extern BOOL CanRecurse;

extern struct in_addr myip;
extern struct in_addr bcast_ip;
extern struct in_addr Netmask;
extern pstring myhostname;
static pstring host_file;
static pstring myname="";

static int ClientNMB= -1;
static int ClientDGRAM= -1;

static BOOL needannounce=True;

/* this is our name database */
static struct name_record *namelist = NULL;

/* list of servers to be returned by NetServerEnum */
static struct server_record *serverlist = NULL;

/* this is the domain list. For the moment we will assume that our
   primary domain is the first one listed in this list */
static struct domain_record *domainlist = NULL;

/* are we running as a daemon ? */
static BOOL is_daemon = False;

/* machine comment for host announcements */
static pstring ServerComment="";

static BOOL got_bcast = False;
static BOOL got_myip = False;
static BOOL got_nmask = False;

static BOOL updatedlists = False;
static int  updatecount=0;

/* what server type are we currently */
static int ServerType = 
SV_TYPE_WORKSTATION | SV_TYPE_SERVER | SV_TYPE_TIME_SOURCE |
SV_TYPE_SERVER_UNIX |
SV_TYPE_PRINTQ_SERVER | SV_TYPE_POTENTIAL_BROWSER;

/* here are my election parameters */

/* NTAS uses 2, NT uses 1, WfWg uses 0 */
#define MAINTAIN_LIST 1
#define ELECTION_VERSION 1

static BOOL RunningElection = False;
static BOOL needelection = False;
static int ElectionCount = 0;
static int StartupTime =0;


/* WfWg uses 01040b01 */
/* Win95 uses 01041501 */
/* NTAS uses ?? */
static uint32 ElectionCriterion = (MAINTAIN_LIST<<1)|(ELECTION_VERSION<<8);

/* we currently support being the master for just one group. Being the
   master for more than one group might be tricky as NetServerEnum is
   often asked for a list without naming the group */
static fstring PrimaryGroup="";

#define AM_MASTER (PrimaryGroup[0] && (ServerType & SV_TYPE_MASTER_BROWSER))

#define MSBROWSE "\001\002__MSBROWSE__\002"

#define GET_TTL(ttl) ((ttl)?MIN(ttl,lp_max_ttl()):lp_max_ttl())

#define BROWSE_MAILSLOT "\\MAILSLOT\\BROWSE"

/****************************************************************************
catch a sighup
****************************************************************************/
static int sig_hup()
{
  BlockSignals(True);

  DEBUG(0,("Got SIGHUP (reload not implemented)\n"));
  dump_names();
  reload_services(True);

  BlockSignals(False);
#ifndef DONT_REINSTALL_SIG
  signal(SIGHUP,SIGNAL_CAST sig_hup);
#endif
  return(0);
}

/****************************************************************************
catch a sigpipe
****************************************************************************/
static int sig_pipe()
{
  BlockSignals(True);

  DEBUG(0,("Got SIGPIPE\n"));
  if (!is_daemon)
    exit(1);
  BlockSignals(False);
  return(0);
}

#if DUMP_CORE
/*******************************************************************
prepare to dump a core file - carefully!
********************************************************************/
static BOOL dump_core(void)
{
  char *p;
  pstring dname;
  strcpy(dname,debugf);
  if ((p=strrchr(dname,'/'))) *p=0;
  strcat(dname,"/corefiles");
  mkdir(dname,0700);
  sys_chown(dname,getuid(),getgid());
  chmod(dname,0700);
  if (chdir(dname)) return(False);
  umask(~(0700));

#ifndef NO_GETRLIMIT
#ifdef RLIMIT_CORE
  {
    struct rlimit rlp;
    getrlimit(RLIMIT_CORE, &rlp);
    rlp.rlim_cur = MAX(4*1024*1024,rlp.rlim_cur);
    setrlimit(RLIMIT_CORE, &rlp);
    getrlimit(RLIMIT_CORE, &rlp);
    DEBUG(3,("Core limits now %d %d\n",rlp.rlim_cur,rlp.rlim_max));
  }
#endif
#endif


  DEBUG(0,("Dumping core in %s\n",dname));
  return(True);
}
#endif


/****************************************************************************
possibly continue after a fault
****************************************************************************/
static void fault_continue(void)
{
  static int errcount=1;

  errcount--;

  if (is_daemon && errcount)
    process();

#if DUMP_CORE
    if (dump_core()) return;
#endif

  return;
}


/*******************************************************************
  wrapper to get the DC
  ******************************************************************/
static char *domain_controller(void)
{
  char *dc = lp_domain_controller();
  /* so many people mistake this for a bool that we need to handle it. sigh. */
  if (!*dc || strequal(dc,"yes") || strequal(dc,"true"))
    strcpy(dc,myname);
  return(dc);
}



/****************************************************************************
  true if two netbios names are equal
****************************************************************************/
static BOOL name_equal(struct nmb_name *n1,struct nmb_name *n2)
{
  if (n1->name_type != n2->name_type) return(False);

  return(strequal(n1->name,n2->name) && strequal(n1->scope,n2->scope));
}

/****************************************************************************
  add a netbios name into the namelist
  **************************************************************************/
static void add_name(struct name_record *n)
{
  struct name_record *n2;

  if (!namelist) {
    namelist = n;
    n->prev = NULL;
    n->next = NULL;
    return;
  }

  for (n2 = namelist; n2->next; n2 = n2->next) ;

  n2->next = n;
  n->next = NULL;
  n->prev = n2;
}

/****************************************************************************
  add a domain into the list
  **************************************************************************/
static void add_domain(struct domain_record *d)
{
  struct domain_record *d2;

  if (!domainlist) {
    domainlist = d;
    d->prev = NULL;
    d->next = NULL;
    return;
  }

  for (d2 = domainlist; d2->next; d2 = d2->next) ;

  d2->next = d;
  d->next = NULL;
  d->prev = d2;
}


/****************************************************************************
  add a server into the list
  **************************************************************************/
static void add_server(struct server_record *s)
{
  struct server_record *s2;

  if (!serverlist) {
    serverlist = s;
    s->prev = NULL;
    s->next = NULL;
    return;
  }

  for (s2 = serverlist; s2->next; s2 = s2->next) ;

  s2->next = s;
  s->next = NULL;
  s->prev = s2;
}

/****************************************************************************
  remove a name from the namelist. The pointer must be an element just 
  retrieved
  **************************************************************************/
static void remove_name(struct name_record *n)
{
  struct name_record *nlist = namelist;
  while (nlist && nlist != n) nlist = nlist->next;
  if (nlist) {
    if (nlist->next) nlist->next->prev = nlist->prev;
    if (nlist->prev) nlist->prev->next = nlist->next;
    free(nlist);
  }
}

/****************************************************************************
  find a name in the namelist 
  **************************************************************************/
static struct name_record *find_name(struct nmb_name *n)
{
  struct name_record *ret;
  for (ret = namelist; ret; ret = ret->next)
    if (name_equal(&ret->name,n)) return(ret);

  return(NULL);
}

/****************************************************************************
  dump a copy of the name table
  **************************************************************************/
static void dump_names(void)
{
  time_t t = time(NULL);
  struct name_record *n;
  struct domain_record *d;

  DEBUG(3,("Dump of local name table:\n"));

  for (n = namelist; n; n = n->next) {
    DEBUG(3,("%s %s TTL=%d Unique=%s\n",
	     namestr(&n->name),
	     inet_ntoa(n->ip),
	     n->death_time?n->death_time-t:0,
	     BOOLSTR(n->unique)));
    }

  DEBUG(3,("\nDump of domain list:\n"));
  for (d = domainlist; d; d = d->next)
    DEBUG(3,("%s %s\n",d->name,inet_ntoa(d->bcast_ip)));
}


/****************************************************************************
  add a host entry to the name list
  ****************************************************************************/
static struct name_record *add_host_entry(char *name,int type,BOOL unique,int ttl,
					  enum name_source source,
					  struct in_addr ip)
{
  struct name_record *n;
  struct name_record *n2=NULL;

  n = (struct name_record *)malloc(sizeof(*n));
  if (!n) return(NULL);

  bzero((char *)n,sizeof(*n));

  make_nmb_name(&n->name,name,type,scope);
  if ((n2=find_name(&n->name))) {
    free(n);
    n = n2;
  }

  if (ttl) n->death_time = time(NULL)+ttl*3;
  n->ip = ip;
  n->unique = unique;
  n->source = source;
  
  if (!n2) add_name(n);

  DEBUG(3,("Added host entry %s at %s ttl=%d unique=%s\n",
	   namestr(&n->name),inet_ntoa(ip),ttl,BOOLSTR(unique)));

  return(n);
}


/****************************************************************************
  add a domain entry
  ****************************************************************************/
static struct domain_record *add_domain_entry(char *name,struct in_addr ip)
{
  struct domain_record *d;

  d = (struct domain_record *)malloc(sizeof(*d));

  if (!d) return(NULL);

  bzero((char *)d,sizeof(*d));

  if (zero_ip(ip)) ip = bcast_ip;

  StrnCpy(d->name,name,sizeof(d->name)-1);
  d->bcast_ip = ip;

  if (!PrimaryGroup[0] && ip_equal(bcast_ip,ip) && name[0] != '*') {
    strcpy(PrimaryGroup,name);
    strupper(PrimaryGroup);
    DEBUG(3,("Setting primary group to %s (%s)\n",PrimaryGroup,inet_ntoa(ip)));
  }

  add_domain(d);

  ip = *interpret_addr2("255.255.255.255");
  if (name[0] != '*') add_host_entry(name,0x1e,False,0,SELF,ip);	  

  DEBUG(3,("Added domain entry %s at %s\n",
	   name,inet_ntoa(ip)));

  return(d);
}

/****************************************************************************
  add a server entry
  ****************************************************************************/
struct server_record *add_server_entry(char *name,int servertype,
				       int ttl,char *comment,BOOL replace)
{
  BOOL newentry=False;
  struct server_record *s;

  for (s = serverlist; s; s = s->next)
    if (strequal(name,s->name)) break;

  if (s && !replace) {
    DEBUG(4,("Not replacing %s\n",name));
    return(s);
  }

  updatedlists=True;

  if (!s) {
    newentry = True;
    s = (struct server_record *)malloc(sizeof(*s));

    if (!s) return(NULL);

    bzero((char *)s,sizeof(*s));
  }

  /* update the entry */
  StrnCpy(s->name,name,sizeof(s->name)-1);
  StrnCpy(s->comment,comment,sizeof(s->comment)-1);
  s->servertype = servertype;
  s->death_time = ttl?time(NULL)+ttl*3:0;
  strupper(s->name);
  if (s->servertype & SV_TYPE_DOMAIN_ENUM) strupper(s->comment);

  if (!newentry) return(s);

  add_server(s);

  if (newentry) {
    DEBUG(3,("Added server entry %s of type %x (%s)\n",
	     name,servertype,comment));
  } else {
    DEBUG(3,("Updated server entry %s of type %x (%s)\n",
	     name,servertype,comment));
  }

  return(s);
}


/****************************************************************************
  add the magic samba names, useful for finding samba servers
  **************************************************************************/
static void add_my_names(void)
{
  struct in_addr ip;

  ip = *interpret_addr2("0.0.0.0");

  add_host_entry(myname,0x20,True,0,SELF,ip);
  add_host_entry(myname,0x0,True,0,SELF,ip);
  add_host_entry(myname,0x1f,True,0,SELF,ip); /* used for chat?? */
  add_host_entry(myname,0x3,True,0,SELF,ip); /* used for winpopup */
						
  if (!domainlist)
    add_domain_entry(lp_workgroup(),bcast_ip);
  add_server_entry(myname,
		   ServerType,
		   0,ServerComment,True);

  add_host_entry("__SAMBA__",0x20,True,0,SELF,ip);
  add_host_entry("__SAMBA__",0x0,True,0,SELF,ip);

  if (lp_preferred_master()) {
    DEBUG(3,("Preferred master startup\n"));
    needelection = True;
    ElectionCriterion |= (1<<3);
  }

  ElectionCriterion |= (lp_os_level() << 24);
}


/*******************************************************************
  write out browse.dat
  ******************************************************************/
static void write_browse_list(void)
{
  struct server_record *s;
  pstring fname,fnamenew;
  FILE *f;
  
  updatecount++;

  strcpy(fname,lp_lockdir());
  trim_string(fname,NULL,"/");
  strcat(fname,"/");
  strcat(fname,SERVER_LIST);
  strcpy(fnamenew,fname);
  strcat(fnamenew,".");
  
  f = fopen(fnamenew,"w");
  
  if (!f) {
    DEBUG(4,("Can't open %s - %s\n",fnamenew,strerror(errno)));
    return;
  }
  
  for (s=serverlist; s ; s = s->next) {
    /* don't list domains I don't have a master for */
    if ((s->servertype & SV_TYPE_DOMAIN_ENUM) && !s->comment[0]) continue;
	
    fprintf(f,"\"%s\"\t%08x\t\"%s\"\n",s->name,s->servertype,s->comment);
  }
  
  
  fclose(f);
  chmod(fnamenew,0644);
  /* unlink(fname); */
  rename(fnamenew,fname);   
  DEBUG(3,("Wrote browse list %s\n",fname));
}

/*******************************************************************
  expire old names in the namelist and serverlist
  ******************************************************************/
static void expire_names(void)
{
  static time_t lastrun=0;
  time_t t = time(NULL);
  struct name_record *n;
  struct name_record *next;
  struct server_record *s;
  struct server_record *nexts;

  if (!lastrun) lastrun = t;
  if (t < lastrun + 5) return;
  lastrun = t;

  /* expire old names */
  for (n = namelist; n; n = next) {
    if (n->death_time && n->death_time < t) {
      DEBUG(3,("Removing dead name %s\n",
	       namestr(&n->name)));
      next = n->next;
      if (n->prev) n->prev->next = n->next;
      if (n->next) n->next->prev = n->prev;
      if (namelist == n) namelist = n->next; 
      free(n);
    } else {
      next = n->next;
    }
  }

  /* expire old entries in the serverlist */
  for (s = serverlist; s; s = nexts) {
    if (s->death_time && s->death_time < t) {
      DEBUG(3,("Removing dead server %s\n",s->name));
      updatedlists = True;
      nexts = s->next;
      if (s->prev) s->prev->next = s->next;
      if (s->next) s->next->prev = s->prev;
      if (serverlist == s) serverlist = s->next; 
      free(s);
    } else {
      nexts = s->next;
    }
  }
}


/*******************************************************************
  delete old names from the namelist
  ******************************************************************/
static void housekeeping(void)
{
  time_t t = time(NULL);

  expire_names();

  /* write out the browse.dat database for smbd to get */
  if (updatedlists) {
    write_browse_list();
    updatedlists = False;
  }

  {
    /* occasionally check to see if the master browser is around */
    static time_t lastrun=0;
    if (!lastrun) lastrun = t;
    if (t < lastrun + 5*60) return;
    lastrun = t;

    if (!AM_MASTER && PrimaryGroup[0] &&
	!name_query(ClientNMB,PrimaryGroup,0x1d,True,False,
		    bcast_ip,NULL,queue_packet)) {
      DEBUG(2,("Forcing election on %s\n",PrimaryGroup));
      needelection = True;
    }
  }
}


/****************************************************************************
  reload the services file
  **************************************************************************/
BOOL reload_services(BOOL test)
{
  BOOL ret;
  extern fstring remote_machine;

  strcpy(remote_machine,"nmbd");

  if (lp_loaded())
    {
      pstring fname;
      strcpy(fname,lp_configfile());
      if (file_exist(fname,NULL) && !strcsequal(fname,servicesf))
	{
	  strcpy(servicesf,fname);
	  test = False;
	}
    }

  if (test && !lp_file_list_changed())
    return(True);

  ret = lp_load(servicesf,True);

  /* perhaps the config filename is now set */
  if (!test)
    reload_services(True);

  return(ret);
}



/****************************************************************************
load a netbios hosts file
****************************************************************************/
static void load_hosts_file(char *fname)
{
  FILE *f = fopen(fname,"r");
  pstring line;
  if (!f) {
    DEBUG(2,("Can't open lmhosts file %s\n",fname));
    return;
  }

  while (!feof(f))
    {
      if (!fgets_slash(line,sizeof(pstring),f)) continue;
      
      if (*line == '#') continue;

      {
	BOOL group=False;
	string ip,name,flags,extra;
	char *ptr;
	int count = 0;
	struct in_addr ipaddr;
	enum name_source source = LMHOSTS;

	*ip = *name = *flags = *extra = 0;

	ptr = line;

	if (next_token(&ptr,ip,NULL)) ++count;
	if (next_token(&ptr,name,NULL)) ++count;
	if (next_token(&ptr,flags,NULL)) ++count;
	if (next_token(&ptr,extra,NULL)) ++count;

	if (count <= 0) continue;

	if (count > 0 && count < 2)
	  {
	    DEBUG(0,("Ill formed hosts line [%s]\n",line));	    
	    continue;
	  }

	if (strchr(flags,'G') || strchr(flags,'S'))
	  group = True;

	if (strchr(flags,'M') && !group) {
	  source = SELF;
	  strcpy(myname,name);
	}

	ipaddr = *interpret_addr2(ip);

	if (group) {
	  add_domain_entry(name,ipaddr);
	} else {
	  add_host_entry(name,0x20,True,0,source,ipaddr);
	}
      }
    }

  fclose(f);
}

/*******************************************************************
  check if 2 IPs are on the same net
  we will assume the local netmask, although this could be wrong XXXX
  ******************************************************************/
static BOOL same_net(struct in_addr ip1,struct in_addr ip2)
{
  unsigned long net1,net2,nmask;

  nmask = ntohl(Netmask.s_addr);
  net1 = ntohl(ip1.s_addr);
  net2 = ntohl(ip2.s_addr);
	    
  return((net1 & nmask) == (net2 & nmask));
}

/****************************************************************************
  send an election packet
  **************************************************************************/
static void send_election(char *group,uint32 criterion,int timeup,char *name)
{
  pstring outbuf;
  char *p;

  DEBUG(2,("Sending election to %s for workgroup %s\n",
	   inet_ntoa(bcast_ip),group));	   

  bzero(outbuf,sizeof(outbuf));
  p = outbuf;
  CVAL(p,0) = 8; /* election */
  p++;

  CVAL(p,0) = ELECTION_VERSION;
  SIVAL(p,1,criterion);
  SIVAL(p,5,timeup*1000); /* ms - despite the spec */
  p += 13;
  strcpy(p,name);
  strupper(p);
  p = skip_string(p,1);

  send_mailslot_reply(BROWSE_MAILSLOT,ClientDGRAM,outbuf,PTR_DIFF(p,outbuf),
		      name,group,0,0x1e,bcast_ip,myip);
}


/****************************************************************************
  send a backup list response
  **************************************************************************/
static void send_backup_list(char *name,int token,struct nmb_name *to,
			     struct in_addr ip)
{
  pstring outbuf;
  char *p;

  DEBUG(2,("Sending backup list to %s for workgroup %s\n",
	   inet_ntoa(ip),PrimaryGroup));	   

  bzero(outbuf,sizeof(outbuf));
  p = outbuf;
  CVAL(p,0) = 10; /* backup list response */
  p++;

  CVAL(p,0) = 1; /* count */
  SIVAL(p,1,token);
  p += 5; 
  strcpy(p,name);
  strupper(p);
  p = skip_string(p,1) + 1;

  send_mailslot_reply(BROWSE_MAILSLOT,ClientDGRAM,outbuf,PTR_DIFF(p,outbuf),
		      myname,to->name,0,to->name_type,ip,myip);
}


/*******************************************************************
  become the master browser
  ******************************************************************/
static void become_master(void)
{
  uint32 domain_type = SV_TYPE_DOMAIN_ENUM | SV_TYPE_SERVER_UNIX;
  DEBUG(2,("Becoming master for %s\n",PrimaryGroup));

  ServerType |= SV_TYPE_MASTER_BROWSER;
  ServerType |= SV_TYPE_BACKUP_BROWSER;
  ElectionCriterion |= 0x5;

  add_host_entry(PrimaryGroup,0x1d,True,0,SELF,myip);
  add_host_entry(PrimaryGroup,0x0,False,0,SELF,myip);
  add_host_entry(MSBROWSE,1,False,0,SELF,myip);

  if (lp_domain_master()) {
    add_host_entry(myname,0x1b,True,0,SELF,myip);
    add_host_entry(PrimaryGroup,0x1b,True,0,SELF,myip);
    add_host_entry(PrimaryGroup,0x1c,False,0,SELF,myip);
    ServerType |= SV_TYPE_DOMAIN_MASTER;
    if (lp_domain_logons()) {
      ServerType |= SV_TYPE_DOMAIN_CTRL;
      ServerType |= SV_TYPE_DOMAIN_MEMBER;
      domain_type |= SV_TYPE_DOMAIN_CTRL;
    }
  }

  add_server_entry(PrimaryGroup,domain_type,0,myname,True);
  add_server_entry(myname,ServerType,0,ServerComment,True);

  announce_request(PrimaryGroup);

  needannounce = True;
}


/*******************************************************************
  unbecome the master browser
  ******************************************************************/
static void become_nonmaster(void)
{
  struct name_record *n;
  struct nmb_name nn;

  DEBUG(2,("Becoming non-master for %s\n",PrimaryGroup));

  ServerType &= ~SV_TYPE_MASTER_BROWSER;
  ServerType &= ~SV_TYPE_DOMAIN_CTRL;
  ServerType &= ~SV_TYPE_DOMAIN_MASTER;

  ElectionCriterion &= ~0x4;

  make_nmb_name(&nn,PrimaryGroup,0x1d,scope);
  n = find_name(&nn);
  if (n && n->source == SELF) remove_name(n);

  make_nmb_name(&nn,PrimaryGroup,0x1b,scope);
  n = find_name(&nn);
  if (n && n->source == SELF) remove_name(n);

  make_nmb_name(&nn,MSBROWSE,1,scope);
  n = find_name(&nn);
  if (n && n->source == SELF) remove_name(n);
}


/*******************************************************************
  run the election
  ******************************************************************/
static void run_election(void)
{
  time_t t = time(NULL);
  static time_t lastime = 0;

  if (!PrimaryGroup[0] || !RunningElection) return;

  /* send election packets once a second */
  if (lastime &&
      t-lastime <= 0) return;

  lastime = t;

  send_election(PrimaryGroup,ElectionCriterion,t-StartupTime,myname);

  if (ElectionCount++ < 4) return;
   
  /* I won! now what :-) */
  RunningElection = False;
  DEBUG(2,(">>> Won election on %s <<<\n",PrimaryGroup));
  become_master();
}


/****************************************************************************
  construct a host announcement unicast
  **************************************************************************/
static void announce_host(struct domain_record *d,char *my_name,char *comment)
{
  time_t t = time(NULL);
  pstring outbuf;
  char *p;
  char *namep;
  char *stypep;
  char *commentp;
  uint32 stype = ServerType;

  if (needannounce) {
    /* drop back to a max 3 minute announce - this is to prevent a
       single lost packet from stuffing things up for too long */
    d->announce_interval = MIN(d->announce_interval,3*60);
    d->lastannounce_time = t - (d->announce_interval+1);
  }

  /* announce every minute at first then progress to every 12 mins */
  if (d->lastannounce_time && 
      (t - d->lastannounce_time) < d->announce_interval)
    return;

  if (d->announce_interval < 12*60) d->announce_interval += 60;
  d->lastannounce_time = t;

  DEBUG(2,("Sending announcement to %s for workgroup %s\n",
	   inet_ntoa(d->bcast_ip),d->name));

  if (!strequal(PrimaryGroup,d->name) ||
      !ip_equal(bcast_ip,d->bcast_ip)) {
    stype &= ~(SV_TYPE_POTENTIAL_BROWSER | SV_TYPE_MASTER_BROWSER |
	       SV_TYPE_DOMAIN_MASTER | SV_TYPE_BACKUP_BROWSER |
	       SV_TYPE_DOMAIN_CTRL | SV_TYPE_DOMAIN_MEMBER);
  }

  if (!*comment) comment = "NoComment";
  if (!*my_name) my_name = "NoName";

  if (strlen(comment) > 43) comment[43] = 0;  

  bzero(outbuf,sizeof(outbuf));
  CVAL(outbuf,0) = 1; /* host announce */
  p = outbuf+1;

  CVAL(p,0) = updatecount;
  SIVAL(p,1,d->announce_interval*1000); /* ms - despite the spec */
  namep = p+5;
  StrnCpy(p+5,my_name,16);
  strupper(p+5);
  CVAL(p,21) = 2; /* major version */
  CVAL(p,22) = 2; /* minor version */
  stypep = p+23;
  SIVAL(p,23,stype);
  SSVAL(p,27,0xaa55); /* browse signature */
  SSVAL(p,29,1); /* browse version */
  commentp = p+31;
  strcpy(p+31,comment);
  p += 31;
  p = skip_string(p,1);

  send_mailslot_reply(BROWSE_MAILSLOT,ClientDGRAM,outbuf,PTR_DIFF(p,outbuf),
		      my_name,d->name,0,0x1d,d->bcast_ip,myip);

  /* if I'm the master then I also need to do a local master and
     domain announcement */

  if (AM_MASTER &&
      strequal(d->name,PrimaryGroup) &&
      ip_equal(bcast_ip,d->bcast_ip)) {

    /* do master announcements as well */
    SIVAL(stypep,0,ServerType);

    CVAL(outbuf,0) = 15; /* local master announce */
    send_mailslot_reply(BROWSE_MAILSLOT,ClientDGRAM,outbuf,PTR_DIFF(p,outbuf),
			my_name,PrimaryGroup,0,0x1e,d->bcast_ip,myip);

    CVAL(outbuf,0) = 12; /* domain announce */
    StrnCpy(namep,PrimaryGroup,15);
    strupper(namep);
    StrnCpy(commentp,myname,15);
    strupper(commentp);
    SIVAL(stypep,0,(unsigned)0x80000000);
    p = commentp + strlen(commentp) + 1;

    send_mailslot_reply(BROWSE_MAILSLOT,ClientDGRAM,outbuf,PTR_DIFF(p,outbuf),
			my_name,MSBROWSE,0,1,d->bcast_ip,myip);
  }
}


/****************************************************************************
  send a announce request to the local net
  **************************************************************************/
static void announce_request(char *group)
{
  pstring outbuf;
  char *p;

  DEBUG(2,("Sending announce request to %s for workgroup %s\n",
	   inet_ntoa(bcast_ip),group));

  bzero(outbuf,sizeof(outbuf));
  p = outbuf;
  CVAL(p,0) = 2; /* announce request */
  p++;

  CVAL(p,0) = 0; /* flags?? */
  p++;
  StrnCpy(p,myname,16);
  strupper(p);
  p = skip_string(p,1);

  send_mailslot_reply(BROWSE_MAILSLOT,ClientDGRAM,outbuf,PTR_DIFF(p,outbuf),
		      myname,group,0,0,bcast_ip,myip);
}

/****************************************************************************
  announce myself as a master to the PDC
  **************************************************************************/
static void announce_master(char *group)
{
  static time_t last=0;
  time_t t = time(NULL);
  pstring outbuf;
  char *p;
  struct in_addr ip,pdc_ip;
  fstring pdcname;
  *pdcname = 0;

  if (strequal(domain_controller(),myname)) return;

  if (!AM_MASTER || (last && (t-last < 10*60))) return;
  last = t;

  ip = *interpret_addr2(domain_controller());

  if (zero_ip(ip)) ip = bcast_ip;

  if (!name_query(ClientNMB,PrimaryGroup,
		  0x1b,False,False,ip,&pdc_ip,queue_packet)) {
    DEBUG(2,("Failed to find PDC at %s\n",domain_controller()));
    return;
  }

  name_status(ClientNMB,PrimaryGroup,0x1b,False,
	      pdc_ip,NULL,pdcname,queue_packet);

  if (!pdcname[0]) {
    DEBUG(3,("Can't find netbios name of PDC at %s\n",inet_ntoa(pdc_ip)));
  } else {
    sync_browse_lists(pdcname,0x20,myname,PrimaryGroup,pdc_ip);
  }


  DEBUG(2,("Sending master announce to %s for workgroup %s\n",
	   inet_ntoa(pdc_ip),group));

  bzero(outbuf,sizeof(outbuf));
  p = outbuf;
  CVAL(p,0) = 13; /* announce request */
  p++;

  StrnCpy(p,myname,16);
  strupper(p);
  p = skip_string(p,1);

  send_mailslot_reply(BROWSE_MAILSLOT,ClientDGRAM,outbuf,PTR_DIFF(p,outbuf),
		      myname,PrimaryGroup,0x1b,0,pdc_ip,myip);
}


/*******************************************************************
  am I listening on a name. Should check name_type as well 

  This is primarily used to prevent us gathering server lists from
  other workgroups we aren't a part of
  ******************************************************************/
static BOOL listening(struct nmb_name *n)
{
  if (!strequal(n->scope,scope)) return(False);

  if (strequal(n->name,myname) ||
      strequal(n->name,PrimaryGroup) ||
      strequal(n->name,MSBROWSE))
    return(True);

  return(False);
}


/*******************************************************************
  process a domain announcement frame

  Announce frames come in 3 types. Servers send host announcements
  (command=1) to let the master browswer know they are
  available. Master browsers send local master announcements
  (command=15) to let other masters and backups that they are the
  master. They also send domain announcements (command=12) to register
  the domain

  The comment field of domain announcements contains the master
  browser name. The servertype is used by NetServerEnum to select
  resources. We just have to pass it to smbd (via browser.dat) and let
  the client choose using bit masks.
  ******************************************************************/
static void process_announce(struct packet_struct *p,int command,char *buf)
{
  struct dgram_packet *dgram = &p->packet.dgram;
  int update_count = CVAL(buf,0);
  int ttl = IVAL(buf,1)/1000;
  char *name = buf+5;
  int osmajor=CVAL(buf,21);
  int osminor=CVAL(buf,22);
  uint32 servertype = IVAL(buf,23);
  char *comment = buf+31;

  name[15] = 0;  
  comment[43] = 0;
  
  DEBUG(3,("Announce(%d) %s count=%d ttl=%d OS=(%d,%d) type=%08x comment=%s\n",
	   command,name,update_count,ttl,osmajor,osminor,
	   servertype,comment));

  if (strequal(dgram->source_name.name,myname)) return;

  if (!listening(&dgram->dest_name)) return;

  ttl = GET_TTL(ttl);

  /* add them to our browse list */
  add_server_entry(name,servertype,ttl,comment,True);

}

/*******************************************************************
  process a master announcement frame
  ******************************************************************/
static void process_master_announce(struct packet_struct *p,char *buf)
{
  struct dgram_packet *dgram = &p->packet.dgram;
  char *name = buf;

  name[15] = 0;
  
  DEBUG(3,("Master Announce from %s (%s)\n",name,inet_ntoa(p->ip)));

  if (strequal(dgram->source_name.name,myname)) return;

  if (!AM_MASTER || !listening(&dgram->dest_name)) return;

  /* merge browse lists with them */
  if (lp_domain_master())
    sync_browse_lists(name,0x20,myname,PrimaryGroup,p->ip);
}


/*******************************************************************
  process a backup list request

  A client send a backup list request to ask for a list of servers on
  the net that maintain server lists for a domain. A server is then
  chosen from this list to send NetServerEnum commands to to list
  available servers.

  Currently samba only sends back one name in the backup list, its
  wn. For larger nets we'll have to add backups and send "become
  backup" requests occasionally.
  ******************************************************************/
static void process_backup_list(struct packet_struct *p,char *buf)
{
  struct dgram_packet *dgram = &p->packet.dgram;
  int count = CVAL(buf,0);
  int token = IVAL(buf,1);
  
  DEBUG(3,("Backup request to %s token=%d\n",
	   namestr(&dgram->dest_name),
	   token));

  if (strequal(dgram->source_name.name,myname)) return;

  if (count <= 0) return;

  if (!AM_MASTER || 
      !strequal(PrimaryGroup,dgram->dest_name.name))
    return;

  if (!listening(&dgram->dest_name)) return;

  send_backup_list(myname,token,
		   &dgram->source_name,
		   p->ip);
}


/*******************************************************************
  work out if I win an election
  ******************************************************************/
static BOOL win_election(int version,uint32 criterion,int timeup,char *name)
{  
  time_t t = time(NULL);
  uint32 mycriterion;
  if (version > ELECTION_VERSION) return(False);
  if (version < ELECTION_VERSION) return(True);
  
  mycriterion = ElectionCriterion;

  if (criterion > mycriterion) return(False);
  if (criterion < mycriterion) return(True);

  if (timeup > (t - StartupTime)) return(False);
  if (timeup < (t - StartupTime)) return(True);

  if (strcasecmp(myname,name) > 0) return(False);
  
  return(True);
}


/*******************************************************************
  process a election packet

  An election dynamically decides who will be the master. 
  ******************************************************************/
static void process_election(struct packet_struct *p,char *buf)
{
  struct dgram_packet *dgram = &p->packet.dgram;
  int version = CVAL(buf,0);
  uint32 criterion = IVAL(buf,1);
  int timeup = IVAL(buf,5)/1000;
  char *name = buf+13;

  name[15] = 0;  
  
  DEBUG(3,("Election request from %s vers=%d criterion=%08x timeup=%d\n",
	   name,version,criterion,timeup));

  if (strequal(dgram->source_name.name,myname)) return;

  if (!listening(&dgram->dest_name)) return;

  if (win_election(version,criterion,timeup,name)) {
    if (!RunningElection) {
      needelection = True;
      ElectionCount=0;
    }
  } else {
    needelection = False;
    if (RunningElection) {
      RunningElection = False;
      DEBUG(3,(">>> Lost election on %s <<<\n",PrimaryGroup));

      /* if we are the master then remove our masterly names */
      if (AM_MASTER)
	become_nonmaster();
    }
  }
}


/*******************************************************************
  process a announcement request

  clients send these when they want everyone to send an announcement
  immediately. This can cause quite a storm of packets!
  ******************************************************************/
static void process_announce_request(struct packet_struct *p,char *buf)
{
  struct dgram_packet *dgram = &p->packet.dgram;
  int flags = CVAL(buf,0);
  char *name = buf+1;

  name[15] = 0;

  DEBUG(3,("Announce request from %s flags=0x%X\n",name,flags));

  if (strequal(dgram->source_name.name,myname)) return;

  needannounce = True;
}


/****************************************************************************
process a browse frame
****************************************************************************/
static void process_browse_packet(struct packet_struct *p,char *buf,int len)
{
  int command = CVAL(buf,0);
  switch (command) 
    {
    case 1: /* host announce */
    case 12: /* domain announce */
    case 15: /* local master announce */
      process_announce(p,command,buf+1);
      break;

    case 2: /* announce request */
      process_announce_request(p,buf+1);
      break;

    case 8: /* election */
      process_election(p,buf+1);
      break;

    case 9: /* get backup list */
      process_backup_list(p,buf+1);
      break;

    case 13: /* master announcement */
      process_master_announce(p,buf+1);
      break;
    }
}


/****************************************************************************
  process a domain logon packet
  **************************************************************************/
static void process_logon_packet(struct packet_struct *p,char *buf,int len)
{
  char *logname,*q;
  pstring outbuf;
  struct dgram_packet *dgram = &p->packet.dgram;
  int code;

  if (!lp_domain_logons()) {
    DEBUG(3,("No domain logons\n"));
    return;
  }
  if (!listening(&dgram->dest_name)) {
    DEBUG(4,("Not listening to that domain\n"));
    return;
  }

  q = outbuf;
  bzero(outbuf,sizeof(outbuf));

  code = SVAL(buf,0);
  switch (code) {
  case 0:    
    {
      char *machine = buf+2;
      char *user = skip_string(machine,1);
      logname = skip_string(user,1);

      SSVAL(q,0,6);
      q += 2;
      strcpy(q,"\\\\");
      q += 2;
      StrnCpy(q,myname,16);
      strupper(q);
      q = skip_string(q,1);
      SSVAL(q,0,0xFFFF);
      q += 2;

      DEBUG(3,("Domain login request from %s(%s) user=%s\n",
	       machine,inet_ntoa(p->ip),user));
    }
    break;
  case 7:    
    {
      char *machine = buf+2;
      logname = skip_string(machine,1);

      SSVAL(q,0,0xc);
      q += 2;
      StrnCpy(q,domain_controller(),16);
      strupper(q);
      q = skip_string(q,1);
      q += PutUniCode(q,domain_controller());
      q += PutUniCode(q,dgram->dest_name.name);
      SSVAL(q,0,0xFFFF);
      q += 2;

      DEBUG(3,("GETDC request from %s(%s)\n",
	       machine,inet_ntoa(p->ip)));
    }
    break;
  default:
    DEBUG(3,("Unknown domain request %d\n",code));
    return;
  }


  send_mailslot_reply(logname,ClientDGRAM,outbuf,PTR_DIFF(q,outbuf),
		      myname,&dgram->source_name.name[0],0,0,p->ip,myip);  
}

/****************************************************************************
process udp 138 datagrams
****************************************************************************/
static void process_dgram(struct packet_struct *p)
{
  char *buf;
  char *buf2;
  int len;
  struct dgram_packet *dgram = &p->packet.dgram;

  if (dgram->header.msg_type != 0x10 &&
      dgram->header.msg_type != 0x11 &&
      dgram->header.msg_type != 0x12) {
    /* don't process error packets etc yet */
    return;
  }

  buf = &dgram->data[0];
  buf -= 4; /* XXXX for the pseudo tcp length - 
	       someday I need to get rid of this */

  if (CVAL(buf,smb_com) != SMBtrans) return;

  len = SVAL(buf,smb_vwv11);
  buf2 = smb_base(buf) + SVAL(buf,smb_vwv12);

  DEBUG(3,("datagram from %s to %s for %s of type %d len=%d\n",
	   namestr(&dgram->source_name),namestr(&dgram->dest_name),
	   smb_buf(buf),CVAL(buf2,0),len));

  if (len <= 0) return;

  if (strequal(smb_buf(buf),"\\MAILSLOT\\BROWSE")) {
    process_browse_packet(p,buf2,len);
  } else if (strequal(smb_buf(buf),"\\MAILSLOT\\NET\\NETLOGON")) {
    process_logon_packet(p,buf2,len);
  }

}

/*******************************************************************
  find a workgroup using the specified broadcast
  ******************************************************************/
static BOOL find_workgroup(char *name,struct in_addr ip)
{
  fstring name1;
  BOOL ret;
  struct in_addr ipout;

  strcpy(name1,MSBROWSE);

  ret = name_query(ClientNMB,name1,0x1,True,False,ip,&ipout,queue_packet);
  if (!ret) return(False);

  name_status(ClientNMB,name1,0x1,False,ipout,name,NULL,queue_packet);

  if (name[0] != '*') {
    DEBUG(2,("Found workgroup %s on broadcast %s\n",name,inet_ntoa(ip)));
  } else {
    DEBUG(3,("Failed to find workgroup %s on broadcast %s\n",name,inet_ntoa(ip)));
  }
  return(name[0] != '*');
}


/****************************************************************************
  a hook for announce handling - called every minute
  **************************************************************************/
static void do_announcements(void)
{
  struct domain_record *d;

  for (d = domainlist; d; d = d->next) {
    /* if the ip address is 0 then set to the broadcast */
    if (zero_ip(d->bcast_ip)) d->bcast_ip = bcast_ip;

    /* if the workgroup is '*' then find a workgroup to be part of */
    if (d->name[0] == '*') {
      if (!find_workgroup(d->name,d->bcast_ip)) continue;
      add_host_entry(d->name,0x1e,False,0,SELF,
		     *interpret_addr2("255.255.255.255"));
      if (!PrimaryGroup[0] && ip_equal(bcast_ip,d->bcast_ip)) {
	strcpy(PrimaryGroup,d->name);
	strupper(PrimaryGroup);
      }
    }

    announce_host(d,myname,ServerComment);
  }

  /* if I have a domain controller then announce to it */
  if (AM_MASTER)
    announce_master(PrimaryGroup);

  needannounce=False;
}

/*******************************************************************
  check if someone still owns a name
  ******************************************************************/
static BOOL confirm_name(struct name_record *n)
{
  struct in_addr ipout;
  BOOL ret = name_query(ClientNMB,n->name.name,
			n->name.name_type,False,
			False,n->ip,&ipout,queue_packet);
  return(ret && ip_equal(ipout,n->ip));
}

/****************************************************************************
reply to a name release
****************************************************************************/
static void reply_name_release(struct packet_struct *p)
{
  struct nmb_packet *nmb = &p->packet.nmb;
  struct packet_struct p2;
  struct nmb_packet *nmb2;
  struct res_rec answer_rec;
  struct in_addr ip;
  int rcode=0;
  int nb_flags = nmb->additional->rdata[0];
  BOOL bcast = nmb->header.nm_flags.bcast;
  

  putip((char *)&ip,&nmb->additional->rdata[2]);  

  {
    struct name_record *n = find_name(&nmb->question.question_name);
    if (n && n->unique && n->source == REGISTER &&
	ip_equal(ip,n->ip)) {
      remove_name(n); n = NULL;
    }

    /* XXXX under what conditions should we reject the removal?? */
  }

  DEBUG(3,("Name release on name %s rcode=%d\n",
	   namestr(&nmb->question.question_name),rcode));

  if (bcast) return;

  /* Send a NAME RELEASE RESPONSE */
  p2 = *p;
  nmb2 = &p2.packet.nmb;

  nmb2->header.response = True;
  nmb2->header.nm_flags.bcast = False;
  nmb2->header.nm_flags.recursion_available = CanRecurse;
  nmb2->header.nm_flags.trunc = False;
  nmb2->header.nm_flags.authoritative = True; 
  nmb2->header.qdcount = 0;
  nmb2->header.ancount = 1;
  nmb2->header.nscount = 0;
  nmb2->header.arcount = 0;
  nmb2->header.rcode = rcode;

  nmb2->answers = &answer_rec;
  bzero((char *)nmb2->answers,sizeof(*nmb2->answers));
  
  nmb2->answers->rr_name = nmb->question.question_name;
  nmb2->answers->rr_type = nmb->question.question_type;
  nmb2->answers->rr_class = nmb->question.question_class;
  nmb2->answers->ttl = 0; 
  nmb2->answers->rdlength = 6;
  nmb2->answers->rdata[0] = nb_flags;
  putip(&nmb2->answers->rdata[2],(char *)&ip);

  send_packet(&p2);
}

/****************************************************************************
  reply to a reg request
  **************************************************************************/
static void reply_name_reg(struct packet_struct *p)
{
  struct nmb_packet *nmb = &p->packet.nmb;
  char *qname = nmb->question.question_name.name;
  BOOL wildcard = (qname[0] == '*'); 
  BOOL bcast = nmb->header.nm_flags.bcast;
  int ttl = GET_TTL(nmb->additional->ttl);
  int name_type = nmb->question.question_name.name_type;
  int nb_flags = nmb->additional->rdata[0];
  struct packet_struct p2;
  struct nmb_packet *nmb2;
  struct res_rec answer_rec;
  struct in_addr ip;
  BOOL group = (nb_flags&0x80)?True:False;
  int rcode = 0;  

  if (wildcard) return;

  putip((char *)&ip,&nmb->additional->rdata[2]);

  if (group) {
    /* apparently we should return 255.255.255.255 for group queries (email from MS) */
    ip = *interpret_addr2("255.255.255.255");
  }

  {
    struct name_record *n = find_name(&nmb->question.question_name);

    if (n) {
      if (!group && !ip_equal(ip,n->ip)) {
	/* check if the previous owner still wants it, 
	   if so reject the registration, otherwise change the owner 
	   and refresh */
	if (n->source != REGISTER || confirm_name(n)) {
	  rcode = 6;
	} else {
	  n->ip = ip;
	  n->death_time = ttl?p->timestamp+ttl*3:0;
	  DEBUG(3,("%s changed owner to %s\n",
		   namestr(&n->name),inet_ntoa(n->ip)));
	}
      } else {
	/* refresh the name */
	if (n->source != SELF)
	  n->death_time = ttl?p->timestamp + ttl*3:0;
      }
    } else {
      /* add the name to our database */
      n = add_host_entry(qname,name_type,!group,ttl,REGISTER,ip);
    }
  }

  if (bcast) return;

  DEBUG(3,("Name registration for name %s at %s rcode=%d\n",
	   namestr(&nmb->question.question_name),
	   inet_ntoa(ip),rcode));

  /* Send a NAME REGISTRATION RESPONSE */
  /* a lot of fields get copied from the query. This gives us the IP
     and port the reply will be sent to etc */
  p2 = *p;
  nmb2 = &p2.packet.nmb;

  nmb2->header.opcode = 5; 
  nmb2->header.response = True;
  nmb2->header.nm_flags.bcast = False;
  nmb2->header.nm_flags.recursion_available = CanRecurse;
  nmb2->header.nm_flags.trunc = False;
  nmb2->header.nm_flags.authoritative = True; 
  nmb2->header.qdcount = 0;
  nmb2->header.ancount = 1;
  nmb2->header.nscount = 0;
  nmb2->header.arcount = 0;
  nmb2->header.rcode = rcode;

  nmb2->answers = &answer_rec;
  bzero((char *)nmb2->answers,sizeof(*nmb2->answers));
  
  nmb2->answers->rr_name = nmb->question.question_name;
  nmb2->answers->rr_type = nmb->question.question_type;
  nmb2->answers->rr_class = nmb->question.question_class;

  nmb2->answers->ttl = ttl; 
  nmb2->answers->rdlength = 6;
  nmb2->answers->rdata[0] = nb_flags;
  putip(&nmb2->answers->rdata[2],(char *)&ip);

  send_packet(&p2);  
}


/****************************************************************************
reply to a name status query
****************************************************************************/
static void reply_name_status(struct packet_struct *p)
{
  struct nmb_packet *nmb = &p->packet.nmb;
  char *qname = nmb->question.question_name.name;
  BOOL wildcard = (qname[0] == '*'); 
  struct packet_struct p2;
  struct nmb_packet *nmb2;
  struct res_rec answer_rec;
  char *buf;
  int count;
  int rcode = 0;
  struct name_record *n = find_name(&nmb->question.question_name);

  DEBUG(3,("Name status for name %s\n",
	   namestr(&nmb->question.question_name)));

  if (!wildcard && (!n || n->source != SELF)) 
    return;

  /* Send a POSITIVE NAME STATUS RESPONSE */
  /* a lot of fields get copied from the query. This gives us the IP
     and port the reply will be sent to etc */
  p2 = *p;
  nmb2 = &p2.packet.nmb;

  nmb2->header.response = True;
  nmb2->header.nm_flags.bcast = False;
  nmb2->header.nm_flags.recursion_available = CanRecurse;
  nmb2->header.nm_flags.trunc = False;
  nmb2->header.nm_flags.authoritative = True; /* WfWg ignores 
						 non-authoritative answers */
  nmb2->header.qdcount = 0;
  nmb2->header.ancount = 1;
  nmb2->header.nscount = 0;
  nmb2->header.arcount = 0;
  nmb2->header.rcode = rcode;

  nmb2->answers = &answer_rec;
  bzero((char *)nmb2->answers,sizeof(*nmb2->answers));
  

  nmb2->answers->rr_name = nmb->question.question_name;
  nmb2->answers->rr_type = nmb->question.question_type;
  nmb2->answers->rr_class = nmb->question.question_class;
  nmb2->answers->ttl = 0; 

  for (count=0, n = namelist ; n; n = n->next) {
    if (n->source != SELF) continue;
    count++;
  }

  count = MIN(count,400/18); /* XXXX hack, we should calculate exactly
				how many will fit */

  
  buf = &nmb2->answers->rdata[0];
  SCVAL(buf,0,count);
  buf += 1;

  for (n = namelist ; n; n = n->next) 
    {
      if (n->source != SELF) continue;

      bzero(buf,18);
      strcpy(buf,n->name.name);
      strupper(buf);
      buf[15] = n->name.name_type;
      buf += 16;
      buf[0] = 0x4; /* active */
      if (!n->unique) buf[0] |= 0x80; /* group */
      buf += 2;
      count--;
    }

  /* XXXXXXX we should fill in more fields of the statistics structure */
  bzero(buf,64);
  {
    extern int num_good_sends,num_good_receives;
    SIVAL(buf,20,num_good_sends);
    SIVAL(buf,24,num_good_receives);
  }
  SIVAL(buf,46,0xFFB8E5); /* undocumented - used by NT */

  buf += 64;

  nmb2->answers->rdlength = PTR_DIFF(buf,&nmb2->answers->rdata[0]);

  send_packet(&p2);
}



/****************************************************************************
reply to a name query
****************************************************************************/
static void reply_name_query(struct packet_struct *p)
{
  struct nmb_packet *nmb = &p->packet.nmb;
  char *qname = nmb->question.question_name.name;
  BOOL wildcard = (qname[0] == '*'); 
  BOOL bcast = nmb->header.nm_flags.bcast;
  struct in_addr retip;
  int name_type = nmb->question.question_name.name_type;
  struct packet_struct p2;
  struct nmb_packet *nmb2;
  struct res_rec answer_rec;
  int ttl=0;
  int rcode=0;
  BOOL unique = True;

  DEBUG(3,("Name query for %s from %s (bcast=%s) - ",
	   namestr(&nmb->question.question_name),
	   inet_ntoa(p->ip),
	   BOOLSTR(bcast)));

  if (wildcard)
    retip = myip;

  if (!wildcard) {
    struct name_record *n = find_name(&nmb->question.question_name);

    if (!n) {
      struct in_addr ip;
      unsigned long a;

      /* only do DNS lookups if the query is for type 0x20 or type 0x0 */
      if (name_type != 0x20 && name_type != 0) {
	DEBUG(3,("not found\n"));
	return;
      }

      /* look it up with DNS */      
      a = interpret_addr(qname);

      putip((char *)&ip,(char *)&a);

      if (!a) {
	/* no luck with DNS. We could possibly recurse here XXXX */
	/* if this isn't a bcast then we should send a negative reply XXXX */
	DEBUG(3,("no recursion\n"));
	add_host_entry(qname,name_type,True,60*60,DNSFAIL,ip);
	return;
      }

      /* add it to our cache of names. give it 2 hours in the cache */
      n = add_host_entry(qname,name_type,True,2*60*60,DNS,ip);

      /* failed to add it? yikes! */
      if (!n) return;
    }

    /* don't respond to bcast queries for group names unless we own them */
    if (bcast && !n->unique && !n->source == SELF) {
      DEBUG(3,("no bcast replies\n"));
      return;
    }

    /* don't respond to bcast queries for addresses on the same net as the 
       machine doing the querying unless its our IP */
    if (bcast && 
	n->source != SELF && 
	same_net(n->ip,p->ip)) {
      DEBUG(3,("same net\n"));      
      return;
    }

    /* is our entry already dead? */
    if (n->death_time) {
      if (n->death_time < p->timestamp) return;
      ttl = n->death_time - p->timestamp;
    }

    retip = n->ip;
    unique = n->unique;

    /* it may have been an earlier failure */
    if (n->source == DNSFAIL) {
      DEBUG(3,("DNSFAIL\n"));
      return;
    }
  }

  /* if the IP is 0 then substitute my IP - we should see which one is on the 
     right interface for the caller to do this right XXX */
  if (zero_ip(retip)) retip = myip;
  
  DEBUG(3,("OK %s rcode=%d\n",inet_ntoa(retip),rcode));      

  /* a lot of fields get copied from the query. This gives us the IP
     and port the reply will be sent to etc */
  p2 = *p;
  nmb2 = &p2.packet.nmb;

  nmb2->header.response = True;
  nmb2->header.nm_flags.bcast = False;
  nmb2->header.nm_flags.recursion_available = CanRecurse;
  nmb2->header.nm_flags.trunc = False;
  nmb2->header.nm_flags.authoritative = True; /* WfWg ignores 
						 non-authoritative answers */
  nmb2->header.qdcount = 0;
  nmb2->header.ancount = 1;
  nmb2->header.nscount = 0;
  nmb2->header.arcount = 0;
  nmb2->header.rcode = rcode;

  nmb2->answers = &answer_rec;
  bzero((char *)nmb2->answers,sizeof(*nmb2->answers));

  nmb2->answers->rr_name = nmb->question.question_name;
  nmb2->answers->rr_type = nmb->question.question_type;
  nmb2->answers->rr_class = nmb->question.question_class;
  nmb2->answers->ttl = ttl;
  nmb2->answers->rdlength = 6;
  nmb2->answers->rdata[0] = unique?0:0x80; 
  nmb2->answers->rdata[1] = 0; 
  putip(&nmb2->answers->rdata[2],(char *)&retip);

  send_packet(&p2);
}



/* the global packet linked-list. incoming entries are added to the
   end of this list.  it is supposed to remain fairly short so we
   won't bother with an end pointer. */
static struct packet_struct *packet_queue = NULL;


/*******************************************************************
  queue a packet into the packet queue
  ******************************************************************/
static void queue_packet(struct packet_struct *packet)
{
  struct packet_struct *p;
  if (!packet_queue) {
    packet->prev = NULL;
    packet->next = NULL;
    packet_queue = packet;
    return;
  }
  
  /* find the bottom */
  for (p=packet_queue;p->next;p=p->next) ;

  p->next = packet;
  packet->next = NULL;
  packet->prev = p;
}

/****************************************************************************
  process a nmb packet
  ****************************************************************************/
static void process_nmb(struct packet_struct *p)
{
  struct nmb_packet *nmb = &p->packet.nmb;

  /* if this is a response then ignore it */
  if (nmb->header.response) return;

  switch (nmb->header.opcode) 
    {
    case 5:
    case 8:
    case 9:
      if (nmb->header.qdcount>0 && 
	  nmb->header.arcount>0) {
	reply_name_reg(p);
	return;
      }
      break;

    case 0:
      if (nmb->header.qdcount>0) 
	{
	  switch (nmb->question.question_type)
	    {
	    case 0x20:
	      reply_name_query(p);
	      break;

	    case 0x21:
	      reply_name_status(p);
	      break;
	    }
	  return;
	}
      break;

    case 6:
      if (nmb->header.qdcount>0 && 
	  nmb->header.arcount>0) {
	reply_name_release(p);
	return;
      }
      break;
    }

}



/*******************************************************************
  run elements off the packet queue till its empty
  ******************************************************************/
static void run_packet_queue(void)
{
  struct packet_struct *p;

  while ((p=packet_queue)) {
    switch (p->packet_type)
      {
      case NMB_PACKET:
	process_nmb(p);
	break;

      case DGRAM_PACKET:
	process_dgram(p);
	break;
      }

    packet_queue = packet_queue->next;
    if (packet_queue) packet_queue->prev = NULL;
    free_packet(p);
  }
}


/****************************************************************************
  The main select loop, listen for packets and respond
  ***************************************************************************/
void process(void)
{

  while (True)
    {
      fd_set fds;
      int selrtn;
      struct timeval timeout;

      if (needelection && PrimaryGroup[0] && !RunningElection) {
	DEBUG(3,(">>> Starting election on %s <<<\n",PrimaryGroup));
	ElectionCount = 0;
	RunningElection = True;
	needelection = False;
      }

      FD_ZERO(&fds);
      FD_SET(ClientNMB,&fds);
      FD_SET(ClientDGRAM,&fds);
      /* during elections we need to send election packets at one
         second intervals */
      timeout.tv_sec = RunningElection?1:NMBD_SELECT_LOOP;
      timeout.tv_usec = 0;

      selrtn = sys_select(&fds,&timeout);

      if (FD_ISSET(ClientNMB,&fds)) {
	struct packet_struct *packet = read_packet(ClientNMB,NMB_PACKET);
	if (packet) queue_packet(packet);
      }

      if (FD_ISSET(ClientDGRAM,&fds)) {
	struct packet_struct *packet = read_packet(ClientDGRAM,DGRAM_PACKET);
	if (packet) queue_packet(packet);
      }

      if (RunningElection) 
	run_election();

      run_packet_queue();

      do_announcements();

      housekeeping();
    }
}


/****************************************************************************
  open the socket communication
****************************************************************************/
static BOOL open_sockets(BOOL isdaemon,int port)
{
  struct hostent *hp;
 
  /* get host info */
  if ((hp = Get_Hostbyname(myhostname)) == 0) 
    {
      DEBUG(0,( "Get_Hostbyname: Unknown host. %s\n",myhostname));
      return False;
    }   

  if (isdaemon)
    ClientNMB = open_socket_in(SOCK_DGRAM, port,0);
  else
    ClientNMB = 0;

  ClientDGRAM = open_socket_in(SOCK_DGRAM,DGRAM_PORT,3);

  if (ClientNMB == -1)
    return(False);

  signal(SIGPIPE, SIGNAL_CAST sig_pipe);

  set_socket_options(ClientNMB,"SO_BROADCAST");
  set_socket_options(ClientDGRAM,"SO_BROADCAST");

  DEBUG(3, ("Socket opened.\n"));
  return True;
}


/*******************************************************************
  check that a IP, bcast and netmask and consistent. Must be a 1s
  broadcast
  ******************************************************************/
static BOOL ip_consistent(struct in_addr ip,struct in_addr bcast,
			  struct in_addr nmask)
{
  unsigned long a_ip,a_bcast,a_nmask;

  a_ip = ntohl(ip.s_addr);
  a_bcast = ntohl(bcast.s_addr);
  a_nmask = ntohl(nmask.s_addr);

  /* check the netmask is sane */
  if (((a_nmask>>24)&0xFF) != 0xFF) {
    DEBUG(0,("Insane netmask %s\n",inet_ntoa(nmask)));
    return(False);
  }

  /* check the IP and bcast are on the same net */
  if ((a_ip&a_nmask) != (a_bcast&a_nmask)) {
    DEBUG(0,("IP and broadcast are on different nets!\n"));
    return(False);
  }

  /* check the IP and bcast are on the same net */
  if ((a_bcast|a_nmask) != 0xFFFFFFFF) {
    DEBUG(0,("Not a ones based broadcast %s\n",inet_ntoa(bcast)));
    return(False);
  }

  return(True);
}

/****************************************************************************
  initialise connect, service and file structs
****************************************************************************/
static BOOL init_structs(void )
{
  if (!get_myname(myhostname,got_myip?NULL:&myip))
    return(False);

  /* Read the broadcast address from the interface */
  {
    struct in_addr ip0,ip1,ip2;

    ip0 = myip;

    if (!(got_bcast && got_nmask))
      {
	get_broadcast(&ip0,&ip1,&ip2);

	if (!got_myip)
	  myip = ip0;
    
	if (!got_bcast)
	  bcast_ip = ip1;
    
	if (!got_nmask)
	  Netmask = ip2;   
      } 

    DEBUG(1,("Using IP %s  ",inet_ntoa(myip))); 
    DEBUG(1,("broadcast %s  ",inet_ntoa(bcast_ip)));
    DEBUG(1,("netmask %s\n",inet_ntoa(Netmask)));    

    if (!ip_consistent(myip,bcast_ip,Netmask)) {
      DEBUG(0,("WARNING: The IP address, broadcast and Netmask are not consistent\n"));
      DEBUG(0,("You are likely to experience problems with this setup!\n"));
    }
  }

  if (! *myname) {
    char *p;
    strcpy(myname,myhostname);
    p = strchr(myname,'.');
    if (p) *p = 0;
  }

  {
    extern fstring local_machine;
    strcpy(local_machine,myname);
    strupper(local_machine);
  }

  return True;
}

/****************************************************************************
usage on the program
****************************************************************************/
static void usage(char *pname)
{
  DEBUG(0,("Incorrect program usage - is the command line correct?\n"));

  printf("Usage: %s [-n name] [-B bcast address] [-D] [-p port] [-d debuglevel] [-l log basename]\n",pname);
  printf("Version %s\n",VERSION);
  printf("\t-D                    become a daemon\n");
  printf("\t-p port               listen on the specified port\n");
  printf("\t-d debuglevel         set the debuglevel\n");
  printf("\t-l log basename.      Basename for log/debug files\n");
  printf("\t-n netbiosname.       the netbios name to advertise for this host\n");
  printf("\t-B broadcast address  the address to use for broadcasts\n");
  printf("\t-N netmask           the netmask to use for subnet determination\n");
  printf("\t-H hosts file        load a netbios hosts file\n");
  printf("\t-I ip-address        override the IP address\n");
  printf("\t-G group name        add a group name to be part of\n");
  printf("\t-C comment           sets the machine comment that appears in browse lists\n");
  printf("\n");
}


/****************************************************************************
  main program
  **************************************************************************/
int main(int argc,char *argv[])
{
  int port = NMB_PORT;
  int opt;
  extern FILE *dbf;
  extern char *optarg;

  *host_file = 0;

#if 0
  sleep(10);
#endif

  StartupTime = time(NULL);

  TimeInit();

  strcpy(debugf,NMBLOGFILE);

  setup_logging(argv[0],False);

  charset_initialise();

#ifdef LMHOSTSFILE
  strcpy(host_file,LMHOSTSFILE);
#endif

  /* this is for people who can't start the program correctly */
  while (argc > 1 && (*argv[1] != '-'))
    {
      argv++;
      argc--;
    }

  fault_setup(fault_continue);

  signal(SIGHUP,SIGNAL_CAST sig_hup);

  bcast_ip = *interpret_addr2("0.0.0.0");
  myip = *interpret_addr2("0.0.0.0");

  while ((opt = getopt (argc, argv, "s:T:I:C:bAi:B:N:Rn:l:d:Dp:hSH:G:")) != EOF)
    switch (opt)
      {
      case 's':
	strcpy(servicesf,optarg);
	break;
      case 'C':
	strcpy(ServerComment,optarg);
	break;
      case 'G':
	add_domain_entry(optarg,bcast_ip);
	break;
      case 'H':
	strcpy(host_file,optarg);
	break;
      case 'I':
	myip = *interpret_addr2(optarg);
	got_myip = True;
	break;
      case 'B':
	bcast_ip = *interpret_addr2(optarg);
	got_bcast = True;
	break;
      case 'N':
	Netmask = *interpret_addr2(optarg);
	got_nmask = True;
	break;
      case 'n':
	strcpy(myname,optarg);
	break;
      case 'l':
	sprintf(debugf,"%s.nmb",optarg);
	break;
      case 'i':
	strcpy(scope,optarg);
	strupper(scope);
	break;
      case 'D':
	is_daemon = True;
	break;
      case 'd':
	DEBUGLEVEL = atoi(optarg);
	break;
      case 'p':
	port = atoi(optarg);
	break;
      case 'h':
	usage(argv[0]);
	exit(0);
	break;
      default:
	if (!is_a_socket(0))
	  usage(argv[0]);
	break;
      }
  
  DEBUG(1,("%s netbios nameserver version %s started\n",timestring(),VERSION));
  DEBUG(1,("Copyright Andrew Tridgell 1994\n"));

  init_structs();

  if (!reload_services(False))
    return(-1);	

  if (*host_file)
    {
      load_hosts_file(host_file);
      DEBUG(3,("Loaded hosts file\n"));
    }

  if (!*ServerComment)
    strcpy(ServerComment,"Samba %v");
  string_sub(ServerComment,"%v",VERSION);
  string_sub(ServerComment,"%h",myhostname);

  add_my_names();

  DEBUG(3,("Checked names\n"));
  
  dump_names();

  DEBUG(3,("Dumped names\n"));

  if (!is_daemon && !is_a_socket(0)) {
    DEBUG(0,("standard input is not a socket, assuming -D option\n"));
    is_daemon = True;
  }
  

  if (is_daemon) {
    DEBUG(2,("%s becoming a daemon\n",timestring()));
    become_daemon();
  }


  DEBUG(3,("Opening sockets\n"));

  if (open_sockets(is_daemon,port))
    {
      process();
      close_sockets();
    }

  if (dbf)
    fclose(dbf);
  return(0);
}
