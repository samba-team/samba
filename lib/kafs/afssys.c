#include "config.h"
#include "protos.h"

RCSID("$Id$");

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/ioctl.h>
#ifdef HAVE_SYS_FILIO_H
#include <sys/filio.h>
#endif
#ifdef HAVE_SYS_SYSCALL_H
#include <sys/syscall.h>
#endif

#include <signal.h>
#include <setjmp.h>
#include <errno.h>
#include <string.h>
#include <signal.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#ifdef HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif
#ifdef HAVE_RESOLV_H
#include <resolv.h>
#endif

#include <krb.h>
#include <kafs.h>

#include "afssysdefs.h"

#define AUTH_SUPERUSER "afs"

/*
 * Here only ASCII characters are relevant.
 */

#define IsAsciiLower(c) ('a' <= (c) && (c) <= 'z')

#define ToAsciiUpper(c) ((c) - 'a' + 'A')

static void
foldup(char *a, char *b)
{
  for (; *b; a++, b++)
    if (IsAsciiLower(*b))
      *a = ToAsciiUpper(*b);
    else
      *a = *b;
  *a = '\0';
}

static int
get_cred(char *princ, char *inst, char *krealm, CREDENTIALS *c, KTEXT_ST *tkt)
{
  int k_errno = krb_get_cred(princ, inst, krealm, c);
  if (k_errno != KSUCCESS)
    {
      k_errno = krb_mk_req(tkt, princ, inst, krealm, 0);
      if (k_errno == KSUCCESS)
	k_errno = krb_get_cred(princ, inst, krealm, c);
    }
  return k_errno;
}


/* Convert a string to a 32 bit ip number in network byte order. 
   Return 0 on error
   */

static u_int32_t ip_aton(char *ip)
{
  u_int32_t addr;
  int a, b, c, d;
  if(sscanf(ip, "%d.%d.%d.%d", &a, &b, &c, &d) != 4)
    return 0;
  if(a < 0 || a > 255 || 
     b < 0 || b > 255 || 
     c < 0 || c > 255 || 
     d < 0 || d > 255)
    return 0;
  addr = (a << 24) | (b << 16) | (c << 8) | d;
  addr = htonl(addr);
  return addr;
}

/* Try to get a db-server for an AFS cell from a AFSDB record */
static int
dns_find_cell(char *cell, char *dbserver)
{
#if defined(HAVE_DN_EXPAND) && defined(HAVE_RES_SEARCH)
#ifndef T_AFSDB
#define T_AFSDB 18
#endif
    unsigned char data[1024];
    unsigned char host[MaxHostNameLen];
    int len;

    int status;
    unsigned char *p;

    len = res_search(cell, C_IN, T_AFSDB, data, sizeof(data));
    if(len < 0)
	return -1;
    p = data + sizeof(HEADER);
    status = dn_expand(data, data + len, p, host, sizeof(host));
    if(status < 0)
	return -1;
    p += status;
    p += 4; /* type and class */
    while(p < data + len){
	int type, subtype, class, ttl, size;
	status = dn_expand(data, data + len, p, host, sizeof(host));
	if(status < 0)
	    return -1;
	p += status;
	type = (p[0] << 8) | p[1];
	p += 2;
	class = (p[0] << 8) | p[1];
	p += 2;
	ttl = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
	p += 4;
	size = (p[0] << 8) | p[1];
	p += 2;
	if(type == T_AFSDB){
	    subtype = (p[0] << 8) | p[1];
	    if(subtype == 1){
		p += 2;
		status = dn_expand(data, data + len, p, host, sizeof(host));
		if(status < 0)
		    return -1;
		strncpy(dbserver, (char*)host, MaxHostNameLen);
		dbserver[MaxHostNameLen] = 0;
		return 0;
	    }
	}
	p += size;
    }
#endif
    return -1;
}

/* Find the realm associated with cell. Do this by opening
   /usr/vice/etc/CellServDB and getting the realm-of-host for the
   first VL-server for the cell.

   This does not work when the VL-server is living in one cell, but
   the cell it is serving is living in another cell.
   */

static char*
realm_of_cell(char *cell)
{
  FILE *F;
  char buf[1024];
  u_int32_t addr;
  struct hostent *hp;
  char *realm = NULL;

  F = fopen(_PATH_CELLSERVDB, "r");
  while(F && !feof(F)){
    fgets(buf, 1024, F);
    if(buf[0] != '>')
      continue;
    if(strncmp(buf+1, cell, strlen(cell)) == 0){
      fgets(buf, 1024, F);
      if(feof(F))
	break;
      addr = ip_aton(buf);
      if(addr == 0)
	break;
      hp = gethostbyaddr((char*)&addr, 4, AF_INET);
      if(hp == NULL)
	break;
      strcpy(buf, hp->h_name);
      realm = krb_realmofhost(buf);
      break;
    }
  }
  if(F)
    fclose(F);

  if(realm == NULL){
      if(dns_find_cell(cell, buf) == 0)
	  realm = krb_realmofhost(buf);
  }
  return realm;
}

/* Magic to get AIX syscalls to work */
#ifdef _AIX

static int (*Pioctl)(char*, int, void*, int);
static int (*Setpag)(void);

#include "dlfcn.h"

static
int
isSuid()
{
  int uid = getuid();
  int gid = getgid();
  int euid = getegid();
  int egid = getegid();
  return (uid != euid) || (gid != egid);
}

static
int
aix_setup(void)
{
#ifdef STATIC_AFS_SYSCALLS
    Pioctl = aix_pioctl;
    Setpag = aix_setpag;
#else
    void *ptr;
    char path[MaxPathLen], *p;
    /*
     * If we are root or running setuid don't trust AFSLIBPATH!
     */
    if (getuid() != 0 && !isSuid() && (p = getenv("AFSLIBPATH")) != NULL)
	strcpy(path, p);
    else
	sprintf(path, "%s/afslib.so", LIBDIR);
	
    ptr = dlopen(path, 0);
    if(ptr){
	Setpag = (int (*)(void))dlsym(ptr, "aix_setpag");
	Pioctl = (int (*)(char*, int, void*, int))dlsym(ptr, "aix_pioctl");
    }
#endif
}
#endif


/*
 * Try to find the cells we should try to klog to.  Look at
 * /usr/vice/etc/TheseCells and /usr/vice/etc/ThisCell,
 * in that order.
 */

static int
k_afslog_file(char *file, char *krealm)
{
    FILE *f;
    char cell[64];
    int err = KSUCCESS;
    f = fopen(file, "r");
    if(f == NULL)
	return -1;
    while(fgets(cell, sizeof(cell), f) && err == KSUCCESS){
	char *nl = strchr(cell, '\n');
	if(nl)
	    *nl = 0;
	err = k_afsklog(cell, krealm);
    }
    fclose(f);
    return err;
}

static int
k_afsklog_all_local_cells (char *krealm)
{
    int err = KFAILURE;
    char *p, home[MaxPathLen];

    if((p = getenv("HOME"))){
	sprintf(home, "%s/.TheseCells", p);
	err = err && k_afslog_file(home, krealm);
    }
    k_afslog_file(_PATH_THESECELLS, krealm);
    k_afslog_file(_PATH_THISCELL, krealm);
    return err;
}

int
k_afsklog(char *cell, char *krealm)
{
  int k_errno;
  CREDENTIALS c;
  KTEXT_ST ticket;
  char realm[REALM_SZ];
  char *vl_realm; /* realm of vl-server */
  char *lrealm; /* local realm */
  char CELL[64];

  if (!k_hasafs())
    return KSUCCESS;

  if (cell == 0 || cell[0] == 0)
    return k_afsklog_all_local_cells (krealm);
  foldup(CELL, cell);

  vl_realm = realm_of_cell(cell);

  k_errno = krb_get_lrealm(realm , 0);
  if(k_errno == KSUCCESS && (krealm == NULL || strcmp(krealm, realm)))
    lrealm = realm;
  else
    lrealm = NULL;

  /* We're about to find the the realm that holds the key for afs in
   * the specified cell. The problem is that null-instance
   * afs-principals are common and that hitting the wrong realm might
   * yield the wrong afs key. The following assumptions were made.
   *
   * Any realm passed to us is preferred.
   *
   * If there is a realm with the same name as the cell, it is most
   * likely the correct realm to talk to.
   *
   * In most (maybe even all) cases the database servers of the cell
   * will live in the realm we are looking for.
   *
   * Try the local realm, but if the previous cases fail, this is
   * really a long shot.
   *
   */
  
  /* comments on the ordering of these tests */

  /* If the user passes a realm, she probably knows something we don't
   * know and we should try afs@krealm (otherwise we're talking with a
   * blondino and she might as well have it.)
   */
  
  k_errno = -1;
  if(krealm){
    k_errno = get_cred(AUTH_SUPERUSER, cell, krealm, &c, &ticket);
    if(k_errno)
      k_errno = get_cred(AUTH_SUPERUSER, "", krealm, &c, &ticket);
  }

  if(k_errno)
    k_errno = get_cred(AUTH_SUPERUSER, cell, CELL, &c, &ticket);
  if(k_errno)
    k_errno = get_cred(AUTH_SUPERUSER, "", CELL, &c, &ticket);
  
  /* this might work in some conditions */
  if(k_errno && vl_realm){
    k_errno = get_cred(AUTH_SUPERUSER, cell, vl_realm, &c, &ticket);
    if(k_errno)
      k_errno = get_cred(AUTH_SUPERUSER, "", vl_realm, &c, &ticket);
  }
  
  if(k_errno && lrealm){
    k_errno = get_cred(AUTH_SUPERUSER, cell, lrealm, &c, &ticket);
#if 0
    /* this is most likely never right anyway, but won't fail */
    if(k_errno)
      k_errno = get_cred(AUTH_SUPERUSER, "", lrealm, &c, &ticket);
#endif
  }
  
  if (k_errno == KSUCCESS)
    {
      struct ViceIoctl parms;
      struct ClearToken ct;
      int32_t sizeof_x;
      char buf[2048], *t;

      /*
       * Build a struct ClearToken
       */
      ct.AuthHandle = c.kvno;
      memcpy (ct.HandShakeKey, c.session, sizeof(c.session));
      ct.ViceId = getuid();	/* is this always valid? */
      ct.BeginTimestamp = 1 + c.issue_date;
      ct.EndTimestamp = krb_life_to_time(c.issue_date, c.lifetime);

      t = buf;
      /*
       * length of secret token followed by secret token
       */
      sizeof_x = c.ticket_st.length;
      memcpy(t, &sizeof_x, sizeof(sizeof_x));
      t += sizeof(sizeof_x);
      memcpy(t, c.ticket_st.dat, sizeof_x);
      t += sizeof_x;
      /*
       * length of clear token followed by clear token
       */
      sizeof_x = sizeof(ct);
      memcpy(t, &sizeof_x, sizeof(sizeof_x));
      t += sizeof(sizeof_x);
      memcpy(t, &ct, sizeof_x);
      t += sizeof_x;

      /*
       * do *not* mark as primary cell
       */
      sizeof_x = 0;
      memcpy(t, &sizeof_x, sizeof(sizeof_x));
      t += sizeof(sizeof_x);
      /*
       * follow with cell name
       */
      sizeof_x = strlen(cell) + 1;
      memcpy(t, cell, sizeof_x);
      t += sizeof_x;

      /*
       * Build argument block
       */
      parms.in = buf;
      parms.in_size = t - buf;
      parms.out = 0;
      parms.out_size = 0;
      k_pioctl(0, VIOCSETTOK, &parms, 0);
    }
  return k_errno;
}

#define NO_ENTRY_POINT		0
#define SINGLE_ENTRY_POINT	1
#define MULTIPLE_ENTRY_POINT	2
#define SINGLE_ENTRY_POINT2	3
#define SINGLE_ENTRY_POINT3	4
#define AIX_ENTRY_POINTS	5
#define UNKNOWN_ENTRY_POINT	6
static int afs_entry_point = UNKNOWN_ENTRY_POINT;

int
k_pioctl(char *a_path,
	 int o_opcode,
	 struct ViceIoctl *a_paramsP,
	 int a_followSymlinks)
{
#ifndef NO_AFS
#ifdef AFS_SYSCALL
  if (afs_entry_point == SINGLE_ENTRY_POINT)
    return syscall(AFS_SYSCALL, AFSCALL_PIOCTL,
		   a_path, o_opcode, a_paramsP, a_followSymlinks);
#endif

#ifdef AFS_PIOCTL
    if (afs_entry_point == MULTIPLE_ENTRY_POINT)
      return syscall(AFS_PIOCTL,
		     a_path, o_opcode, a_paramsP, a_followSymlinks);
#endif

#ifdef AFS_SYSCALL2
  if (afs_entry_point == SINGLE_ENTRY_POINT2)
    return syscall(AFS_SYSCALL2, AFSCALL_PIOCTL,
		   a_path, o_opcode, a_paramsP, a_followSymlinks);
#endif

#ifdef AFS_SYSCALL3
  if (afs_entry_point == SINGLE_ENTRY_POINT3)
    return syscall(AFS_SYSCALL3, AFSCALL_PIOCTL,
		   a_path, o_opcode, a_paramsP, a_followSymlinks);
#endif

#ifdef _AIX
  if (afs_entry_point == AIX_ENTRY_POINTS)
      return Pioctl(a_path, o_opcode, a_paramsP, a_followSymlinks);
#endif

  errno = ENOSYS;
#ifdef SIGSYS
  kill(getpid(), SIGSYS);	/* You loose! */
#endif
#endif /* NO_AFS */
  return -1;
}

int
k_unlog(void)
{
  struct ViceIoctl parms;
  memset(&parms, 0, sizeof(parms));
  return k_pioctl(0, VIOCUNLOG, &parms, 0);
}

int
k_setpag(void)
{
#ifndef NO_AFS
#ifdef AFS_SYSCALL
  if (afs_entry_point == SINGLE_ENTRY_POINT)
    return syscall(AFS_SYSCALL, AFSCALL_SETPAG);
#endif

#ifdef AFS_SETPAG
  if (afs_entry_point == MULTIPLE_ENTRY_POINT)
    return syscall(AFS_SETPAG);
#endif

#ifdef AFS_SYSCALL2
  if (afs_entry_point == SINGLE_ENTRY_POINT2)
    return syscall(AFS_SYSCALL2, AFSCALL_SETPAG);
#endif

#ifdef _AIX
  if (afs_entry_point == AIX_ENTRY_POINTS)
      return Setpag();
#endif

  errno = ENOSYS;
#ifdef SIGSYS
  kill(getpid(), SIGSYS);	/* You loose! */
#endif
#endif /* NO_AFS */
  return -1;
}

static jmp_buf catch_SIGSYS;

#ifdef SIGSYS

static void
SIGSYS_handler(int sig)
{
  errno = 0;
  signal(SIGSYS, SIGSYS_handler); /* Need to reinstall handler on SYSV */
  longjmp(catch_SIGSYS, 1);
}

#endif

int
k_hasafs(void)
{
  int saved_errno;
  RETSIGTYPE (*saved_func)();
  struct ViceIoctl parms;
  
  /*
   * Already checked presence of AFS syscalls?
   */
  if (afs_entry_point != UNKNOWN_ENTRY_POINT)
    return afs_entry_point != NO_ENTRY_POINT;

  /*
   * Probe kernel for AFS specific syscalls,
   * they (currently) come in two flavors.
   * If the syscall is absent we recive a SIGSYS.
   */
  afs_entry_point = NO_ENTRY_POINT;
  memset(&parms, 0, sizeof(parms));
  
  saved_errno = errno;
#ifndef NO_AFS
#ifdef SIGSYS
  saved_func = signal(SIGSYS, SIGSYS_handler);
#endif

#ifdef AFS_SYSCALL
  if (setjmp(catch_SIGSYS) == 0)
    {
      syscall(AFS_SYSCALL, AFSCALL_PIOCTL,
	      0, VIOCSETTOK, &parms, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
      if (errno == EINVAL)
	{
	  afs_entry_point = SINGLE_ENTRY_POINT;
	  goto done;
	}
    }
#endif /* AFS_SYSCALL */

#ifdef AFS_PIOCTL
  if (setjmp(catch_SIGSYS) == 0)
    {
      syscall(AFS_PIOCTL,
	      0, VIOCSETTOK, &parms, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
      if (errno == EINVAL)
	{
	  afs_entry_point = MULTIPLE_ENTRY_POINT;
	  goto done;
	}
    }
#endif /* AFS_PIOCTL */

#ifdef AFS_SYSCALL2
  if (setjmp(catch_SIGSYS) == 0)
    {
      syscall(AFS_SYSCALL2, AFSCALL_PIOCTL,
	      0, VIOCSETTOK, &parms, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
      if (errno == EINVAL)
	{
	  afs_entry_point = SINGLE_ENTRY_POINT2;
	  goto done;
	}
    }
#endif /* AFS_SYSCALL */

#ifdef AFS_SYSCALL3
  if (setjmp(catch_SIGSYS) == 0)
    {
      syscall(AFS_SYSCALL3, AFSCALL_PIOCTL,
	      0, VIOCSETTOK, &parms, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
      if (errno == EINVAL)
	{
	  afs_entry_point = SINGLE_ENTRY_POINT3;
	  goto done;
	}
    }
#endif /* AFS_SYSCALL */

#ifdef _AIX
  aix_setup();
  if(Pioctl != NULL && Setpag != NULL){
      afs_entry_point = AIX_ENTRY_POINTS;
      goto done;
  }
#endif

 done:
#ifdef SIGSYS
  signal(SIGSYS, saved_func);
#endif
#endif /* NO_AFS */
  errno = saved_errno;
  return afs_entry_point != NO_ENTRY_POINT;
}

