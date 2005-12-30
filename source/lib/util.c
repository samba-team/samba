/* 
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Jeremy Allison 2001-2002
   Copyright (C) Simo Sorce 2001
   Copyright (C) Jim McDonough (jmcd@us.ibm.com)  2003.
   Copyright (C) James J Myers 2003
   
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
#include "dynconfig.h"
#include "system/network.h"
#include "system/iconv.h"
#include "system/filesys.h"

/***************************************************************************
 Find a suitable temporary directory. The result should be copied immediately
 as it may be overwritten by a subsequent call.
****************************************************************************/
const char *tmpdir(void)
{
	char *p;
	if ((p = getenv("TMPDIR")))
		return p;
	return "/tmp";
}


/*******************************************************************
 Check if a file exists - call vfs_file_exist for samba files.
********************************************************************/
BOOL file_exist(const char *fname)
{
	struct stat st;

	if (stat(fname, &st) != 0) {
		return False;
	}

	return ((S_ISREG(st.st_mode)) || (S_ISFIFO(st.st_mode)));
}

/*******************************************************************
 Check a files mod time.
********************************************************************/

time_t file_modtime(const char *fname)
{
	struct stat st;
  
	if (stat(fname,&st) != 0) 
		return(0);

	return(st.st_mtime);
}

/*******************************************************************
 Check if a directory exists.
********************************************************************/

BOOL directory_exist(const char *dname)
{
	struct stat st;
	BOOL ret;

	if (stat(dname,&st) != 0) {
		return False;
	}

	ret = S_ISDIR(st.st_mode);
	if(!ret)
		errno = ENOTDIR;
	return ret;
}

/*******************************************************************
 Returns the size in bytes of the named file.
********************************************************************/
off_t get_file_size(char *file_name)
{
	struct stat buf;
	buf.st_size = 0;
	if(stat(file_name,&buf) != 0)
		return (off_t)-1;
	return(buf.st_size);
}

/*******************************************************************
 Close the low 3 fd's and open dev/null in their place.
********************************************************************/
void close_low_fds(BOOL stderr_too)
{
#ifndef VALGRIND
	int fd;
	int i;

	close(0);
	close(1); 

	if (stderr_too)
		close(2);

	/* try and use up these file descriptors, so silly
		library routines writing to stdout etc won't cause havoc */
	for (i=0;i<3;i++) {
		if (i == 2 && !stderr_too)
			continue;

		fd = open("/dev/null",O_RDWR,0);
		if (fd < 0)
			fd = open("/dev/null",O_WRONLY,0);
		if (fd < 0) {
			DEBUG(0,("Can't open /dev/null\n"));
			return;
		}
		if (fd != i) {
			DEBUG(0,("Didn't get file descriptor %d\n",i));
			return;
		}
	}
#endif
}

/****************************************************************************
 Set a fd into blocking/nonblocking mode. Uses POSIX O_NONBLOCK if available,
 else
  if SYSV use O_NDELAY
  if BSD use FNDELAY
****************************************************************************/

int set_blocking(int fd, BOOL set)
{
	int val;
#ifdef O_NONBLOCK
#define FLAG_TO_SET O_NONBLOCK
#else
#ifdef SYSV
#define FLAG_TO_SET O_NDELAY
#else /* BSD */
#define FLAG_TO_SET FNDELAY
#endif
#endif

	if((val = fcntl(fd, F_GETFL, 0)) == -1)
		return -1;
	if(set) /* Turn blocking on - ie. clear nonblock flag */
		val &= ~FLAG_TO_SET;
	else
		val |= FLAG_TO_SET;
	return fcntl( fd, F_SETFL, val);
#undef FLAG_TO_SET
}


/*******************************************************************
 Sleep for a specified number of milliseconds.
********************************************************************/

void msleep(uint_t t)
{
	struct timeval tval;  

	tval.tv_sec = t/1000;
	tval.tv_usec = 1000*(t%1000);
	/* this should be the real select - do NOT replace
	   with sys_select() */
	select(0,NULL,NULL,NULL,&tval);
}

/****************************************************************************
 Become a daemon, discarding the controlling terminal.
****************************************************************************/

void become_daemon(BOOL Fork)
{
	if (Fork) {
		if (fork()) {
			_exit(0);
		}
	}

  /* detach from the terminal */
#ifdef HAVE_SETSID
	setsid();
#elif defined(TIOCNOTTY)
	{
		int i = open("/dev/tty", O_RDWR, 0);
		if (i != -1) {
			ioctl(i, (int) TIOCNOTTY, (char *)0);      
			close(i);
		}
	}
#endif /* HAVE_SETSID */

	/* Close fd's 0,1,2. Needed if started by rsh */
	close_low_fds(False);  /* Don't close stderr, let the debug system
				  attach it to the logfile */
}


/****************************************************************************
 Free memory, checks for NULL.
 Use directly SAFE_FREE()
 Exists only because we need to pass a function pointer somewhere --SSS
****************************************************************************/

void safe_free(void *p)
{
	SAFE_FREE(p);
}


/*
  see if a string matches either our primary or one of our secondary 
  netbios aliases. do a case insensitive match
*/
BOOL is_myname(const char *name)
{
	const char **aliases;
	int i;

	if (strcasecmp(name, lp_netbios_name()) == 0) {
		return True;
	}

	aliases = lp_netbios_aliases();
	for (i=0; aliases && aliases[i]; i++) {
		if (strcasecmp(name, aliases[i]) == 0) {
			return True;
		}
	}

	return False;
}


/****************************************************************************
 Get my own name, return in malloc'ed storage.
****************************************************************************/

char* get_myname(void)
{
	char *hostname;
	const int host_name_max = 255;
	char *p;

	hostname = malloc(host_name_max+1);
	*hostname = 0;

	/* get my host name */
	if (gethostname(hostname, host_name_max+1) == -1) {
		DEBUG(0,("gethostname failed\n"));
		return NULL;
	} 

	/* Ensure null termination. */
	hostname[host_name_max] = '\0';

	/* split off any parts after an initial . */
	p = strchr_m(hostname,'.');

	if (p)
		*p = 0;
	
	return hostname;
}

/****************************************************************************
 Return true if a string could be a pure IP address.
****************************************************************************/

BOOL is_ipaddress(const char *str)
{
	BOOL pure_address = True;
	int i;
  
	for (i=0; pure_address && str[i]; i++)
		if (!(isdigit((int)str[i]) || str[i] == '.'))
			pure_address = False;

	/* Check that a pure number is not misinterpreted as an IP */
	pure_address = pure_address && (strchr_m(str, '.') != NULL);

	return pure_address;
}

/****************************************************************************
 Interpret an internet address or name into an IP address in 4 byte form.
****************************************************************************/
uint32_t interpret_addr(const char *str)
{
	struct hostent *hp;
	uint32_t res;

	if (str == NULL || *str == 0 ||
	    strcmp(str,"0.0.0.0") == 0) {
		return 0;
	}
	if (strcmp(str,"255.255.255.255") == 0) {
		return 0xFFFFFFFF;
	}
	/* recognise 'localhost' as a special name. This fixes problems with
	   some hosts that don't have localhost in /etc/hosts */
	if (strcasecmp(str,"localhost") == 0) {
		str = "127.0.0.1";
	}

	/* if it's in the form of an IP address then get the lib to interpret it */
	if (is_ipaddress(str)) {
		res = inet_addr(str);
	} else {
		/* otherwise assume it's a network name of some sort and use 
			sys_gethostbyname */
		if ((hp = sys_gethostbyname(str)) == 0) {
			DEBUG(3,("sys_gethostbyname: Unknown host. %s\n",str));
			return 0;
		}

		if(hp->h_addr == NULL) {
			DEBUG(3,("sys_gethostbyname: host address is invalid for host %s\n",str));
			return 0;
		}
		memcpy((char *)&res,(char *)hp->h_addr, 4);
	}

	if (res == (uint32_t)-1)
		return(0);

	return(res);
}

/*******************************************************************
 A convenient addition to interpret_addr().
******************************************************************/
struct ipv4_addr interpret_addr2(const char *str)
{
	struct ipv4_addr ret;
	uint32_t a = interpret_addr(str);
	ret.addr = a;
	return ret;
}

/*******************************************************************
 Check if an IP is the 0.0.0.0.
******************************************************************/

BOOL is_zero_ip(struct ipv4_addr ip)
{
	return ip.addr == 0;
}

/*******************************************************************
 Set an IP to 0.0.0.0.
******************************************************************/

void zero_ip(struct ipv4_addr *ip)
{
	*ip = sys_inet_makeaddr(0,0);
	return;
}


/*******************************************************************
 Are two IPs on the same subnet?
********************************************************************/

BOOL same_net(struct ipv4_addr ip1,struct ipv4_addr ip2,struct ipv4_addr mask)
{
	uint32_t net1,net2,nmask;

	nmask = ntohl(mask.addr);
	net1  = ntohl(ip1.addr);
	net2  = ntohl(ip2.addr);
            
	return((net1 & nmask) == (net2 & nmask));
}


/****************************************************************************
 Check if a process exists. Does this work on all unixes?
****************************************************************************/

BOOL process_exists(pid_t pid)
{
	/* Doing kill with a non-positive pid causes messages to be
	 * sent to places we don't want. */
	SMB_ASSERT(pid > 0);
	return(kill(pid,0) == 0 || errno != ESRCH);
}

/****************************************************************************
 Simple routine to do POSIX file locking. Cruft in NFS and 64->32 bit mapping
 is dealt with in posix.c
****************************************************************************/

BOOL fcntl_lock(int fd, int op, off_t offset, off_t count, int type)
{
	struct flock lock;
	int ret;

	DEBUG(8,("fcntl_lock %d %d %.0f %.0f %d\n",fd,op,(double)offset,(double)count,type));

	lock.l_type = type;
	lock.l_whence = SEEK_SET;
	lock.l_start = offset;
	lock.l_len = count;
	lock.l_pid = 0;

	ret = fcntl(fd,op,&lock);

	if (ret == -1 && errno != 0)
		DEBUG(3,("fcntl_lock: fcntl lock gave errno %d (%s)\n",errno,strerror(errno)));

	/* a lock query */
	if (op == F_GETLK) {
		if ((ret != -1) &&
				(lock.l_type != F_UNLCK) && 
				(lock.l_pid != 0) && 
				(lock.l_pid != getpid())) {
			DEBUG(3,("fcntl_lock: fd %d is locked by pid %d\n",fd,(int)lock.l_pid));
			return(True);
		}

		/* it must be not locked or locked by me */
		return(False);
	}

	/* a lock set or unset */
	if (ret == -1) {
		DEBUG(3,("fcntl_lock: lock failed at offset %.0f count %.0f op %d type %d (%s)\n",
			(double)offset,(double)count,op,type,strerror(errno)));
		return(False);
	}

	/* everything went OK */
	DEBUG(8,("fcntl_lock: Lock call successful\n"));

	return(True);
}


static void print_asc(int level, const uint8_t *buf,int len)
{
	int i;
	for (i=0;i<len;i++)
		DEBUGADD(level,("%c", isprint(buf[i])?buf[i]:'.'));
}

void dump_data(int level, const uint8_t *buf,int len)
{
	int i=0;
	if (len<=0) return;

	if (!DEBUGLVL(level)) return;
	
	DEBUGADD(level,("[%03X] ",i));
	for (i=0;i<len;) {
		DEBUGADD(level,("%02X ",(int)buf[i]));
		i++;
		if (i%8 == 0) DEBUGADD(level,(" "));
		if (i%16 == 0) {      
			print_asc(level,&buf[i-16],8); DEBUGADD(level,(" "));
			print_asc(level,&buf[i-8],8); DEBUGADD(level,("\n"));
			if (i<len) DEBUGADD(level,("[%03X] ",i));
		}
	}
	if (i%16) {
		int n;
		n = 16 - (i%16);
		DEBUGADD(level,(" "));
		if (n>8) DEBUGADD(level,(" "));
		while (n--) DEBUGADD(level,("   "));
		n = MIN(8,i%16);
		print_asc(level,&buf[i-(i%16)],n); DEBUGADD(level,( " " ));
		n = (i%16) - n;
		if (n>0) print_asc(level,&buf[i-n],n); 
		DEBUGADD(level,("\n"));    
	}	
}

/*****************************************************************
 malloc that aborts with smb_panic on fail or zero size.
 *****************************************************************/  

void *smb_xmalloc(size_t size)
{
	void *p;
	if (size == 0)
		smb_panic("smb_xmalloc: called with zero size.\n");
	if ((p = malloc(size)) == NULL)
		smb_panic("smb_xmalloc: malloc fail.\n");
	return p;
}

/**
 Memdup with smb_panic on fail.
**/

void *smb_xmemdup(const void *p, size_t size)
{
	void *p2;
	p2 = smb_xmalloc(size);
	memcpy(p2, p, size);
	return p2;
}

/**
 strdup that aborts on malloc fail.
**/

char *smb_xstrdup(const char *s)
{
	char *s1 = strdup(s);
	if (!s1)
		smb_panic("smb_xstrdup: malloc fail\n");
	return s1;
}


/*****************************************************************
 Like strdup but for memory.
*****************************************************************/  

void *memdup(const void *p, size_t size)
{
	void *p2;
	if (size == 0)
		return NULL;
	p2 = malloc(size);
	if (!p2)
		return NULL;
	memcpy(p2, p, size);
	return p2;
}

/*****************************************************************
 Get local hostname and cache result.
*****************************************************************/  

char *myhostname(TALLOC_CTX *mem_ctx)
{
	char *myname, *ret;
	myname = get_myname();
	ret = talloc_strdup(mem_ctx, myname);
	free(myname);
	return ret;

}

/**********************************************************************
 Converts a name to a fully qalified domain name.
***********************************************************************/

char *name_to_fqdn(TALLOC_CTX *mem_ctx, const char *name)
{
	struct hostent *hp = sys_gethostbyname(name);
	if ( hp && hp->h_name && *hp->h_name ) {
		DEBUG(10,("name_to_fqdn: lookup for %s -> %s.\n", name, hp->h_name));
		return talloc_strdup(mem_ctx, hp->h_name);
	} else {
		DEBUG(10,("name_to_fqdn: lookup for %s failed.\n", name));
		return talloc_strdup(mem_ctx, name);
	}
}


/*****************************************************************
 A useful function for returning a path in the Samba lock directory.
*****************************************************************/  
char *lock_path(TALLOC_CTX* mem_ctx, const char *name)
{
	char *fname, *dname;
	if (name == NULL) {
		return NULL;
	}
	if (name[0] == 0 || name[0] == '/' || strstr(name, ":/")) {
		return talloc_strdup(mem_ctx, name);
	}

	dname = talloc_strdup(mem_ctx, lp_lockdir());
	trim_string(dname,"","/");
	
	if (!directory_exist(dname)) {
		mkdir(dname,0755);
	}
	
	fname = talloc_asprintf(mem_ctx, "%s/%s", dname, name);

	talloc_free(dname);

	return fname;
}


/*****************************************************************
 A useful function for returning a path in the Samba piddir directory.
*****************************************************************/  
char *pid_path(TALLOC_CTX* mem_ctx, const char *name)
{
	char *fname, *dname;

	dname = talloc_strdup(mem_ctx, lp_piddir());
	trim_string(dname,"","/");
	
	if (!directory_exist(dname)) {
		mkdir(dname,0755);
	}
	
	fname = talloc_asprintf(mem_ctx, "%s/%s", dname, name);

	talloc_free(dname);

	return fname;
}


/**
 * @brief Returns an absolute path to a file in the Samba lib directory.
 *
 * @param name File to find, relative to LIBDIR.
 *
 * @retval Pointer to a talloc'ed string containing the full path.
 **/

char *lib_path(TALLOC_CTX* mem_ctx, const char *name)
{
	char *fname;
	fname = talloc_asprintf(mem_ctx, "%s/%s", dyn_LIBDIR, name);
	return fname;
}

/**
 * @brief Returns an absolute path to a file in the Samba private directory.
 *
 * @param name File to find, relative to PRIVATEDIR.
 * if name is not relative, then use it as-is
 *
 * @retval Pointer to a talloc'ed string containing the full path.
 **/
char *private_path(TALLOC_CTX* mem_ctx, const char *name)
{
	char *fname;
	if (name == NULL) {
		return NULL;
	}
	if (name[0] == 0 || name[0] == '/' || strstr(name, ":/")) {
		return talloc_strdup(mem_ctx, name);
	}
	fname = talloc_asprintf(mem_ctx, "%s/%s", lp_private_dir(), name);
	return fname;
}

/*
  return a path in the smbd.tmp directory, where all temporary file
  for smbd go. If NULL is passed for name then return the directory 
  path itself
*/
char *smbd_tmp_path(TALLOC_CTX *mem_ctx, const char *name)
{
	char *fname, *dname;

	dname = pid_path(mem_ctx, "smbd.tmp");
	if (!directory_exist(dname)) {
		mkdir(dname,0755);
	}

	if (name == NULL) {
		return dname;
	}

	fname = talloc_asprintf(mem_ctx, "%s/%s", dname, name);
	talloc_free(dname);

	return fname;
}

char *modules_path(TALLOC_CTX* mem_ctx, const char *name)
{
	return talloc_asprintf(mem_ctx, "%s/%s", dyn_MODULESDIR, name);
}

init_module_fn *load_samba_modules(TALLOC_CTX *mem_ctx, const char *subsystem)
{
	char *path = modules_path(mem_ctx, subsystem);
	init_module_fn *ret;

	ret = load_modules(mem_ctx, path);

	talloc_free(path);

	return ret;
}

void dump_data_pw(const char *msg, const uint8_t * data, size_t len)
{
#ifdef DEBUG_PASSWORD
	DEBUG(11, ("%s", msg));
	if (data != NULL && len > 0)
	{
		dump_data(11, data, len);
	}
#endif
}


/* see if a range of memory is all zero. A NULL pointer is considered
   to be all zero */
BOOL all_zero(const uint8_t *ptr, uint_t size)
{
	int i;
	if (!ptr) return True;
	for (i=0;i<size;i++) {
		if (ptr[i]) return False;
	}
	return True;
}

/*
  realloc an array, checking for integer overflow in the array size
*/
void *realloc_array(void *ptr, size_t el_size, unsigned count)
{
#define MAX_MALLOC_SIZE 0x7fffffff
	if (count == 0 ||
	    count >= MAX_MALLOC_SIZE/el_size) {
		return NULL;
	}
	if (!ptr) {
		return malloc(el_size * count);
	}
	return realloc(ptr, el_size * count);
}

