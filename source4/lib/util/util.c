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
#include "system/network.h"
#include "system/filesys.h"
#include "system/locale.h"

/**
 * @file
 * @brief Misc utility functions
 */

/**
 Find a suitable temporary directory. The result should be copied immediately
 as it may be overwritten by a subsequent call.
**/
_PUBLIC_ const char *tmpdir(void)
{
	char *p;
	if ((p = getenv("TMPDIR")))
		return p;
	return "/tmp";
}


/**
 Check if a file exists - call vfs_file_exist for samba files.
**/
_PUBLIC_ BOOL file_exist(const char *fname)
{
	struct stat st;

	if (stat(fname, &st) != 0) {
		return False;
	}

	return ((S_ISREG(st.st_mode)) || (S_ISFIFO(st.st_mode)));
}

/**
 Check a files mod time.
**/

_PUBLIC_ time_t file_modtime(const char *fname)
{
	struct stat st;
  
	if (stat(fname,&st) != 0) 
		return(0);

	return(st.st_mtime);
}

/**
 Check if a directory exists.
**/

_PUBLIC_ BOOL directory_exist(const char *dname)
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

/**
 * Try to create the specified directory if it didn't exist.
 *
 * @retval True if the directory already existed and has the right permissions 
 * or was successfully created.
 */
_PUBLIC_ BOOL directory_create_or_exist(const char *dname, uid_t uid, 
			       mode_t dir_perms)
{
	mode_t old_umask;
  	struct stat st;
      
	old_umask = umask(0);
	if (lstat(dname, &st) == -1) {
		if (errno == ENOENT) {
			/* Create directory */
			if (mkdir(dname, dir_perms) == -1) {
				DEBUG(0, ("error creating directory "
					  "%s: %s\n", dname, 
					  strerror(errno)));
				umask(old_umask);
				return False;
			}
		} else {
			DEBUG(0, ("lstat failed on directory %s: %s\n",
				  dname, strerror(errno)));
			umask(old_umask);
			return False;
		}
	} else {
		/* Check ownership and permission on existing directory */
		if (!S_ISDIR(st.st_mode)) {
			DEBUG(0, ("directory %s isn't a directory\n",
				dname));
			umask(old_umask);
			return False;
		}
		if ((st.st_uid != uid) || 
		    ((st.st_mode & 0777) != dir_perms)) {
			DEBUG(0, ("invalid permissions on directory "
				  "%s\n", dname));
			umask(old_umask);
			return False;
		}
	}
	return True;
}       


/*******************************************************************
 Close the low 3 fd's and open dev/null in their place.
********************************************************************/
static void close_low_fds(BOOL stderr_too)
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

/**
 Set a fd into blocking/nonblocking mode. Uses POSIX O_NONBLOCK if available,
 else
  if SYSV use O_NDELAY
  if BSD use FNDELAY
**/

_PUBLIC_ int set_blocking(int fd, BOOL set)
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


/**
 Sleep for a specified number of milliseconds.
**/

_PUBLIC_ void msleep(unsigned int t)
{
	struct timeval tval;  

	tval.tv_sec = t/1000;
	tval.tv_usec = 1000*(t%1000);
	/* this should be the real select - do NOT replace
	   with sys_select() */
	select(0,NULL,NULL,NULL,&tval);
}

/**
 Become a daemon, discarding the controlling terminal.
**/

_PUBLIC_ void become_daemon(BOOL Fork)
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

/**
 Get my own name, return in malloc'ed storage.
**/

_PUBLIC_ char* get_myname(void)
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
	p = strchr(hostname,'.');

	if (p)
		*p = 0;
	
	return hostname;
}

/**
 Return true if a string could be a pure IP address.
**/

_PUBLIC_ BOOL is_ipaddress(const char *str)
{
	BOOL pure_address = True;
	int i;
  
	for (i=0; pure_address && str[i]; i++)
		if (!(isdigit((int)str[i]) || str[i] == '.'))
			pure_address = False;

	/* Check that a pure number is not misinterpreted as an IP */
	pure_address = pure_address && (strchr(str, '.') != NULL);

	return pure_address;
}

/**
 Interpret an internet address or name into an IP address in 4 byte form.
**/
_PUBLIC_ uint32_t interpret_addr(const char *str)
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

/**
 A convenient addition to interpret_addr().
**/
_PUBLIC_ struct ipv4_addr interpret_addr2(const char *str)
{
	struct ipv4_addr ret;
	uint32_t a = interpret_addr(str);
	ret.addr = a;
	return ret;
}

/**
 Check if an IP is the 0.0.0.0.
**/

_PUBLIC_ BOOL is_zero_ip(struct ipv4_addr ip)
{
	return ip.addr == 0;
}

/**
 Are two IPs on the same subnet?
**/

_PUBLIC_ BOOL same_net(struct ipv4_addr ip1,struct ipv4_addr ip2,struct ipv4_addr mask)
{
	uint32_t net1,net2,nmask;

	nmask = ntohl(mask.addr);
	net1  = ntohl(ip1.addr);
	net2  = ntohl(ip2.addr);
            
	return((net1 & nmask) == (net2 & nmask));
}


/**
 Check if a process exists. Does this work on all unixes?
**/

_PUBLIC_ BOOL process_exists(pid_t pid)
{
	/* Doing kill with a non-positive pid causes messages to be
	 * sent to places we don't want. */
	SMB_ASSERT(pid > 0);
	return(kill(pid,0) == 0 || errno != ESRCH);
}

/**
 Simple routine to do POSIX file locking. Cruft in NFS and 64->32 bit mapping
 is dealt with in posix.c
**/

_PUBLIC_ BOOL fcntl_lock(int fd, int op, off_t offset, off_t count, int type)
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

/**
 * Write dump of binary data to the log file.
 *
 * The data is only written if the log level is at least level.
 */
_PUBLIC_ void dump_data(int level, const uint8_t *buf,int len)
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

/**
 malloc that aborts with smb_panic on fail or zero size.
**/

_PUBLIC_ void *smb_xmalloc(size_t size)
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

_PUBLIC_ void *smb_xmemdup(const void *p, size_t size)
{
	void *p2;
	p2 = smb_xmalloc(size);
	memcpy(p2, p, size);
	return p2;
}

/**
 strdup that aborts on malloc fail.
**/

_PUBLIC_ char *smb_xstrdup(const char *s)
{
	char *s1 = strdup(s);
	if (!s1)
		smb_panic("smb_xstrdup: malloc fail\n");
	return s1;
}


/**
 Like strdup but for memory.
**/

_PUBLIC_ void *memdup(const void *p, size_t size)
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

/**
 * Write a password to the log file.
 *
 * @note Only actually does something if DEBUG_PASSWORD was defined during 
 * compile-time.
 */
_PUBLIC_ void dump_data_pw(const char *msg, const uint8_t * data, size_t len)
{
#ifdef DEBUG_PASSWORD
	DEBUG(11, ("%s", msg));
	if (data != NULL && len > 0)
	{
		dump_data(11, data, len);
	}
#endif
}


/**
 * see if a range of memory is all zero. A NULL pointer is considered
 * to be all zero 
 */
_PUBLIC_ BOOL all_zero(const uint8_t *ptr, size_t size)
{
	int i;
	if (!ptr) return True;
	for (i=0;i<size;i++) {
		if (ptr[i]) return False;
	}
	return True;
}

/**
  realloc an array, checking for integer overflow in the array size
*/
_PUBLIC_ void *realloc_array(void *ptr, size_t el_size, unsigned count)
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

