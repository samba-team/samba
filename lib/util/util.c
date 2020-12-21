/* 
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Jeremy Allison 2001-2002
   Copyright (C) Simo Sorce 2001-2011
   Copyright (C) Jim McDonough (jmcd@us.ibm.com)  2003.
   Copyright (C) James J Myers 2003
   Copyright (C) Volker Lendecke 2010
   Copyright (C) Swen Schillig 2019

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"
#include <talloc.h>
#include "system/network.h"
#include "system/filesys.h"
#include "system/locale.h"
#include "system/shmem.h"
#include "system/passwd.h"
#include "system/time.h"
#include "system/wait.h"
#include "debug.h"
#include "samba_util.h"
#include "lib/util/select.h"
#include <libgen.h>

#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

#undef malloc
#undef strcasecmp
#undef strncasecmp
#undef strdup
#undef realloc
#undef calloc

/**
 * @file
 * @brief Misc utility functions
 */

/**
 * Convert a string to an unsigned long integer
 *
 * @param nptr		pointer to string which is to be converted
 * @param endptr	[optional] reference to remainder of the string
 * @param base		base of the numbering scheme
 * @param err		error occured during conversion
 * @flags		controlling conversion feature
 * @result		result of the conversion as provided by strtoul
 *
 * The following flags are supported
 *	SMB_STR_STANDARD # raise error if negative or non-numeric
 *	SMB_STR_ALLOW_NEGATIVE # allow strings with a leading "-"
 *	SMB_STR_FULL_STR_CONV # entire string must be converted
 *	SMB_STR_ALLOW_NO_CONVERSION # allow empty strings or non-numeric
 *	SMB_STR_GLIBC_STANDARD # act exactly as the standard glibc strtoul
 *
 * The following errors are detected
 * - wrong base
 * - value overflow
 * - string with a leading "-" indicating a negative number
 * - no conversion due to empty string or not representing a number
 */
unsigned long int
smb_strtoul(const char *nptr, char **endptr, int base, int *err, int flags)
{
	unsigned long int val;
	int saved_errno = errno;
	char *needle = NULL;
	char *tmp_endptr = NULL;

	errno = 0;
	*err = 0;

	val = strtoul(nptr, &tmp_endptr, base);

	if (endptr != NULL) {
		*endptr = tmp_endptr;
	}

	if (errno != 0) {
		*err = errno;
		errno = saved_errno;
		return val;
	}

	if ((flags & SMB_STR_ALLOW_NO_CONVERSION) == 0) {
		/* got an invalid number-string resulting in no conversion */
		if (nptr == tmp_endptr) {
			*err = EINVAL;
			goto out;
		}
	}

	if ((flags & SMB_STR_ALLOW_NEGATIVE ) == 0) {
		/* did we convert a negative "number" ? */
		needle = strchr(nptr, '-');
		if (needle != NULL && needle < tmp_endptr) {
			*err = EINVAL;
			goto out;
		}
	}

	if ((flags & SMB_STR_FULL_STR_CONV) != 0) {
		/* did we convert the entire string ? */
		if (tmp_endptr[0] != '\0') {
			*err = EINVAL;
			goto out;
		}
	}

out:
	errno = saved_errno;
	return val;
}

/**
 * Convert a string to an unsigned long long integer
 *
 * @param nptr		pointer to string which is to be converted
 * @param endptr	[optional] reference to remainder of the string
 * @param base		base of the numbering scheme
 * @param err		error occured during conversion
 * @flags		controlling conversion feature
 * @result		result of the conversion as provided by strtoull
 *
 * The following flags are supported
 *	SMB_STR_STANDARD # raise error if negative or non-numeric
 *	SMB_STR_ALLOW_NEGATIVE # allow strings with a leading "-"
 *	SMB_STR_FULL_STR_CONV # entire string must be converted
 *	SMB_STR_ALLOW_NO_CONVERSION # allow empty strings or non-numeric
 *	SMB_STR_GLIBC_STANDARD # act exactly as the standard glibc strtoul
 *
 * The following errors are detected
 * - wrong base
 * - value overflow
 * - string with a leading "-" indicating a negative number
 * - no conversion due to empty string or not representing a number
 */
unsigned long long int
smb_strtoull(const char *nptr, char **endptr, int base, int *err, int flags)
{
	unsigned long long int val;
	int saved_errno = errno;
	char *needle = NULL;
	char *tmp_endptr = NULL;

	errno = 0;
	*err = 0;

	val = strtoull(nptr, &tmp_endptr, base);

	if (endptr != NULL) {
		*endptr = tmp_endptr;
	}

	if (errno != 0) {
		*err = errno;
		errno = saved_errno;
		return val;
	}

	if ((flags & SMB_STR_ALLOW_NO_CONVERSION) == 0) {
		/* got an invalid number-string resulting in no conversion */
		if (nptr == tmp_endptr) {
			*err = EINVAL;
			goto out;
		}
	}

	if ((flags & SMB_STR_ALLOW_NEGATIVE ) == 0) {
		/* did we convert a negative "number" ? */
		needle = strchr(nptr, '-');
		if (needle != NULL && needle < tmp_endptr) {
			*err = EINVAL;
			goto out;
		}
	}

	if ((flags & SMB_STR_FULL_STR_CONV) != 0) {
		/* did we convert the entire string ? */
		if (tmp_endptr[0] != '\0') {
			*err = EINVAL;
			goto out;
		}
	}

out:
	errno = saved_errno;
	return val;
}

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
 Create a tmp file, open it and immediately unlink it.
 If dir is NULL uses tmpdir()
 Returns the file descriptor or -1 on error.
**/
int create_unlink_tmp(const char *dir)
{
	size_t len = strlen(dir ? dir : (dir = tmpdir()));
	char fname[len+25];
	int fd;
	mode_t mask;

	len = snprintf(fname, sizeof(fname), "%s/listenerlock_XXXXXX", dir);
	if (len >= sizeof(fname)) {
		errno = ENOMEM;
		return -1;
	}
	mask = umask(S_IRWXO | S_IRWXG);
	fd = mkstemp(fname);
	umask(mask);
	if (fd == -1) {
		return -1;
	}
	if (unlink(fname) == -1) {
		int sys_errno = errno;
		close(fd);
		errno = sys_errno;
		return -1;
	}
	return fd;
}


/**
 Check if a file exists - call vfs_file_exist for samba files.
**/
_PUBLIC_ bool file_exist(const char *fname)
{
	struct stat st;

	if (stat(fname, &st) != 0) {
		return false;
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
 Check file permissions.
**/

_PUBLIC_ bool file_check_permissions(const char *fname,
				     uid_t uid,
				     mode_t file_perms,
				     struct stat *pst)
{
	int ret;
	struct stat st;

	if (pst == NULL) {
		pst = &st;
	}

	ZERO_STRUCTP(pst);

	ret = stat(fname, pst);
	if (ret != 0) {
		DEBUG(0, ("stat failed on file '%s': %s\n",
			 fname, strerror(errno)));
		return false;
	}

	if (pst->st_uid != uid && !uid_wrapper_enabled()) {
		DEBUG(0, ("invalid ownership of file '%s': "
			 "owned by uid %u, should be %u\n",
			 fname, (unsigned int)pst->st_uid,
			 (unsigned int)uid));
		return false;
	}

	if ((pst->st_mode & 0777) != file_perms) {
		DEBUG(0, ("invalid permissions on file "
			 "'%s': has 0%o should be 0%o\n", fname,
			 (unsigned int)(pst->st_mode & 0777),
			 (unsigned int)file_perms));
		return false;
	}

	return true;
}

/**
 Check if a directory exists.
**/

_PUBLIC_ bool directory_exist(const char *dname)
{
	struct stat st;
	bool ret;

	if (stat(dname,&st) != 0) {
		return false;
	}

	ret = S_ISDIR(st.st_mode);
	if(!ret)
		errno = ENOTDIR;
	return ret;
}

/**
 * Try to create the specified directory if it didn't exist.
 * A symlink to a directory is also accepted as a valid existing directory.
 *
 * @retval true if the directory already existed
 * or was successfully created.
 */
_PUBLIC_ bool directory_create_or_exist(const char *dname,
					mode_t dir_perms)
{
	int ret;
	mode_t old_umask;

	/* Create directory */
	old_umask = umask(0);
	ret = mkdir(dname, dir_perms);
	if (ret == -1 && errno != EEXIST) {
		int dbg_level = geteuid() == 0 ? DBGLVL_ERR : DBGLVL_NOTICE;

		DBG_PREFIX(dbg_level,
			   ("mkdir failed on directory %s: %s\n",
			    dname,
			    strerror(errno)));
		umask(old_umask);
		return false;
	}
	umask(old_umask);

	if (ret != 0 && errno == EEXIST) {
		struct stat sbuf;

		ret = lstat(dname, &sbuf);
		if (ret != 0) {
			return false;
		}

		if (S_ISDIR(sbuf.st_mode)) {
			return true;
		}

		if (S_ISLNK(sbuf.st_mode)) {
			ret = stat(dname, &sbuf);
			if (ret != 0) {
				return false;
			}

			if (S_ISDIR(sbuf.st_mode)) {
				return true;
			}
		}

		return false;
	}

	return true;
}

_PUBLIC_ bool directory_create_or_exists_recursive(
		const char *dname,
		mode_t dir_perms)
{
	bool ok;

	ok = directory_create_or_exist(dname, dir_perms);
	if (!ok) {
		if (!directory_exist(dname)) {
			char tmp[PATH_MAX] = {0};
			char *parent = NULL;
			size_t n;

			/* Use the null context */
			n = strlcpy(tmp, dname, sizeof(tmp));
			if (n < strlen(dname)) {
				DBG_ERR("Path too long!\n");
				return false;
			}

			parent = dirname(tmp);
			if (parent == NULL) {
				DBG_ERR("Failed to create dirname!\n");
				return false;
			}

			ok = directory_create_or_exists_recursive(parent,
								  dir_perms);
			if (!ok) {
				return false;
			}

			ok = directory_create_or_exist(dname, dir_perms);
		}
	}

	return ok;
}

/**
 * @brief Try to create a specified directory if it doesn't exist.
 *
 * The function creates a directory with the given uid and permissions if it
 * doesn't exist. If it exists it makes sure the uid and permissions are
 * correct and it will fail if they are different.
 *
 * @param[in]  dname  The directory to create.
 *
 * @param[in]  uid    The uid the directory needs to belong too.
 *
 * @param[in]  dir_perms  The expected permissions of the directory.
 *
 * @return True on success, false on error.
 */
_PUBLIC_ bool directory_create_or_exist_strict(const char *dname,
					       uid_t uid,
					       mode_t dir_perms)
{
	struct stat st;
	bool ok;
	int rc;

	ok = directory_create_or_exist(dname, dir_perms);
	if (!ok) {
		return false;
	}

	rc = lstat(dname, &st);
	if (rc == -1) {
		DEBUG(0, ("lstat failed on created directory %s: %s\n",
			  dname, strerror(errno)));
		return false;
	}

	/* Check ownership and permission on existing directory */
	if (!S_ISDIR(st.st_mode)) {
		DEBUG(0, ("directory %s isn't a directory\n",
			dname));
		return false;
	}
	if (st.st_uid != uid && !uid_wrapper_enabled()) {
		DBG_NOTICE("invalid ownership on directory "
			  "%s\n", dname);
		return false;
	}
	if ((st.st_mode & 0777) != dir_perms) {
		DEBUG(0, ("invalid permissions on directory "
			  "'%s': has 0%o should be 0%o\n", dname,
			  (unsigned int)(st.st_mode & 0777), (unsigned int)dir_perms));
		return false;
	}

	return true;
}


/**
 Sleep for a specified number of milliseconds.
**/

_PUBLIC_ void smb_msleep(unsigned int t)
{
	sys_poll_intr(NULL, 0, t);
}

/**
 Get my own name, return in talloc'ed storage.
**/

_PUBLIC_ char *get_myname(TALLOC_CTX *ctx)
{
	char *p;
	char hostname[HOST_NAME_MAX];

	/* get my host name */
	if (gethostname(hostname, sizeof(hostname)) == -1) {
		DEBUG(0,("gethostname failed\n"));
		return NULL;
	}

	/* Ensure null termination. */
	hostname[sizeof(hostname)-1] = '\0';

	/* split off any parts after an initial . */
	p = strchr_m(hostname, '.');
	if (p) {
		*p = 0;
	}

	return talloc_strdup(ctx, hostname);
}

/**
 Check if a process exists. Does this work on all unixes?
**/

_PUBLIC_ bool process_exists_by_pid(pid_t pid)
{
	/* Doing kill with a non-positive pid causes messages to be
	 * sent to places we don't want. */
	if (pid <= 0) {
		return false;
	}
	return(kill(pid,0) == 0 || errno != ESRCH);
}

/**
 Simple routine to do POSIX file locking. Cruft in NFS and 64->32 bit mapping
 is dealt with in posix.c
**/

_PUBLIC_ bool fcntl_lock(int fd, int op, off_t offset, off_t count, int type)
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
			return true;
		}

		/* it must be not locked or locked by me */
		return false;
	}

	/* a lock set or unset */
	if (ret == -1) {
		DEBUG(3,("fcntl_lock: lock failed at offset %.0f count %.0f op %d type %d (%s)\n",
			(double)offset,(double)count,op,type,strerror(errno)));
		return false;
	}

	/* everything went OK */
	DEBUG(8,("fcntl_lock: Lock call successful\n"));

	return true;
}

struct debug_channel_level {
	int channel;
	int level;
};

static void debugadd_channel_cb(const char *buf, void *private_data)
{
	struct debug_channel_level *dcl =
		(struct debug_channel_level *)private_data;

	DEBUGADDC(dcl->channel, dcl->level,("%s", buf));
}

static void debugadd_cb(const char *buf, void *private_data)
{
	int *plevel = (int *)private_data;
	DEBUGADD(*plevel, ("%s", buf));
}

void print_asc_cb(const uint8_t *buf, int len,
		  void (*cb)(const char *buf, void *private_data),
		  void *private_data)
{
	int i;
	char s[2];
	s[1] = 0;

	for (i=0; i<len; i++) {
		s[0] = isprint(buf[i]) ? buf[i] : '.';
		cb(s, private_data);
	}
}

void print_asc(int level, const uint8_t *buf,int len)
{
	print_asc_cb(buf, len, debugadd_cb, &level);
}

/**
 * Write dump of binary data to a callback
 */
void dump_data_cb(const uint8_t *buf, int len,
		  bool omit_zero_bytes,
		  void (*cb)(const char *buf, void *private_data),
		  void *private_data)
{
	int i=0;
	bool skipped = false;
	char tmp[16];

	if (len<=0) return;

	for (i=0;i<len;) {

		if (i%16 == 0) {
			if ((omit_zero_bytes == true) &&
			    (i > 0) &&
			    (len > i+16) &&
			    all_zero(&buf[i], 16))
			{
				i +=16;
				continue;
			}

			if (i<len)  {
				snprintf(tmp, sizeof(tmp), "[%04X] ", i);
				cb(tmp, private_data);
			}
		}

		snprintf(tmp, sizeof(tmp), "%02X ", (int)buf[i]);
		cb(tmp, private_data);
		i++;
		if (i%8 == 0) {
			cb("  ", private_data);
		}
		if (i%16 == 0) {

			print_asc_cb(&buf[i-16], 8, cb, private_data);
			cb(" ", private_data);
			print_asc_cb(&buf[i-8], 8, cb, private_data);
			cb("\n", private_data);

			if ((omit_zero_bytes == true) &&
			    (len > i+16) &&
			    all_zero(&buf[i], 16)) {
				if (!skipped) {
					cb("skipping zero buffer bytes\n",
					   private_data);
					skipped = true;
				}
			}
		}
	}

	if (i%16) {
		int n;
		n = 16 - (i%16);
		cb("  ", private_data);
		if (n>8) {
			cb(" ", private_data);
		}
		while (n--) {
			cb("   ", private_data);
		}
		n = MIN(8,i%16);
		print_asc_cb(&buf[i-(i%16)], n, cb, private_data);
		cb(" ", private_data);
		n = (i%16) - n;
		if (n>0) {
			print_asc_cb(&buf[i-n], n, cb, private_data);
		}
		cb("\n", private_data);
	}

}

/**
 * Write dump of binary data to the log file.
 *
 * The data is only written if the log level is at least level.
 */
_PUBLIC_ void dump_data(int level, const uint8_t *buf, int len)
{
	if (!DEBUGLVL(level)) {
		return;
	}
	dump_data_cb(buf, len, false, debugadd_cb, &level);
}

/**
 * Write dump of binary data to the log file.
 *
 * The data is only written if the log level is at least level for
 * debug class dbgc_class.
 */
_PUBLIC_ void dump_data_dbgc(int dbgc_class, int level, const uint8_t *buf, int len)
{
	struct debug_channel_level dcl = { dbgc_class, level };

	if (!DEBUGLVLC(dbgc_class, level)) {
		return;
	}
	dump_data_cb(buf, len, false, debugadd_channel_cb, &dcl);
}

/**
 * Write dump of binary data to the log file.
 *
 * The data is only written if the log level is at least level.
 * 16 zero bytes in a row are omitted
 */
_PUBLIC_ void dump_data_skip_zeros(int level, const uint8_t *buf, int len)
{
	if (!DEBUGLVL(level)) {
		return;
	}
	dump_data_cb(buf, len, true, debugadd_cb, &level);
}

static void fprintf_cb(const char *buf, void *private_data)
{
	FILE *f = (FILE *)private_data;
	fprintf(f, "%s", buf);
}

void dump_data_file(const uint8_t *buf, int len, bool omit_zero_bytes,
		    FILE *f)
{
	dump_data_cb(buf, len, omit_zero_bytes, fprintf_cb, f);
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

char *smb_xstrdup(const char *s)
{
#if defined(PARANOID_MALLOC_CHECKER)
#ifdef strdup
#undef strdup
#endif
#endif

#ifndef HAVE_STRDUP
#define strdup rep_strdup
#endif

	char *s1 = strdup(s);
#if defined(PARANOID_MALLOC_CHECKER)
#ifdef strdup
#undef strdup
#endif
#define strdup(s) __ERROR_DONT_USE_STRDUP_DIRECTLY
#endif
	if (!s1) {
		smb_panic("smb_xstrdup: malloc failed");
	}
	return s1;

}

/**
 strndup that aborts on malloc fail.
**/

char *smb_xstrndup(const char *s, size_t n)
{
#if defined(PARANOID_MALLOC_CHECKER)
#ifdef strndup
#undef strndup
#endif
#endif

#if (defined(BROKEN_STRNDUP) || !defined(HAVE_STRNDUP))
#undef HAVE_STRNDUP
#define strndup rep_strndup
#endif

	char *s1 = strndup(s, n);
#if defined(PARANOID_MALLOC_CHECKER)
#ifdef strndup
#undef strndup
#endif
#define strndup(s,n) __ERROR_DONT_USE_STRNDUP_DIRECTLY
#endif
	if (!s1) {
		smb_panic("smb_xstrndup: malloc failed");
	}
	return s1;
}



/**
 Like strdup but for memory.
**/

_PUBLIC_ void *smb_memdup(const void *p, size_t size)
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
_PUBLIC_ bool all_zero(const uint8_t *ptr, size_t size)
{
	size_t i;
	if (!ptr) return true;
	for (i=0;i<size;i++) {
		if (ptr[i]) return false;
	}
	return true;
}

/**
  realloc an array, checking for integer overflow in the array size
*/
_PUBLIC_ void *realloc_array(void *ptr, size_t el_size, unsigned count, bool free_on_fail)
{
#define MAX_MALLOC_SIZE 0x7fffffff
	if (count == 0 ||
	    count >= MAX_MALLOC_SIZE/el_size) {
		if (free_on_fail)
			SAFE_FREE(ptr);
		return NULL;
	}
	if (!ptr) {
		return malloc(el_size * count);
	}
	return realloc(ptr, el_size * count);
}

/****************************************************************************
 Type-safe malloc.
****************************************************************************/

void *malloc_array(size_t el_size, unsigned int count)
{
	return realloc_array(NULL, el_size, count, false);
}

/****************************************************************************
 Type-safe memalign
****************************************************************************/

void *memalign_array(size_t el_size, size_t align, unsigned int count)
{
	if (el_size == 0 || count >= MAX_MALLOC_SIZE/el_size) {
		return NULL;
	}

	return memalign(align, el_size*count);
}

/****************************************************************************
 Type-safe calloc.
****************************************************************************/

void *calloc_array(size_t size, size_t nmemb)
{
	if (nmemb >= MAX_MALLOC_SIZE/size) {
		return NULL;
	}
	if (size == 0 || nmemb == 0) {
		return NULL;
	}
	return calloc(nmemb, size);
}

/**
 Trim the specified elements off the front and back of a string.
**/
_PUBLIC_ bool trim_string(char *s, const char *front, const char *back)
{
	bool ret = false;
	size_t front_len;
	size_t back_len;
	size_t len;

	/* Ignore null or empty strings. */
	if (!s || (s[0] == '\0')) {
		return false;
	}
	len = strlen(s);

	front_len	= front? strlen(front) : 0;
	back_len	= back? strlen(back) : 0;

	if (front_len) {
		size_t front_trim = 0;

		while (strncmp(s+front_trim, front, front_len)==0) {
			front_trim += front_len;
		}
		if (front_trim > 0) {
			/* Must use memmove here as src & dest can
			 * easily overlap. Found by valgrind. JRA. */
			memmove(s, s+front_trim, (len-front_trim)+1);
			len -= front_trim;
			ret=true;
		}
	}

	if (back_len) {
		while ((len >= back_len) && strncmp(s+len-back_len,back,back_len)==0) {
			s[len-back_len]='\0';
			len -= back_len;
			ret=true;
		}
	}
	return ret;
}

/**
 Find the number of 'c' chars in a string
**/
_PUBLIC_ _PURE_ size_t count_chars(const char *s, char c)
{
	size_t count = 0;

	while (*s) {
		if (*s == c) count++;
		s ++;
	}

	return count;
}

/**
 * Routine to get hex characters and turn them into a byte array.
 * the array can be variable length.
 * -  "0xnn" or "0Xnn" is specially catered for.
 * - The first non-hex-digit character (apart from possibly leading "0x"
 *   finishes the conversion and skips the rest of the input.
 * - A single hex-digit character at the end of the string is skipped.
 *
 * valid examples: "0A5D15"; "0x123456"
 */
_PUBLIC_ size_t strhex_to_str(char *p, size_t p_len, const char *strhex, size_t strhex_len)
{
	size_t i = 0;
	size_t num_chars = 0;
	uint8_t   lonybble, hinybble;
	const char     *hexchars = "0123456789ABCDEF";
	char           *p1 = NULL, *p2 = NULL;

	/* skip leading 0x prefix */
	if (strncasecmp(strhex, "0x", 2) == 0) {
		i += 2; /* skip two chars */
	}

	for (; i+1 < strhex_len && strhex[i] != 0 && strhex[i+1] != 0; i++) {
		p1 = strchr(hexchars, toupper((unsigned char)strhex[i]));
		if (p1 == NULL) {
			break;
		}

		i++; /* next hex digit */

		p2 = strchr(hexchars, toupper((unsigned char)strhex[i]));
		if (p2 == NULL) {
			break;
		}

		/* get the two nybbles */
		hinybble = PTR_DIFF(p1, hexchars);
		lonybble = PTR_DIFF(p2, hexchars);

		if (num_chars >= p_len) {
			break;
		}

		p[num_chars] = (hinybble << 4) | lonybble;
		num_chars++;

		p1 = NULL;
		p2 = NULL;
	}
	return num_chars;
}

/**
 * Parse a hex string and return a data blob.
 */
_PUBLIC_ _PURE_ DATA_BLOB strhex_to_data_blob(TALLOC_CTX *mem_ctx, const char *strhex) 
{
	DATA_BLOB ret_blob = data_blob_talloc(mem_ctx, NULL, strlen(strhex)/2+1);

	ret_blob.length = strhex_to_str((char *)ret_blob.data, ret_blob.length,
					strhex,
					strlen(strhex));

	return ret_blob;
}

/**
 * Parse a hex dump and return a data blob. Hex dump is structured as 
 * is generated from dump_data_cb() elsewhere in this file
 * 
 */
_PUBLIC_ _PURE_ DATA_BLOB hexdump_to_data_blob(TALLOC_CTX *mem_ctx, const char *hexdump, size_t hexdump_len)
{
	DATA_BLOB ret_blob = { 0 };
	size_t i = 0;
	size_t char_count = 0;
	/* hexdump line length is 77 chars long. We then use the ASCII representation of the bytes
	 * at the end of the final line to calculate how many are in that line, minus the extra space
	 * and newline. */
	size_t hexdump_byte_count = (16 * (hexdump_len / 77));
	if (hexdump_len % 77) {
		hexdump_byte_count += ((hexdump_len % 77) - 59 - 2);
	}
	
	ret_blob = data_blob_talloc(mem_ctx, NULL, hexdump_byte_count+1);
	for (; i+1 < hexdump_len && hexdump[i] != 0 && hexdump[i+1] != 0; i++) {
		if ((i%77) == 0) 
			i += 7; /* Skip the offset at the start of the line */
		if ((i%77) < 56) { /* position 56 is after both hex chunks */
			if (hexdump[i] != ' ') {
				char_count += strhex_to_str((char *)&ret_blob.data[char_count],
							    hexdump_byte_count - char_count,
							    &hexdump[i], 2);
				i += 2;
			} else {
				i++;
			}
		} else {
			i++;
		}
	}
	ret_blob.length = char_count;
	
	return ret_blob;
}

/**
 * Print a buf in hex. Assumes dst is at least (srclen*2)+1 large.
 */
_PUBLIC_ void hex_encode_buf(char *dst, const uint8_t *src, size_t srclen)
{
	size_t i;
	for (i=0; i<srclen; i++) {
		snprintf(dst + i*2, 3, "%02X", src[i]);
	}
	/*
	 * Ensure 0-termination for 0-length buffers
	 */
	dst[srclen*2] = '\0';
}

/**
 * talloc version of hex_encode_buf()
 */
_PUBLIC_ char *hex_encode_talloc(TALLOC_CTX *mem_ctx, const unsigned char *buff_in, size_t len)
{
	char *hex_buffer;

	hex_buffer = talloc_array(mem_ctx, char, (len*2)+1);
	if (!hex_buffer) {
		return NULL;
	}
	hex_encode_buf(hex_buffer, buff_in, len);
	talloc_set_name_const(hex_buffer, hex_buffer);
	return hex_buffer;
}

/**
  varient of strcmp() that handles NULL ptrs
**/
_PUBLIC_ int strcmp_safe(const char *s1, const char *s2)
{
	if (s1 == s2) {
		return 0;
	}
	if (s1 == NULL || s2 == NULL) {
		return s1?-1:1;
	}
	return strcmp(s1, s2);
}


/**
return the number of bytes occupied by a buffer in ASCII format
the result includes the null termination
limited by 'n' bytes
**/
_PUBLIC_ size_t ascii_len_n(const char *src, size_t n)
{
	size_t len;

	len = strnlen(src, n);
	if (len+1 <= n) {
		len += 1;
	}

	return len;
}

struct anonymous_shared_header {
	union {
		size_t length;
		uint8_t pad[16];
	} u;
};

/* Map a shared memory buffer of at least nelem counters. */
void *anonymous_shared_allocate(size_t orig_bufsz)
{
	void *ptr;
	void *buf;
	size_t pagesz = getpagesize();
	size_t pagecnt;
	size_t bufsz = orig_bufsz;
	struct anonymous_shared_header *hdr;

	bufsz += sizeof(*hdr);

	/* round up to full pages */
	pagecnt = bufsz / pagesz;
	if (bufsz % pagesz) {
		pagecnt += 1;
	}
	bufsz = pagesz * pagecnt;

	if (orig_bufsz >= bufsz) {
		/* integer wrap */
		errno = ENOMEM;
		return NULL;
	}

#ifdef MAP_ANON
	/* BSD */
	buf = mmap(NULL, bufsz, PROT_READ|PROT_WRITE, MAP_ANON|MAP_SHARED,
			-1 /* fd */, 0 /* offset */);
#else
{
	int saved_errno;
	int fd;

	fd = open("/dev/zero", O_RDWR);
	if (fd == -1) {
		return NULL;
	}

	buf = mmap(NULL, bufsz, PROT_READ|PROT_WRITE, MAP_FILE|MAP_SHARED,
		   fd, 0 /* offset */);
	saved_errno = errno;
	close(fd);
	errno = saved_errno;
}
#endif

	if (buf == MAP_FAILED) {
		return NULL;
	}

	hdr = (struct anonymous_shared_header *)buf;
	hdr->u.length = bufsz;

	ptr = (void *)(&hdr[1]);

	return ptr;
}

void *anonymous_shared_resize(void *ptr, size_t new_size, bool maymove)
{
#ifdef HAVE_MREMAP
	void *buf;
	size_t pagesz = getpagesize();
	size_t pagecnt;
	size_t bufsz;
	struct anonymous_shared_header *hdr;
	int flags = 0;

	if (ptr == NULL) {
		errno = EINVAL;
		return NULL;
	}

	hdr = (struct anonymous_shared_header *)ptr;
	hdr--;
	if (hdr->u.length > (new_size + sizeof(*hdr))) {
		errno = EINVAL;
		return NULL;
	}

	bufsz = new_size + sizeof(*hdr);

	/* round up to full pages */
	pagecnt = bufsz / pagesz;
	if (bufsz % pagesz) {
		pagecnt += 1;
	}
	bufsz = pagesz * pagecnt;

	if (new_size >= bufsz) {
		/* integer wrap */
		errno = ENOSPC;
		return NULL;
	}

	if (bufsz <= hdr->u.length) {
		return ptr;
	}

	if (maymove) {
		flags = MREMAP_MAYMOVE;
	}

	buf = mremap(hdr, hdr->u.length, bufsz, flags);

	if (buf == MAP_FAILED) {
		errno = ENOSPC;
		return NULL;
	}

	hdr = (struct anonymous_shared_header *)buf;
	hdr->u.length = bufsz;

	ptr = (void *)(&hdr[1]);

	return ptr;
#else
	errno = ENOSPC;
	return NULL;
#endif
}

void anonymous_shared_free(void *ptr)
{
	struct anonymous_shared_header *hdr;

	if (ptr == NULL) {
		return;
	}

	hdr = (struct anonymous_shared_header *)ptr;

	hdr--;

	munmap(hdr, hdr->u.length);
}

#ifdef DEVELOPER
/* used when you want a debugger started at a particular point in the
   code. Mostly useful in code that runs as a child process, where
   normal gdb attach is harder to organise.
*/
void samba_start_debugger(void)
{
	char *cmd = NULL;
#if defined(HAVE_PRCTL) && defined(PR_SET_PTRACER)
	/*
	 * Make sure all children can attach a debugger.
	 */
	prctl(PR_SET_PTRACER, getpid(), 0, 0, 0);
#endif
	if (asprintf(&cmd, "xterm -e \"gdb --pid %u\"&", getpid()) == -1) {
		return;
	}
	if (system(cmd) == -1) {
		free(cmd);
		return;
	}
	free(cmd);
	sleep(2);
}
#endif
