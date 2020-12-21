/* 
   Unix SMB/CIFS implementation.
   Utility functions for Samba
   Copyright (C) Andrew Tridgell 1992-1999
   Copyright (C) Jelmer Vernooij 2005
    
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

#ifndef _SAMBA_UTIL_H_
#define _SAMBA_UTIL_H_

#ifndef SAMBA_UTIL_CORE_ONLY
#include "lib/util/charset/charset.h"
#else
#include "charset_compat.h"
#endif

#include "lib/util/attr.h"

/* for TALLOC_CTX */
#include <talloc.h>

/* for struct stat */
#include <sys/stat.h>

/**
 * @file
 * @brief Helpful macros
 */

struct smbsrv_tcon;

extern const char *panic_action;

#include "lib/util/time.h"
#include "lib/util/data_blob.h"
#include "lib/util/byteorder.h"
#include "lib/util/talloc_stack.h"
#include "lib/util/talloc_keep_secret.h"

#ifndef ABS
#define ABS(a) ((a)>0?(a):(-(a)))
#endif

#include "lib/util/memory.h"
#include "lib/util/discard.h"

#include "fault.h"

#include "lib/util/util.h"

/**
 * Write backtrace to debug log
 */
_PUBLIC_ void dump_core_setup(const char *progname, const char *logfile);

/**
  register a fault handler. 
  Should only be called once in the execution of smbd.
*/
_PUBLIC_ bool register_fault_handler(const char *name, void (*fault_handler)(int sig));

#include "lib/util/signal.h" /* Avoid /usr/include/signal.h */

struct sockaddr;

_PUBLIC_ int sys_getnameinfo(const struct sockaddr *psa,
			     int salen,
			     char *host,
			     size_t hostlen,
			     char *service,
			     size_t servlen,
			     int flags);

/* The following definitions come from lib/util/genrand.c  */

#include "lib/util/genrand.h"

/**
  generate a single random uint32_t
**/
_PUBLIC_ uint32_t generate_random(void);

/**
 * generate a single random uint64_t
 * @see generate_unique_u64
**/
_PUBLIC_ uint64_t generate_random_u64(void);

/**
 * @brief Generate random nonces usable for re-use detection.
 *
 * We have a lot of places which require a unique id that can
 * be used as a unique identitier for caching states.
 *
 * Always using generate_nonce_buffer() has it's performance costs,
 * it's typically much better than generate_random_buffer(), but
 * still it's overhead we want to avoid in performance critical
 * workloads.
 *
 * We call generate_nonce_buffer() just once per given state
 * and process.
 *
 * This is much lighter than generate_random_u64() and it's
 * designed for performance critical code paths.
 *
 * @veto_value It is garanteed that the return value if different from
 *             the veto_value.
 *
 * @return a unique value per given state and process
 *
 * @see generate_random_u64
 */
uint64_t generate_unique_u64(uint64_t veto_value);

/**
  very basic password quality checker
**/
_PUBLIC_ bool check_password_quality(const char *s);

/**
 * Generate a random text password (based on printable ascii characters).
 * This function is designed to provide a password that
 * meats the complexity requirements of UF_NORMAL_ACCOUNT objects
 * and they should be human readable and writeable on any keyboard layout.
 *
 * Characters used are:
 * ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+_-#.,@$%&!?:;<=>()[]~
 */
_PUBLIC_ char *generate_random_password(TALLOC_CTX *mem_ctx, size_t min, size_t max);

/**
 * Generate a random machine password
 *
 * min and max are the number of utf16 characters used
 * to generate on utf8 compatible password.
 *
 * Note: if 'unix charset' is not 'utf8' (the default)
 * then each utf16 character is only filled with
 * values from 0x01 to 0x7f (ascii values without 0x00).
 * This is important as the password neets to be
 * a valid value as utf8 string and at the same time
 * a valid value in the 'unix charset'.
 *
 * If 'unix charset' is 'utf8' (the default) then
 * each utf16 character is a random value from 0x0000
 * 0xFFFF (exluding the surrogate ranges from 0xD800-0xDFFF)
 * while the translation from CH_UTF16MUNGED
 * to CH_UTF8 replaces invalid values (see utf16_munged_pull()).
 *
 * Note: these passwords may not pass the complexity requirements
 * for UF_NORMAL_ACCOUNT objects (except krbtgt accounts).
 */
_PUBLIC_ char *generate_random_machine_password(TALLOC_CTX *mem_ctx, size_t min, size_t max);

/**
 Use the random number generator to generate a random string.
**/
_PUBLIC_ char *generate_random_str_list(TALLOC_CTX *mem_ctx, size_t len, const char *list);

/**
 * Generate a random text string consisting of the specified length.
 * The returned string will be allocated.
 *
 * Characters used are: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+_-#.,
 */
_PUBLIC_ char *generate_random_str(TALLOC_CTX *mem_ctx, size_t len);

/**
 * Generate an array of unique text strings all of the same length.
 * The returned strings will be allocated.
 * Returns NULL if the number of unique combinations cannot be created.
 *
 * Characters used are: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+_-#.,
 */
_PUBLIC_ char** generate_unique_strs(TALLOC_CTX *mem_ctx, size_t len,
					 uint32_t num);

/* The following definitions come from lib/util/dprintf.c  */

_PUBLIC_ int d_fprintf(FILE *f, const char *format, ...) PRINTF_ATTRIBUTE(2,3);
_PUBLIC_ int d_printf(const char *format, ...) PRINTF_ATTRIBUTE(1,2);
_PUBLIC_ void display_set_stderr(void);

/* The following definitions come from lib/util/util_str.c  */

bool next_token_talloc(TALLOC_CTX *ctx,
			const char **ptr,
			char **pp_buff,
			const char *sep);

/**
 * Get the next token from a string, return false if none found.  Handles
 * double-quotes.  This version does not trim leading separator characters
 * before looking for a token.
 */
bool next_token_no_ltrim_talloc(TALLOC_CTX *ctx,
			const char **ptr,
			char **pp_buff,
			const char *sep);


/**
 Trim the specified elements off the front and back of a string.
**/
_PUBLIC_ bool trim_string(char *s, const char *front, const char *back);

/**
 Find the number of 'c' chars in a string
**/
_PUBLIC_ _PURE_ size_t count_chars(const char *s, char c);

/**
 Routine to get hex characters and turn them into a 16 byte array.
 the array can be variable length, and any non-hex-numeric
 characters are skipped.  "0xnn" or "0Xnn" is specially catered
 for.

 valid examples: "0A5D15"; "0x15, 0x49, 0xa2"; "59\ta9\te3\n"


**/
_PUBLIC_ size_t strhex_to_str(char *p, size_t p_len, const char *strhex, size_t strhex_len);

/** 
 * Parse a hex string and return a data blob. 
 */
_PUBLIC_ _PURE_ DATA_BLOB strhex_to_data_blob(TALLOC_CTX *mem_ctx, const char *strhex) ;

/**
 * Parse a hex dump and return a data blob
 */
_PUBLIC_ _PURE_ DATA_BLOB hexdump_to_data_blob(TALLOC_CTX *mem_ctx, const char *hexdump, size_t len);

/**
 * Print a buf in hex. Assumes dst is at least (srclen*2)+1 large.
 */
_PUBLIC_ void hex_encode_buf(char *dst, const uint8_t *src, size_t srclen);

/**
 * talloc version of hex_encode_buf()
 */
_PUBLIC_ char *hex_encode_talloc(TALLOC_CTX *mem_ctx, const unsigned char *buff_in, size_t len);

#include "substitute.h"

/**
 Unescape a URL encoded string, in place.
**/
_PUBLIC_ char *rfc1738_unescape(char *buf);

/**
 * rfc1738_escape_part 
 * Returns a static buffer that contains the RFC
 * 1738 compliant, escaped version of the given url segment. (escapes
 * unsafe, reserved and % chars) It would mangle the :// in http://,
 * and mangle paths (because of /).
 **/
_PUBLIC_ char *rfc1738_escape_part(TALLOC_CTX *mem_ctx, const char *url);

/**
  varient of strcmp() that handles NULL ptrs
**/
_PUBLIC_ int strcmp_safe(const char *s1, const char *s2);

/**
return the number of bytes occupied by a buffer in ASCII format
the result includes the null termination
limited by 'n' bytes
**/
_PUBLIC_ size_t ascii_len_n(const char *src, size_t n);

/**
 Set a boolean variable from the text value stored in the passed string.
 Returns true in success, false if the passed string does not correctly 
 represent a boolean.
**/
_PUBLIC_ bool set_boolean(const char *boolean_string, bool *boolean);

/**
 * Parse a string containing a boolean value.
 *
 * val will be set to the read value.
 *
 * @retval true if a boolean value was parsed, false otherwise.
 */
_PUBLIC_ bool conv_str_bool(const char * str, bool * val);

/**
 * Convert a size specification like 16K into an integral number of bytes. 
 **/
_PUBLIC_ bool conv_str_size_error(const char * str, uint64_t * val);

/**
 * Parse a uint64_t value from a string
 *
 * val will be set to the value read.
 *
 * @retval true if parsing was successful, false otherwise
 */
_PUBLIC_ bool conv_str_u64(const char * str, uint64_t * val);

/**
return the number of bytes occupied by a buffer in CH_UTF16 format
the result includes the null termination
**/
_PUBLIC_ size_t utf16_len(const void *buf);

/**
return the number of bytes occupied by a buffer in CH_UTF16 format
the result includes the null termination
limited by 'n' bytes
**/
_PUBLIC_ size_t utf16_len_n(const void *src, size_t n);
_PUBLIC_ size_t ucs2_align(const void *base_ptr, const void *p, int flags);

/**
 * @brief Constant time compare to memory regions.
 *
 * @param[in]  s1  The first memory region to compare.
 *
 * @param[in]  s2  The second memory region to compare.
 *
 * @param[in]  n   The length of the memory to comapre.
 *
 * @return 0 when the memory regions are equal, 0 if not.
 */
_PUBLIC_ int memcmp_const_time(const void *s1, const void *s2, size_t n);

/**
Do a case-insensitive, whitespace-ignoring string compare.
**/
_PUBLIC_ int strwicmp(const char *psz1, const char *psz2);

/**
 String replace.
**/
_PUBLIC_ void string_replace(char *s, char oldc, char newc);

/**
 * Compare 2 strings.
 *
 * @note The comparison is case-insensitive.
 **/
_PUBLIC_ bool strequal(const char *s1, const char *s2);

#include "util_strlist.h"

/* The following definitions come from lib/util/util_strlist_v3.c  */

/**
 * Needed for making an "unconst" list "const"
 */
_PUBLIC_ const char **const_str_list(char **list);

/**
 * str_list_make, v3 version. The v4 version does not
 * look at quoted strings with embedded blanks, so
 * do NOT merge this function please!
 */
char **str_list_make_v3(TALLOC_CTX *mem_ctx, const char *string,
	const char *sep);


const char **str_list_make_v3_const(TALLOC_CTX *mem_ctx,
				    const char *string,
				    const char *sep);

/* The following definitions come from lib/util/util_file.c  */


/**
 * Read one line (data until next newline or eof) and allocate it 
 */
_PUBLIC_ char *afdgets(int fd, TALLOC_CTX *mem_ctx, size_t hint);

char *fgets_slash(TALLOC_CTX *mem_ctx, char *s2, size_t maxlen, FILE *f);

/**
load a file into memory from a fd.
**/
_PUBLIC_ char *fd_load(int fd, size_t *size, size_t maxsize, TALLOC_CTX *mem_ctx);


char **file_lines_parse(char *p, size_t size, int *numlines, TALLOC_CTX *mem_ctx);

/**
load a file into memory
**/
_PUBLIC_ char *file_load(const char *fname, size_t *size, size_t maxsize, TALLOC_CTX *mem_ctx);

/**
load a file into memory and return an array of pointers to lines in the file
must be freed with talloc_free(). 
**/
_PUBLIC_ char **file_lines_load(const char *fname, int *numlines, size_t maxsize, TALLOC_CTX *mem_ctx);

/**
load a fd into memory and return an array of pointers to lines in the file
must be freed with talloc_free(). If convert is true calls unix_to_dos on
the list.
**/
_PUBLIC_ char **fd_lines_load(int fd, int *numlines, size_t maxsize, TALLOC_CTX *mem_ctx);

_PUBLIC_ bool file_save_mode(const char *fname, const void *packet,
			     size_t length, mode_t mode);
/**
  save a lump of data into a file. Mostly used for debugging 
*/
_PUBLIC_ bool file_save(const char *fname, const void *packet, size_t length);
_PUBLIC_ int vfdprintf(int fd, const char *format, va_list ap) PRINTF_ATTRIBUTE(2,0);
_PUBLIC_ int fdprintf(int fd, const char *format, ...) PRINTF_ATTRIBUTE(2,3);

/*
  compare two files, return true if the two files have the same content
 */
bool file_compare(const char *path1, const char *path2);

/*
  load from a pipe into memory.
 */
char *file_ploadv(char * const argl[], size_t *size);

/* The following definitions come from lib/util/util.c  */


/**
 Find a suitable temporary directory. The result should be copied immediately
 as it may be overwritten by a subsequent call.
**/
_PUBLIC_ const char *tmpdir(void);

/**
 * Creates and immediately unlinks a file. Returns open file descriptor.
 **/
_PUBLIC_ int create_unlink_tmp(const char *dir);

/**
 Check if a file exists - call vfs_file_exist for samba files.
**/
_PUBLIC_ bool file_exist(const char *fname);

/**
 Check a files mod time.
**/
_PUBLIC_ time_t file_modtime(const char *fname);

/**
 Check if a directory exists.
**/
_PUBLIC_ bool directory_exist(const char *dname);

/**
 Check file permissions.
**/
_PUBLIC_ bool file_check_permissions(const char *fname,
				     uid_t uid,
				     mode_t file_perms,
				     struct stat *pst);

/**
 * Try to create the specified directory if it didn't exist.
 *
 * @retval true if the directory already existed and has the right permissions 
 * or was successfully created.
 */
_PUBLIC_ bool directory_create_or_exist(const char *dname, mode_t dir_perms);

/**
 * @brief Try to create a specified directory and the parent directory if they
 *        don't exist.
 *
 * @param[in]  dname     The directory path to create.
 *
 * @param[in]  dir_perms The permission of the directories.
 *
 * @return true on success, false otherwise.
 */
_PUBLIC_ bool directory_create_or_exists_recursive(
		const char *dname,
		mode_t dir_perms);

_PUBLIC_ bool directory_create_or_exist_strict(const char *dname,
					       uid_t uid,
					       mode_t dir_perms);

#include "blocking.h"

/**
 Sleep for a specified number of milliseconds.
**/
_PUBLIC_ void smb_msleep(unsigned int t);

/**
 Get my own name, return in talloc'ed storage.
**/
_PUBLIC_ char* get_myname(TALLOC_CTX *mem_ctx);

/**
 Check if a process exists. Does this work on all unixes?
**/
_PUBLIC_ bool process_exists_by_pid(pid_t pid);

/**
 Simple routine to do POSIX file locking. Cruft in NFS and 64->32 bit mapping
 is dealt with in posix.c
**/
_PUBLIC_ bool fcntl_lock(int fd, int op, off_t offset, off_t count, int type);

/**
 * Write dump of binary data to the log file.
 *
 * The data is only written if the log level is at least level.
 * 16 zero bytes in a row are omitted
 */
_PUBLIC_ void dump_data_skip_zeros(int level, const uint8_t *buf, int len);

/**
 malloc that aborts with smb_panic on fail or zero size.
**/
_PUBLIC_ void *smb_xmalloc(size_t size);

/**
 Memdup with smb_panic on fail.
**/
_PUBLIC_ void *smb_xmemdup(const void *p, size_t size);

/**
 strdup that aborts on malloc fail.
**/
_PUBLIC_ char *smb_xstrdup(const char *s);

char *smb_xstrndup(const char *s, size_t n);

/**
 Like strdup but for memory.
**/
_PUBLIC_ void *smb_memdup(const void *p, size_t size);

/**
 * Write a password to the log file.
 *
 * @note Only actually does something if DEBUG_PASSWORD was defined during 
 * compile-time.
 */
_PUBLIC_ void dump_data_pw(const char *msg, const uint8_t * data, size_t len);

/**
 * see if a range of memory is all zero. A NULL pointer is considered
 * to be all zero 
 */
_PUBLIC_ bool all_zero(const uint8_t *ptr, size_t size);

/**
  realloc an array, checking for integer overflow in the array size
*/
_PUBLIC_ void *realloc_array(void *ptr, size_t el_size, unsigned count, bool free_on_fail);

void *malloc_array(size_t el_size, unsigned int count);

void *memalign_array(size_t el_size, size_t align, unsigned int count);

void *calloc_array(size_t size, size_t nmemb);

/* The following definitions come from lib/util/fsusage.c  */


/**
 * Retrieve amount of free disk space.
 * this does all of the system specific guff to get the free disk space.
 * It is derived from code in the GNU fileutils package, but has been
 * considerably mangled for use here 
 *
 * results are returned in *dfree and *dsize, in 512 byte units
*/
_PUBLIC_ int sys_fsusage(const char *path, uint64_t *dfree, uint64_t *dsize);

/* The following definitions come from lib/util/ms_fnmatch.c  */


/**
 * @file
 * @brief MS-style Filename matching
 */

int ms_fnmatch_protocol(const char *pattern, const char *string, int protocol,
			bool is_case_sensitive);

/** a generic fnmatch function - uses for non-CIFS pattern matching */
int gen_fnmatch(const char *pattern, const char *string);

#include "idtree.h"
#include "idtree_random.h"

#include "become_daemon.h"

/**
 * @brief Get a password from the console.
 *
 * You should make sure that the buffer is an empty string!
 *
 * You can also use this function to ask for a username. Then you can fill the
 * buffer with the username and it is shows to the users. If the users just
 * presses enter the buffer will be untouched.
 *
 * @code
 *   char username[128];
 *
 *   snprintf(username, sizeof(username), "john");
 *
 *   smb_getpass("Username:", username, sizeof(username), 1, 0);
 * @endcode
 *
 * The prompt will look like this:
 *
 *   Username: [john]
 *
 * If you press enter then john is used as the username, or you can type it in
 * to change it.
 *
 * @param[in]  prompt   The prompt to show to ask for the password.
 *
 * @param[out] buf    The buffer the password should be stored. It NEEDS to be
 *		      empty or filled out.
 *
 * @param[in]  len      The length of the buffer.
 *
 * @param[in]  echo     Should we echo what you type.
 *
 * @param[in]  verify   Should we ask for the password twice.
 *
 * @return              0 on success, -1 on error.
 */
_PUBLIC_ int samba_getpass(const char *prompt, char *buf, size_t len,
			   bool echo, bool verify);

/**
 * Load a ini-style file.
 */
bool pm_process( const char *fileName,
		 bool (*sfunc)(const char *, void *),
		 bool (*pfunc)(const char *, const char *, void *),
				 void *userdata);
bool pm_process_with_flags(const char *filename,
			   bool allow_empty_values,
			   bool (*sfunc)(const char *section, void *private_data),
			   bool (*pfunc)(const char *name, const char *value,
					 void *private_data),
			   void *private_data);

void print_asc(int level, const uint8_t *buf,int len);
void print_asc_cb(const uint8_t *buf, int len,
		  void (*cb)(const char *buf, void *private_data),
		  void *private_data);

/**
 * Add an id to an array of ids.
 *
 * num should be a pointer to an integer that holds the current
 * number of elements in ids. It will be updated by this function.
 */

bool add_uid_to_array_unique(TALLOC_CTX *mem_ctx, uid_t uid,
			     uid_t **uids, uint32_t *num_uids);
bool add_gid_to_array_unique(TALLOC_CTX *mem_ctx, gid_t gid,
			     gid_t **gids, uint32_t *num_gids);

/**
 * Allocate anonymous shared memory of the given size
 */
void *anonymous_shared_allocate(size_t bufsz);
void *anonymous_shared_resize(void *ptr, size_t new_size, bool maymove);
void anonymous_shared_free(void *ptr);

/*
  run a command as a child process, with a timeout.

  any stdout/stderr from the child will appear in the Samba logs with
  the specified log levels

  If callback is set then the callback is called on completion
  with the return code from the command
 */
struct tevent_context;
struct tevent_req;
struct tevent_req *samba_runcmd_send(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     struct timeval endtime,
				     int stdout_log_level,
				     int stderr_log_level,
				     const char * const *argv0, ...);
int samba_runcmd_recv(struct tevent_req *req, int *perrno);
int samba_runcmd_export_stdin(struct tevent_req *req);

#ifdef DEVELOPER
void samba_start_debugger(void);
#endif

/*
 * Samba code should use samba_tevent_context_init() instead of
 * tevent_context_init() in order to get the debug output.
 */
struct tevent_context *samba_tevent_context_init(TALLOC_CTX *mem_ctx);

/*
 * if same samba code needs to use a specific tevent backend
 * it can use something like this:
 *
 * samba_tevent_set_debug(ev, "pysmb_tevent");
 */
void samba_tevent_set_debug(struct tevent_context *ev, const char *name);

#endif /* _SAMBA_UTIL_H_ */
