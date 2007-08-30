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

#include "charset/charset.h"

/**
 * @file
 * @brief Helpful macros
 */

struct substitute_context;
struct smbsrv_tcon;

extern const char *logfile;
extern const char *panic_action;

#include "util/time.h"
#include "util/data_blob.h"
#include "util/xfile.h"
#include "util/debug.h"
#include "util/mutex.h"
#include "util/byteorder.h"

/**
  this is a warning hack. The idea is to use this everywhere that we
  get the "discarding const" warning from gcc. That doesn't actually
  fix the problem of course, but it means that when we do get to
  cleaning them up we can do it by searching the code for
  discard_const.

  It also means that other error types aren't as swamped by the noise
  of hundreds of const warnings, so we are more likely to notice when
  we get new errors.

  Please only add more uses of this macro when you find it
  _really_ hard to fix const warnings. Our aim is to eventually use
  this function in only a very few places.

  Also, please call this via the discard_const_p() macro interface, as that
  makes the return type safe.
*/
#ifndef discard_const
#define discard_const(ptr) ((void *)((intptr_t)(ptr)))
#endif

/** Type-safe version of discard_const */
#ifndef discard_const_p
#define discard_const_p(type, ptr) ((type *)discard_const(ptr))
#endif

/**
 * assert macros 
 */
#define SMB_ASSERT(b) do { if (!(b)) { \
	DEBUG(0,("PANIC: assert failed at %s(%d)\n", __FILE__, __LINE__)); \
	smb_panic("assert failed"); abort(); }} while (0)

#ifndef SAFE_FREE /* Oh no this is also defined in tdb.h */
/**
 * Free memory if the pointer and zero the pointer.
 *
 * @note You are explicitly allowed to pass NULL pointers -- they will
 * always be ignored.
 **/
#define SAFE_FREE(x) do { if ((x) != NULL) {free(discard_const_p(void *, (x))); (x)=NULL;} } while(0)
#endif

/** 
 * Type-safe version of malloc. Allocated one copy of the 
 * specified data type.
 */
#define malloc_p(type) (type *)malloc(sizeof(type))

/**
 * Allocate an array of elements of one data type. Does type-checking.
 */
#define malloc_array_p(type, count) (type *)realloc_array(NULL, sizeof(type), count)

/** 
 * Resize an array of elements of one data type. Does type-checking.
 */
#define realloc_p(p, type, count) (type *)realloc_array(p, sizeof(type), count)

#if defined(VALGRIND)
#define strlen(x) valgrind_strlen(x)
#endif

/** 
 * zero a structure 
 */
#ifndef ZERO_STRUCT
#define ZERO_STRUCT(x) memset((char *)&(x), 0, sizeof(x))
#endif

/** 
 * zero a structure given a pointer to the structure 
 */
#ifndef ZERO_STRUCTP
#define ZERO_STRUCTP(x) do { if ((x) != NULL) memset((char *)(x), 0, sizeof(*(x))); } while(0)
#endif

/** 
 * zero a structure given a pointer to the structure - no zero check 
 */
#ifndef ZERO_STRUCTPN
#define ZERO_STRUCTPN(x) memset((char *)(x), 0, sizeof(*(x)))
#endif

/* zero an array - note that sizeof(array) must work - ie. it must not be a
   pointer */
#ifndef ZERO_ARRAY
#define ZERO_ARRAY(x) memset((char *)(x), 0, sizeof(x))
#endif

/**
 * work out how many elements there are in a static array 
 */
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))
#endif

/** 
 * pointer difference macro 
 */
#ifndef PTR_DIFF
#define PTR_DIFF(p1,p2) ((ptrdiff_t)(((const char *)(p1)) - (const char *)(p2)))
#endif


/** 
 * this global variable determines what messages are printed 
 */
_PUBLIC_ void debug_schedule_reopen_logs(void);

/**
  the backend for debug messages. Note that the DEBUG() macro has already
  ensured that the log level has been met before this is called
*/
_PUBLIC_ void do_debug_header(int level, const char *location, const char *func);

/**
  the backend for debug messages. Note that the DEBUG() macro has already
  ensured that the log level has been met before this is called

  @note You should never have to call this function directly. Call the DEBUG()
  macro instead.
*/
_PUBLIC_ void do_debug(const char *format, ...) _PRINTF_ATTRIBUTE(1,2);

/**
  reopen the log file (usually called because the log file name might have changed)
*/
_PUBLIC_ void reopen_logs(void);

/**
  control the name of the logfile and whether logging will be to stdout, stderr
  or a file
*/
_PUBLIC_ void setup_logging(const char *prog_name, enum debug_logtype new_logtype);

/**
  return a string constant containing n tabs
  no more than 10 tabs are returned
*/
_PUBLIC_ const char *do_debug_tab(int n);

/**
  log suspicious usage - print comments and backtrace
*/	
_PUBLIC_ void log_suspicious_usage(const char *from, const char *info);

/**
  print suspicious usage - print comments and backtrace
*/	
_PUBLIC_ void print_suspicious_usage(const char* from, const char* info);
_PUBLIC_ uint32_t get_task_id(void);
_PUBLIC_ void log_task_id(void);

/**
  register a set of debug handlers. 
*/
_PUBLIC_ void register_debug_handlers(const char *name, struct debug_ops *ops);

/* The following definitions come from lib/util/fault.c  */


/**
 * Write backtrace to debug log
 */
_PUBLIC_ void call_backtrace(void);

/**
 Something really nasty happened - panic !
**/
_PUBLIC_ _NORETURN_ void smb_panic(const char *why);

/**
setup our fault handlers
**/
_PUBLIC_ void fault_setup(const char *pname);

/**
  register a fault handler. 
  Should only be called once in the execution of smbd.
*/
_PUBLIC_ bool register_fault_handler(const char *name, void (*fault_handler)(int sig));

/* The following definitions come from lib/util/signal.c  */


/**
 Block sigs.
**/
void BlockSignals(bool block, int signum);

/**
 Catch a signal. This should implement the following semantics:

 1) The handler remains installed after being called.
 2) The signal should be blocked during handler execution.
**/
void (*CatchSignal(int signum,void (*handler)(int )))(int);

/**
 Ignore SIGCLD via whatever means is necessary for this OS.
**/
void CatchChild(void);

/**
 Catch SIGCLD but leave the child around so it's status can be reaped.
**/
void CatchChildLeaveStatus(void);

/* The following definitions come from lib/util/system.c  */


/*
  we use struct ipv4_addr to avoid having to include all the
  system networking headers everywhere
*/
struct ipv4_addr {
	uint32_t addr;
};

/**************************************************************************
A wrapper for gethostbyname() that tries avoids looking up hostnames 
in the root domain, which can cause dial-on-demand links to come up for no
apparent reason.
****************************************************************************/
_PUBLIC_ struct hostent *sys_gethostbyname(const char *name);
_PUBLIC_ const char *sys_inet_ntoa(struct ipv4_addr in);
_PUBLIC_ struct ipv4_addr sys_inet_makeaddr(int net, int host);

/* The following definitions come from lib/util/genrand.c  */

/**
 Copy any user given reseed data.
**/
_PUBLIC_ void set_rand_reseed_callback(void (*fn)(int *));

/**
 * Tell the random number generator it needs to reseed.
 */
_PUBLIC_ void set_need_random_reseed(void);

/**
 Interface to the (hopefully) good crypto random number generator.
**/
_PUBLIC_ void generate_random_buffer(uint8_t *out, int len);

/**
  generate a single random uint32_t
**/
_PUBLIC_ uint32_t generate_random(void);

/**
  very basic password quality checker
**/
_PUBLIC_ bool check_password_quality(const char *s);

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

/* The following definitions come from lib/util/dprintf.c  */

_PUBLIC_ int d_vfprintf(FILE *f, const char *format, va_list ap) _PRINTF_ATTRIBUTE(2,0);
_PUBLIC_ int d_fprintf(FILE *f, const char *format, ...) _PRINTF_ATTRIBUTE(2,3);
_PUBLIC_ int d_printf(const char *format, ...) _PRINTF_ATTRIBUTE(1,2);
_PUBLIC_ void display_set_stderr(void);

/* The following definitions come from lib/util/util_str.c  */


/**
 Trim the specified elements off the front and back of a string.
**/
_PUBLIC_ bool trim_string(char *s, const char *front, const char *back);

/**
 Find the number of 'c' chars in a string
**/
_PUBLIC_ _PURE_ size_t count_chars(const char *s, char c);

/**
 Safe string copy into a known length string. maxlength does not
 include the terminating zero.
**/
_PUBLIC_ char *safe_strcpy(char *dest,const char *src, size_t maxlength);

/**
 Safe string cat into a string. maxlength does not
 include the terminating zero.
**/
_PUBLIC_ char *safe_strcat(char *dest, const char *src, size_t maxlength);

/**
 Routine to get hex characters and turn them into a 16 byte array.
 the array can be variable length, and any non-hex-numeric
 characters are skipped.  "0xnn" or "0Xnn" is specially catered
 for.

 valid examples: "0A5D15"; "0x15, 0x49, 0xa2"; "59\ta9\te3\n"


**/
_PUBLIC_ size_t strhex_to_str(char *p, size_t len, const char *strhex);

/** 
 * Parse a hex string and return a data blob. 
 */
_PUBLIC_ _PURE_ DATA_BLOB strhex_to_data_blob(const char *strhex) ;

/**
 * Routine to print a buffer as HEX digits, into an allocated string.
 */
_PUBLIC_ void hex_encode(const unsigned char *buff_in, size_t len, char **out_hex_buffer);

/**
 * talloc version of hex_encode()
 */
_PUBLIC_ char *hex_encode_talloc(TALLOC_CTX *mem_ctx, const unsigned char *buff_in, size_t len);

/**
 Free a string value.
**/
_PUBLIC_ void string_free(char **s);

/**
 Set a string value, deallocating any existing space, and allocing the space
 for the string
**/
_PUBLIC_ bool string_set(char **dest, const char *src);

/**
 Substitute a string for a pattern in another string. Make sure there is 
 enough room!

 This routine looks for pattern in s and replaces it with 
 insert. It may do multiple replacements.

 Any of " ; ' $ or ` in the insert string are replaced with _
 if len==0 then the string cannot be extended. This is different from the old
 use of len==0 which was for no length checks to be done.
**/
_PUBLIC_ void string_sub(char *s,const char *pattern, const char *insert, size_t len);

/**
 Similar to string_sub() but allows for any character to be substituted. 
 Use with caution!
 if len==0 then the string cannot be extended. This is different from the old
 use of len==0 which was for no length checks to be done.
**/
_PUBLIC_ void all_string_sub(char *s,const char *pattern,const char *insert, size_t len);

/**
 Unescape a URL encoded string, in place.
**/
_PUBLIC_ void rfc1738_unescape(char *buf);
size_t valgrind_strlen(const char *s);

/**
  format a string into length-prefixed dotted domain format, as used in NBT
  and in some ADS structures
**/
_PUBLIC_ const char *str_format_nbt_domain(TALLOC_CTX *mem_ctx, const char *s);

/**
 * Add a string to an array of strings.
 *
 * num should be a pointer to an integer that holds the current 
 * number of elements in strings. It will be updated by this function.
 */
_PUBLIC_ bool add_string_to_array(TALLOC_CTX *mem_ctx,
			 const char *str, const char ***strings, int *num);

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
 Return a string representing a CIFS attribute for a file.
**/
_PUBLIC_ char *attrib_string(TALLOC_CTX *mem_ctx, uint32_t attrib);

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
_PUBLIC_ bool conv_str_size(const char * str, uint64_t * val);

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

/* The following definitions come from lib/util/util_strlist.c  */


/**
  build a null terminated list of strings from a input string and a
  separator list. The separator list must contain characters less than
  or equal to 0x2f for this to work correctly on multi-byte strings
*/
_PUBLIC_ const char **str_list_make(TALLOC_CTX *mem_ctx, const char *string, const char *sep);

/**
 * build a null terminated list of strings from an argv-like input string 
 * Entries are seperated by spaces and can be enclosed by quotes. 
 * Does NOT support escaping
 */
_PUBLIC_ const char **str_list_make_shell(TALLOC_CTX *mem_ctx, const char *string, const char *sep);

/**
 * join a list back to one string 
 */
_PUBLIC_ char *str_list_join(TALLOC_CTX *mem_ctx, const char **list, char seperator);

/** join a list back to one (shell-like) string; entries 
 * seperated by spaces, using quotes where necessary */
_PUBLIC_ char *str_list_join_shell(TALLOC_CTX *mem_ctx, const char **list, char sep);

/**
  return the number of elements in a string list
*/
_PUBLIC_ size_t str_list_length(const char **list);

/**
  copy a string list
*/
_PUBLIC_ const char **str_list_copy(TALLOC_CTX *mem_ctx, const char **list);

/**
   Return true if all the elements of the list match exactly.
 */
_PUBLIC_ bool str_list_equal(const char **list1, const char **list2);

/**
  add an entry to a string list
*/
_PUBLIC_ const char **str_list_add(const char **list, const char *s);

/**
  remove an entry from a string list
*/
_PUBLIC_ void str_list_remove(const char **list, const char *s);

/**
  return true if a string is in a list
*/
_PUBLIC_ bool str_list_check(const char **list, const char *s);

/**
  return true if a string is in a list, case insensitively
*/
_PUBLIC_ bool str_list_check_ci(const char **list, const char *s);

/**
 Check if a string is part of a list.
**/
_PUBLIC_ bool in_list(const char *s, const char *list, bool casesensitive);

/* The following definitions come from lib/util/util_file.c  */


/**
read a line from a file with possible \ continuation chars. 
Blanks at the start or end of a line are stripped.
The string will be allocated if s2 is NULL
**/
_PUBLIC_ char *fgets_slash(char *s2,int maxlen,XFILE *f);

/**
 * Read one line (data until next newline or eof) and allocate it 
 */
_PUBLIC_ char *afdgets(int fd, TALLOC_CTX *mem_ctx, size_t hint);

/**
load a file into memory from a fd.
**/
_PUBLIC_ char *fd_load(int fd, size_t *size, TALLOC_CTX *mem_ctx);

/**
load a file into memory
**/
_PUBLIC_ char *file_load(const char *fname, size_t *size, TALLOC_CTX *mem_ctx);

/**
mmap (if possible) or read a file
**/
_PUBLIC_ void *map_file(const char *fname, size_t size);

/**
load a file into memory and return an array of pointers to lines in the file
must be freed with talloc_free(). 
**/
_PUBLIC_ char **file_lines_load(const char *fname, int *numlines, TALLOC_CTX *mem_ctx);

/**
load a fd into memory and return an array of pointers to lines in the file
must be freed with talloc_free(). If convert is true calls unix_to_dos on
the list.
**/
_PUBLIC_ char **fd_lines_load(int fd, int *numlines, TALLOC_CTX *mem_ctx);

/**
take a list of lines and modify them to produce a list where \ continues
a line
**/
_PUBLIC_ void file_lines_slashcont(char **lines);

/**
  save a lump of data into a file. Mostly used for debugging 
*/
_PUBLIC_ bool file_save(const char *fname, const void *packet, size_t length);
_PUBLIC_ int vfdprintf(int fd, const char *format, va_list ap) _PRINTF_ATTRIBUTE(2,0);
_PUBLIC_ int fdprintf(int fd, const char *format, ...) _PRINTF_ATTRIBUTE(2,3);
_PUBLIC_ bool large_file_support(const char *path);

/* The following definitions come from lib/util/util.c  */


/**
 Find a suitable temporary directory. The result should be copied immediately
 as it may be overwritten by a subsequent call.
**/
_PUBLIC_ const char *tmpdir(void);

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
 * Try to create the specified directory if it didn't exist.
 *
 * @retval true if the directory already existed and has the right permissions 
 * or was successfully created.
 */
_PUBLIC_ bool directory_create_or_exist(const char *dname, uid_t uid, 
			       mode_t dir_perms);

/**
 Set a fd into blocking/nonblocking mode. Uses POSIX O_NONBLOCK if available,
 else
  if SYSV use O_NDELAY
  if BSD use FNDELAY
**/
_PUBLIC_ int set_blocking(int fd, bool set);

/**
 Sleep for a specified number of milliseconds.
**/
_PUBLIC_ void msleep(unsigned int t);

/**
 Get my own name, return in malloc'ed storage.
**/
_PUBLIC_ char* get_myname(void);

/**
 Return true if a string could be a pure IP address.
**/
_PUBLIC_ bool is_ipaddress(const char *str);

/**
 Interpret an internet address or name into an IP address in 4 byte form.
**/
_PUBLIC_ uint32_t interpret_addr(const char *str);

/**
 A convenient addition to interpret_addr().
**/
_PUBLIC_ struct ipv4_addr interpret_addr2(const char *str);

/**
 Check if an IP is the 0.0.0.0.
**/
_PUBLIC_ bool is_zero_ip(struct ipv4_addr ip);

/**
 Are two IPs on the same subnet?
**/
_PUBLIC_ bool same_net(struct ipv4_addr ip1,struct ipv4_addr ip2,struct ipv4_addr mask);

/**
 Check if a process exists. Does this work on all unixes?
**/
_PUBLIC_ bool process_exists(pid_t pid);

/**
 Simple routine to do POSIX file locking. Cruft in NFS and 64->32 bit mapping
 is dealt with in posix.c
**/
_PUBLIC_ bool fcntl_lock(int fd, int op, off_t offset, off_t count, int type);

/**
 * Write dump of binary data to the log file.
 *
 * The data is only written if the log level is at least level.
 */
_PUBLIC_ void dump_data(int level, const uint8_t *buf,int len);

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

/**
 Like strdup but for memory.
**/
_PUBLIC_ void *memdup(const void *p, size_t size);

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
_PUBLIC_ void *realloc_array(void *ptr, size_t el_size, unsigned count);

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

/* protocol types. It assumes that higher protocols include lower protocols
   as subsets. FIXME: Move to one of the smb-specific headers */
enum protocol_types {
	PROTOCOL_NONE,
	PROTOCOL_CORE,
	PROTOCOL_COREPLUS,
	PROTOCOL_LANMAN1,
	PROTOCOL_LANMAN2,
	PROTOCOL_NT1,
	PROTOCOL_SMB2
};



int ms_fnmatch(const char *pattern, const char *string, enum protocol_types protocol);

/** a generic fnmatch function - uses for non-CIFS pattern matching */
int gen_fnmatch(const char *pattern, const char *string);

/* The following definitions come from lib/util/mutex.c  */


/**
  register a set of mutex/rwlock handlers. 
  Should only be called once in the execution of smbd.
*/
_PUBLIC_ bool register_mutex_handlers(const char *name, struct mutex_ops *ops);

/* The following definitions come from lib/util/idtree.c  */


/**
  initialise a idr tree. The context return value must be passed to
  all subsequent idr calls. To destroy the idr tree use talloc_free()
  on this context
 */
_PUBLIC_ struct idr_context *idr_init(TALLOC_CTX *mem_ctx);

/**
  allocate the next available id, and assign 'ptr' into its slot.
  you can retrieve later this pointer using idr_find()
*/
_PUBLIC_ int idr_get_new(struct idr_context *idp, void *ptr, int limit);

/**
   allocate a new id, giving the first available value greater than or
   equal to the given starting id
*/
_PUBLIC_ int idr_get_new_above(struct idr_context *idp, void *ptr, int starting_id, int limit);

/**
  allocate a new id randomly in the given range
*/
_PUBLIC_ int idr_get_new_random(struct idr_context *idp, void *ptr, int limit);

/**
  find a pointer value previously set with idr_get_new given an id
*/
_PUBLIC_ void *idr_find(struct idr_context *idp, int id);

/**
  remove an id from the idr tree
*/
_PUBLIC_ int idr_remove(struct idr_context *idp, int id);

/* The following definitions come from lib/util/become_daemon.c  */

/**
 Become a daemon, discarding the controlling terminal.
**/
_PUBLIC_ void become_daemon(bool Fork);

#endif /* _SAMBA_UTIL_H_ */
