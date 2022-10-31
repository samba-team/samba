/*
 * Copyright (c) 2010 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Portions Copyright (c) 2010 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef HEIM_BASE_H
#define HEIM_BASE_H 1

#include "config.h"

#include <sys/types.h>
#ifndef _WIN32
#include <sys/socket.h>
#endif
#if !defined(WIN32) && !defined(HAVE_DISPATCH_DISPATCH_H) && defined(ENABLE_PTHREAD_SUPPORT)
#include <pthread.h>
#endif
#include <krb5-types.h>
#include <stdarg.h>
#ifdef _WIN32
#include <winsock2.h>
#endif
#ifdef HAVE_STDBOOL_H
#include <stdbool.h>
#else
#ifndef false
#define false 0
#endif
#ifndef true
#define true 1
#endif
#endif

#include <stdint.h>

#include <heim_err.h>

#ifdef _WIN32
#define HEIM_CALLCONV __stdcall
#define HEIM_LIB_CALL __stdcall
#else
#define HEIM_CALLCONV
#define HEIM_LIB_CALL
#endif

#if !defined(__GNUC__) && !defined(__attribute__)
#define __attribute__(x)
#endif

#define HEIM_BASE_API_VERSION 20130210

/*
 * Generic facilities (moved from lib/krb5/.
 */

typedef int32_t heim_error_code;
typedef struct heim_context_s *heim_context;
typedef struct heim_pcontext_s *heim_pcontext;

typedef void (HEIM_CALLCONV *heim_log_log_func_t)(heim_context,
                                                  const char *,
                                                  const char *,
                                                  void *);
typedef void (HEIM_CALLCONV *heim_log_close_func_t)(void *);

typedef struct heim_log_facility_s heim_log_facility;

typedef uintptr_t
(HEIM_LIB_CALL *heim_get_instance_func_t)(const char *);

#define HEIM_PLUGIN_INVOKE_ALL 1

struct heim_plugin_data {
    const char *module;
    const char *name;
    int min_version;
    const char **deps;
    heim_get_instance_func_t get_instance;
};

/*
 * heim_config_binding is identical to struct krb5_config_binding
 * within krb5.h.  Its format is public and used by callers of
 * krb5_config_get_list() and krb5_config_vget_list().
 */
enum heim_config_type {
    heim_config_string,
    heim_config_list,
};
struct heim_config_binding {
    enum heim_config_type type;
    char *name;
    struct heim_config_binding *next;
    union {
        char *string;
        struct heim_config_binding *list;
        void *generic;
    } u;
};
typedef struct heim_config_binding heim_config_binding;
typedef struct heim_config_binding heim_config_section;

/*
 * CF-like, JSON APIs
 */

typedef enum heim_tid_enum {
    HEIM_TID_NUMBER = 0,
    HEIM_TID_NULL = 1,
    HEIM_TID_BOOL = 2,
    HEIM_TID_TAGGED_UNUSED2 = 3, /* reserved for tagged object types */
    HEIM_TID_TAGGED_UNUSED3 = 4, /* reserved for tagged object types */
    HEIM_TID_TAGGED_UNUSED4 = 5, /* reserved for tagged object types */
    HEIM_TID_TAGGED_UNUSED5 = 6, /* reserved for tagged object types */
    HEIM_TID_TAGGED_UNUSED6 = 7, /* reserved for tagged object types */
    HEIM_TID_MEMORY = 128,
    HEIM_TID_ARRAY = 129,
    HEIM_TID_DICT = 130,
    HEIM_TID_STRING = 131,
    HEIM_TID_AUTORELEASE = 132,
    HEIM_TID_ERROR = 133,
    HEIM_TID_DATA = 134,
    HEIM_TID_DB = 135,
    HEIM_TID_PA_AUTH_MECH = 136,
    HEIM_TID_PAC = 137,
    HEIM_TID_USER = 255
} heim_tid;

typedef void * heim_object_t;
typedef unsigned int heim_tid_t;
typedef heim_object_t heim_bool_t;
typedef heim_object_t heim_null_t;
#ifdef WIN32
typedef LONG heim_base_once_t;
#define HEIM_BASE_ONCE_INIT 0
#elif defined(HAVE_DISPATCH_DISPATCH_H)
typedef long heim_base_once_t; /* XXX arch dependant */
#define HEIM_BASE_ONCE_INIT 0
#elif defined(ENABLE_PTHREAD_SUPPORT)
typedef pthread_once_t heim_base_once_t;
#define HEIM_BASE_ONCE_INIT PTHREAD_ONCE_INIT
#else
typedef long heim_base_once_t; /* XXX arch dependant */
#define HEIM_BASE_ONCE_INIT 0
#endif

#if !defined(__has_extension)
#define __has_extension(x) 0
#endif

#define HEIM_REQUIRE_GNUC(m,n,p) \
    (((__GNUC__ * 10000) + (__GNUC_MINOR__ * 100) + __GNUC_PATCHLEVEL__) >= \
     (((m) * 10000) + ((n) * 100) + (p)))


#if __has_extension(__builtin_expect) || HEIM_REQUIRE_GNUC(3,0,0)
#define heim_builtin_expect(_op,_res) __builtin_expect(_op,_res)
#else
#define heim_builtin_expect(_op,_res) (_op)
#endif


heim_object_t	heim_retain(heim_object_t);
void	heim_release(heim_object_t);

void	heim_show(heim_object_t);

typedef void (HEIM_CALLCONV *heim_type_dealloc)(void *);

void *
heim_alloc(size_t size, const char *name, heim_type_dealloc dealloc);

heim_tid_t
heim_get_tid(heim_object_t object);

int
heim_cmp(heim_object_t a, heim_object_t b);

uintptr_t
heim_get_hash(heim_object_t ptr);

void
heim_base_once_f(heim_base_once_t *, void *, void (*)(void *));

void
heim_abort(const char *fmt, ...)
    HEIMDAL_NORETURN_ATTRIBUTE
    HEIMDAL_PRINTF_ATTRIBUTE((__printf__, 1, 2));

void
heim_abortv(const char *fmt, va_list ap)
    HEIMDAL_NORETURN_ATTRIBUTE
    HEIMDAL_PRINTF_ATTRIBUTE((__printf__, 1, 0));

#define heim_assert(e,t) \
    (heim_builtin_expect(!(e), 0) ? heim_abort(t ":" #e) : (void)0)

/*
 *
 */

heim_null_t
heim_null_create(void);

heim_bool_t
heim_bool_create(int);

int
heim_bool_val(heim_bool_t);

/*
 * Array
 */

typedef struct heim_array_data *heim_array_t;

heim_array_t heim_array_create(void);
heim_tid_t heim_array_get_type_id(void);

typedef void (*heim_array_iterator_f_t)(heim_object_t, void *, int *);
typedef int (*heim_array_filter_f_t)(heim_object_t, void *);

int	heim_array_append_value(heim_array_t, heim_object_t);
int	heim_array_insert_value(heim_array_t, size_t idx, heim_object_t);
void	heim_array_iterate_f(heim_array_t, void *, heim_array_iterator_f_t);
void	heim_array_iterate_reverse_f(heim_array_t, void *, heim_array_iterator_f_t);
#ifdef __BLOCKS__
void	heim_array_iterate(heim_array_t, void (^)(heim_object_t, int *));
void	heim_array_iterate_reverse(heim_array_t, void (^)(heim_object_t, int *));
#endif
size_t	heim_array_get_length(heim_array_t);
heim_object_t
	heim_array_get_value(heim_array_t, size_t);
heim_object_t
	heim_array_copy_value(heim_array_t, size_t);
void	heim_array_set_value(heim_array_t, size_t, heim_object_t);
void	heim_array_delete_value(heim_array_t, size_t);
void	heim_array_filter_f(heim_array_t, void *, heim_array_filter_f_t);
#ifdef __BLOCKS__
void	heim_array_filter(heim_array_t, int (^)(heim_object_t));
#endif

/*
 * Dict
 */

typedef struct heim_dict_data *heim_dict_t;

heim_dict_t heim_dict_create(size_t size);
heim_tid_t heim_dict_get_type_id(void);

typedef void (*heim_dict_iterator_f_t)(heim_object_t, heim_object_t, void *);

int	heim_dict_set_value(heim_dict_t, heim_object_t, heim_object_t);
void	heim_dict_iterate_f(heim_dict_t, void *, heim_dict_iterator_f_t);
#ifdef __BLOCKS__
void	heim_dict_iterate(heim_dict_t, void (^)(heim_object_t, heim_object_t));
#endif

heim_object_t
	heim_dict_get_value(heim_dict_t, heim_object_t);
heim_object_t
	heim_dict_copy_value(heim_dict_t, heim_object_t);
void	heim_dict_delete_key(heim_dict_t, heim_object_t);

/*
 * String
 */

typedef struct heim_string_data *heim_string_t;
typedef void (*heim_string_free_f_t)(void *);

heim_string_t heim_string_create(const char *);
heim_string_t heim_string_ref_create(const char *, heim_string_free_f_t);
heim_string_t heim_string_create_with_bytes(const void *, size_t);
heim_string_t heim_string_ref_create_with_bytes(const void *, size_t,
						heim_string_free_f_t);
heim_string_t heim_string_create_with_format(const char *, ...);
heim_tid_t heim_string_get_type_id(void);
const char * heim_string_get_utf8(heim_string_t);

#define HSTR(_str) (__heim_string_constant("" _str ""))
heim_string_t __heim_string_constant(const char *);

/*
 * Errors
 */

typedef struct heim_error * heim_error_t;

heim_error_t heim_error_create_enomem(void);

heim_error_t	heim_error_create(int, const char *, ...)
    HEIMDAL_PRINTF_ATTRIBUTE((__printf__, 2, 3));

void		heim_error_create_opt(heim_error_t *error, int error_code, const char *fmt, ...)
    HEIMDAL_PRINTF_ATTRIBUTE((__printf__, 3, 4));

heim_error_t	heim_error_createv(int, const char *, va_list)
    HEIMDAL_PRINTF_ATTRIBUTE((__printf__, 2, 0));

heim_string_t heim_error_copy_string(heim_error_t);
int heim_error_get_code(heim_error_t);

heim_error_t heim_error_append(heim_error_t, heim_error_t);

/*
 * Path
 */

heim_object_t heim_path_get(heim_object_t ptr, heim_error_t *error, ...);
heim_object_t heim_path_copy(heim_object_t ptr, heim_error_t *error, ...);
heim_object_t heim_path_vget(heim_object_t ptr, heim_error_t *error,
			     va_list ap);
heim_object_t heim_path_vcopy(heim_object_t ptr, heim_error_t *error,
				  va_list ap);

int heim_path_vcreate(heim_object_t ptr, size_t size, heim_object_t leaf,
		      heim_error_t *error, va_list ap);
int heim_path_create(heim_object_t ptr, size_t size, heim_object_t leaf,
		     heim_error_t *error, ...);

void heim_path_vdelete(heim_object_t ptr, heim_error_t *error, va_list ap);
void heim_path_delete(heim_object_t ptr, heim_error_t *error, ...);

/*
 * Data (octet strings)
 */

#ifndef __HEIM_BASE_DATA__
#define __HEIM_BASE_DATA__
struct heim_base_data {
    size_t length;
    void *data;
};
typedef struct heim_base_data heim_octet_string;
#endif

typedef struct heim_base_data * heim_data_t;
typedef void (*heim_data_free_f_t)(void *);

heim_data_t	heim_data_create(const void *, size_t);
heim_data_t	heim_data_ref_create(const void *, size_t, heim_data_free_f_t);
heim_tid_t	heim_data_get_type_id(void);
const heim_octet_string *
		heim_data_get_data(heim_data_t);
const void *	heim_data_get_ptr(heim_data_t);
size_t		heim_data_get_length(heim_data_t);

/*
 * DB
 */

typedef struct heim_db_data *heim_db_t;

typedef void (*heim_db_iterator_f_t)(heim_data_t, heim_data_t, void *);

typedef int (*heim_db_plug_open_f_t)(void *, const char *, const char *,
				     heim_dict_t, void **, heim_error_t *);
typedef int (*heim_db_plug_clone_f_t)(void *, void **, heim_error_t *);
typedef int (*heim_db_plug_close_f_t)(void *, heim_error_t *);
typedef int (*heim_db_plug_lock_f_t)(void *, int, heim_error_t *);
typedef int (*heim_db_plug_unlock_f_t)(void *, heim_error_t *);
typedef int (*heim_db_plug_sync_f_t)(void *, heim_error_t *);
typedef int (*heim_db_plug_begin_f_t)(void *, int, heim_error_t *);
typedef int (*heim_db_plug_commit_f_t)(void *, heim_error_t *);
typedef int (*heim_db_plug_rollback_f_t)(void *, heim_error_t *);
typedef heim_data_t (*heim_db_plug_copy_value_f_t)(void *, heim_string_t,
                                                   heim_data_t,
                                                   heim_error_t *);
typedef int (*heim_db_plug_set_value_f_t)(void *, heim_string_t, heim_data_t,
                                          heim_data_t, heim_error_t *);
typedef int (*heim_db_plug_del_key_f_t)(void *, heim_string_t, heim_data_t,
                                        heim_error_t *);
typedef void (*heim_db_plug_iter_f_t)(void *, heim_string_t, void *,
                                      heim_db_iterator_f_t, heim_error_t *);

struct heim_db_type {
    int                         version;
    heim_db_plug_open_f_t       openf;
    heim_db_plug_clone_f_t      clonef;
    heim_db_plug_close_f_t      closef;
    heim_db_plug_lock_f_t       lockf;
    heim_db_plug_unlock_f_t     unlockf;
    heim_db_plug_sync_f_t       syncf;
    heim_db_plug_begin_f_t      beginf;
    heim_db_plug_commit_f_t     commitf;
    heim_db_plug_rollback_f_t   rollbackf;
    heim_db_plug_copy_value_f_t copyf;
    heim_db_plug_set_value_f_t  setf;
    heim_db_plug_del_key_f_t    delf;
    heim_db_plug_iter_f_t       iterf;
};

extern struct heim_db_type heim_sorted_text_file_dbtype;

#define HEIM_DB_TYPE_VERSION_01 1

int heim_db_register(const char *dbtype,
		     void *data,
		     struct heim_db_type *plugin);

heim_db_t heim_db_create(const char *dbtype, const char *dbname,
		         heim_dict_t options, heim_error_t *error);
heim_db_t heim_db_clone(heim_db_t, heim_error_t *);
int heim_db_begin(heim_db_t, int, heim_error_t *);
int heim_db_commit(heim_db_t, heim_error_t *);
int heim_db_rollback(heim_db_t, heim_error_t *);
heim_tid_t heim_db_get_type_id(void);

int     heim_db_set_value(heim_db_t, heim_string_t, heim_data_t, heim_data_t,
                          heim_error_t *);
heim_data_t heim_db_copy_value(heim_db_t, heim_string_t, heim_data_t,
                               heim_error_t *);
int     heim_db_delete_key(heim_db_t, heim_string_t, heim_data_t,
                           heim_error_t *);
void    heim_db_iterate_f(heim_db_t, heim_string_t, void *,
                          heim_db_iterator_f_t, heim_error_t *);
#ifdef __BLOCKS__
void    heim_db_iterate(heim_db_t, heim_string_t,
                        void (^)(heim_data_t, heim_data_t), heim_error_t *);
#endif


/*
 * Number
 */

typedef struct heim_number_data *heim_number_t;

heim_number_t heim_number_create(int64_t);
heim_tid_t heim_number_get_type_id(void);
int heim_number_get_int(heim_number_t);
int64_t heim_number_get_long(heim_number_t);

/*
 *
 */

typedef struct heim_auto_release * heim_auto_release_t;

heim_auto_release_t heim_auto_release_create(void);
void heim_auto_release_drain(heim_auto_release_t);
heim_object_t heim_auto_release(heim_object_t);

/*
 * JSON
 */
typedef enum heim_json_flags {
	HEIM_JSON_F_NO_C_NULL = 1,
	HEIM_JSON_F_STRICT_STRINGS = 2,
	HEIM_JSON_F_NO_DATA = 4,
	HEIM_JSON_F_NO_DATA_DICT = 8,
	HEIM_JSON_F_STRICT_DICT = 16,
	HEIM_JSON_F_STRICT = 31,
	HEIM_JSON_F_CNULL2JSNULL = 32,
	HEIM_JSON_F_TRY_DECODE_DATA = 64,
	HEIM_JSON_F_ONE_LINE = 128,
        HEIM_JSON_F_ESCAPE_NON_ASCII = 256,
        HEIM_JSON_F_NO_ESCAPE_NON_ASCII = 512,
        /* The default is to indent with one tab */
	HEIM_JSON_F_INDENT2 = 1024,
	HEIM_JSON_F_INDENT4 = 2048,
	HEIM_JSON_F_INDENT8 = 4096,
} heim_json_flags_t;

heim_object_t heim_json_create(const char *, size_t, heim_json_flags_t,
			       heim_error_t *);
heim_object_t heim_json_create_with_bytes(const void *, size_t, size_t,
					  heim_json_flags_t,
					  heim_error_t *);
heim_string_t heim_json_copy_serialize(heim_object_t, heim_json_flags_t,
				       heim_error_t *);


/*
 * Debug
 */

heim_string_t
heim_description(heim_object_t ptr);

/*
 * Binary search.
 *
 * Note: these are private until integrated into the heimbase object system.
 */
typedef struct bsearch_file_handle *bsearch_file_handle;
int _bsearch_text(const char *buf, size_t buf_sz, const char *key,
		   char **value, size_t *location, size_t *loops);
int _bsearch_file_open(const char *fname, size_t max_sz, size_t page_sz,
			bsearch_file_handle *bfh, size_t *reads);
int _bsearch_file(bsearch_file_handle bfh, const char *key, char **value,
		   size_t *location, size_t *loops, size_t *reads);
void _bsearch_file_info(bsearch_file_handle bfh, size_t *page_sz,
			 size_t *max_sz, int *blockwise);
void _bsearch_file_close(bsearch_file_handle *bfh);

/*
 * Thread-specific keys
 */

int heim_w32_key_create(unsigned long *, void (*)(void *));
int heim_w32_delete_key(unsigned long);
int heim_w32_setspecific(unsigned long, void *);
void *heim_w32_getspecific(unsigned long);
void heim_w32_service_thread_detach(void *);

#include <heim_threads.h>
#include "heimbase-atomics.h"
#include <com_err.h>

/*
 * Service logging facility (moved from kdc/).
 */

#define HEIM_SVC_AUDIT_EATWHITE      0x1
#define HEIM_SVC_AUDIT_VIS           0x2
#define HEIM_SVC_AUDIT_VISLAST       0x4

typedef struct heim_svc_req_desc_common_s *heim_svc_req_desc;

#include <heimbase-protos.h>

#endif /* HEIM_BASE_H */
