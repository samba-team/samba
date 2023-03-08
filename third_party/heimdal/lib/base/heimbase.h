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


typedef void (HEIM_CALLCONV *heim_type_dealloc)(void *);

#define heim_assert(e,t) \
    (heim_builtin_expect(!(e), 0) ? heim_abort(t ":" #e) : (void)0)

/*
 *
 */

/*
 * Array
 */

typedef struct heim_array_data *heim_array_t;

typedef void (*heim_array_iterator_f_t)(heim_object_t, void *, int *);
typedef int (*heim_array_filter_f_t)(heim_object_t, void *);

/*
 * Dict
 */

typedef struct heim_dict_data *heim_dict_t;

typedef void (*heim_dict_iterator_f_t)(heim_object_t, heim_object_t, void *);

/*
 * String
 */

typedef struct heim_string_data *heim_string_t;
typedef void (*heim_string_free_f_t)(void *);

#define HSTR(_str) (__heim_string_constant("" _str ""))
heim_string_t __heim_string_constant(const char *);

/*
 * Errors
 */

typedef struct heim_error * heim_error_t;

/*
 * Path
 */

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

/*
 * Number
 */

typedef struct heim_number_data *heim_number_t;

/*
 * Autorelease
 */

typedef struct heim_auto_release * heim_auto_release_t;

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

/*
 * Debug
 */

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

#include <heim_threads.h>
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
