#define TAINTED_SCALAR_GENERIC  1
#define ALLOCATION              1
#define ENVIRONMENT             1
#define FILESYSTEM              1
#define FORMAT_STRING           1
#define GENERIC                 1
#define OS_CMD_ARGUMENTS        1
#define OS_CMD_FILENAME         1
#define OS_CMD_ONE_STRING       1
#define OVERRUN                 1
#define PATH                    1
#define TAINT_TYPE_CONSOLE      1
#define TAINT_TYPE_ENVIRONMENT  1
#define TAINT_TYPE_FILESYSTEM   1
#define TAINT_TYPE_NETWORK      1

struct va_list_str;

typedef unsigned long size_t;

void*__coverity_alloc__(size_t);
void*__coverity_alloc_nosize__(void);
void __coverity_always_check_return_internal__(void);
void __coverity_close__(int);
void __coverity_escape__(void *);
void __coverity_escape_const__(const void *);
void __coverity_exclusive_lock_acquire__(void *lock);
void __coverity_exclusive_lock_release__(void *lock);
void __coverity_free__(void *);
void __coverity_mark_as_uninitialized_buffer__(void *);
void __coverity_mark_as_afm_allocated__(const void *, const char *);
void __coverity_mark_as_afm_freed__(const void *, const char *);
void __coverity_mark_pointee_as_sanitized__(const void *, int);
void __coverity_mark_pointee_as_tainted__(const void *, int);
void __coverity_negative_sink__(long);
int  __coverity_open__(void);
void __coverity_panic__(void) __attribute__((__noreturn__));
void __coverity_printf_function_varargs__(int, const char *);
void __coverity_printf_function_valist__(int, const char *, struct va_list_str *);
void __coverity_read_buffer_bytes__(const void *, size_t);
void __coverity_recursive_lock_acquire__(void *lock);
void __coverity_string_size_sink__(const void *);
void __coverity_string_size_sink_vararg__(int);
void __coverity_string_null_argument__(void *, size_t);
void __coverity_string_null_copy__(void *, const void *, size_t);
void __coverity_string_null_sink__(const void *);
void __coverity_string_null_sink_vararg__(int);
void __coverity_taint_sink__(const void *, int);
void __coverity_tainted_data_transitive__(void *, const void *);
void __coverity_tainted_string_sanitize_content__(const char *);
void __coverity_use_handle__(int);
void __coverity_write_buffer_bytes__(char *, size_t);
void __coverity_writeall__(void *);
void __coverity_writeall0__(void *);
