/*
 * Copyright (c) 1997-2020 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Portions Copyright (c) 2009 Apple Inc. All rights reserved.
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

#include "baselocl.h"
#include "heim_threads.h"
#include "heimbase.h"
#include "heimbase-svc.h"
#include <assert.h>
#include <stdarg.h>
#include <vis.h>
#include <base64.h>

struct heim_log_facility_internal {
    int min;
    int max;
    heim_log_log_func_t log_func;
    heim_log_close_func_t close_func;
    void *data;
};

struct heim_log_facility_s {
    char *program;
    size_t refs;
    size_t len;
    struct heim_log_facility_internal *val;
};

typedef struct heim_pcontext_s *heim_pcontext;
typedef struct heim_pconfig *heim_pconfig;
struct heim_svc_req_desc_common_s {
    HEIM_SVC_REQUEST_DESC_COMMON_ELEMENTS;
};

static struct heim_log_facility_internal *
log_realloc(heim_log_facility *f)
{
    struct heim_log_facility_internal *fp;
    fp = realloc(f->val, (f->len + 1) * sizeof(*f->val));
    if (fp == NULL)
        return NULL;
    f->len++;
    f->val = fp;
    fp += f->len - 1;
    return fp;
}

struct s2i {
    const char *s;
    int val;
};

#define L(X) { #X, LOG_ ## X }

static struct s2i syslogvals[] = {
    L(EMERG),
    L(ALERT),
    L(CRIT),
    L(ERR),
    L(WARNING),
    L(NOTICE),
    L(INFO),
    L(DEBUG),

    L(AUTH),
#ifdef LOG_AUTHPRIV
    L(AUTHPRIV),
#endif
#ifdef LOG_CRON
    L(CRON),
#endif
    L(DAEMON),
#ifdef LOG_FTP
    L(FTP),
#endif
    L(KERN),
    L(LPR),
    L(MAIL),
#ifdef LOG_NEWS
    L(NEWS),
#endif
    L(SYSLOG),
    L(USER),
#ifdef LOG_UUCP
    L(UUCP),
#endif
    L(LOCAL0),
    L(LOCAL1),
    L(LOCAL2),
    L(LOCAL3),
    L(LOCAL4),
    L(LOCAL5),
    L(LOCAL6),
    L(LOCAL7),
    { NULL, -1 }
};

static int
find_value(const char *s, struct s2i *table)
{
    while (table->s && strcasecmp(table->s, s) != 0)
        table++;
    return table->val;
}

heim_error_code
heim_initlog(heim_context context,
             const char *program,
             heim_log_facility **fac)
{
    heim_log_facility *f = calloc(1, sizeof(*f));
    if (f == NULL)
        return heim_enomem(context);
    f->refs = 1;
    f->program = strdup(program);
    if (f->program == NULL) {
        free(f);
        return heim_enomem(context);
    }
    *fac = f;
    return 0;
}

heim_log_facility *
heim_log_ref(heim_log_facility *fac)
{
    if (fac)
        fac->refs++;
    return fac;
}

heim_error_code
heim_addlog_func(heim_context context,
                 heim_log_facility *fac,
                 int min,
                 int max,
                 heim_log_log_func_t log_func,
                 heim_log_close_func_t close_func,
                 void *data)
{
    struct heim_log_facility_internal *fp = log_realloc(fac);
    if (fp == NULL)
        return heim_enomem(context);
    fp->min = min;
    fp->max = max;
    fp->log_func = log_func;
    fp->close_func = close_func;
    fp->data = data;
    return 0;
}


struct _heimdal_syslog_data{
    int priority;
};

static void HEIM_CALLCONV
log_syslog(heim_context context, const char *timestr,
           const char *msg, void *data)
{
    struct _heimdal_syslog_data *s = data;
    syslog(s->priority, "%s", msg);
}

static void HEIM_CALLCONV
close_syslog(void *data)
{
    free(data);
    closelog();
}

static heim_error_code
open_syslog(heim_context context,
            heim_log_facility *facility, int min, int max,
            const char *sev, const char *fac)
{
    struct _heimdal_syslog_data *sd;
    heim_error_code ret;
    int i;

    if (facility == NULL)
        return EINVAL;
    if ((sd = calloc(1, sizeof(*sd))) == NULL)
        return heim_enomem(context);
    i = find_value(sev, syslogvals);
    if (i == -1)
        i = LOG_ERR;
    sd->priority = i;
    i = find_value(fac, syslogvals);
    if (i == -1)
        i = LOG_AUTH;
    sd->priority |= i;
    roken_openlog(facility->program, LOG_PID | LOG_NDELAY, i);
    ret = heim_addlog_func(context, facility, min, max, log_syslog,
                           close_syslog, sd);
    if (ret)
        free(sd);
    return ret;
}

struct file_data {
    char *filename;
    const char *mode;
    struct timeval tv;
    FILE *fd;
    int disp;
#define FILEDISP_KEEPOPEN       0x1
#define FILEDISP_REOPEN         0x2
#define FILEDISP_IFEXISTS       0x4
};

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

static void HEIM_CALLCONV
log_file(heim_context context, const char *timestr, const char *msg, void *data)
{
    struct timeval tv;
    struct file_data *f = data;
    FILE *logf = f->fd;
    char *msgclean;
    size_t i = 0;
    size_t j;

    if (f->filename && (logf == NULL || (f->disp & FILEDISP_REOPEN))) {
        int flags = O_WRONLY|O_APPEND;
        int fd;

        if (f->mode[0] == 'e') {
            flags |= O_CLOEXEC;
            i = 1;
        }
        if (f->mode[i] == 'w')
            flags |= O_TRUNC;
        if (f->mode[i + 1] == '+')
            flags |= O_RDWR;

        if (f->disp & FILEDISP_IFEXISTS) {
            /* Cache failure for 1s */
            gettimeofday(&tv, NULL);
            if (tv.tv_sec == f->tv.tv_sec)
                return;
        } else {
            flags |= O_CREAT;
        }

        fd = open(f->filename, flags, 0666); /* umask best be set */
        if (fd == -1) {
            if (f->disp & FILEDISP_IFEXISTS)
                gettimeofday(&f->tv, NULL);
            return;
        }
        rk_cloexec(fd);
        logf = fdopen(fd, f->mode);
    }
    if (f->fd == NULL && (f->disp & FILEDISP_KEEPOPEN))
        f->fd = logf;
    if (logf == NULL)
        return;
    /*
     * make sure the log doesn't contain special chars:
     * we used to use strvisx(3) to encode the log, but this is
     * inconsistent with our syslog(3) code which does not do this.
     * It also makes it inelegant to write data which has already
     * been quoted such as what krb5_unparse_principal() gives us.
     * So, we change here to eat the special characters, instead.
     */
    if (msg && (msgclean = strdup(msg))) {
        for (i = 0, j = 0; msg[i]; i++)
            if (msg[i] >= 32 || msg[i] == '\t')
                msgclean[j++] = msg[i];
        fprintf(logf, "%s %s\n", timestr ? timestr : "", msgclean);
        free(msgclean);
    }
    if (logf != f->fd)
        fclose(logf);
}

static void HEIM_CALLCONV
close_file(void *data)
{
    struct file_data *f = data;
    if (f->fd && f->fd != stdout && f->fd != stderr)
        fclose(f->fd);
    free(f->filename);
    free(data);
}

static heim_error_code
open_file(heim_context context, heim_log_facility *fac, int min, int max,
          const char *filename, const char *mode, FILE *f, int disp,
          int exp_tokens)
{
    heim_error_code ret = 0;
    struct file_data *fd;

    if ((fd = calloc(1, sizeof(*fd))) == NULL)
        return heim_enomem(context);

    fd->filename = NULL;
    fd->mode = mode;
    fd->fd = f;
    fd->disp = disp;

    if (filename) {
        if (exp_tokens)
            ret = heim_expand_path_tokens(context, filename, 1, &fd->filename, NULL);
        else if ((fd->filename = strdup(filename)) == NULL)
            ret = heim_enomem(context);
    }
    if (ret == 0)
        ret = heim_addlog_func(context, fac, min, max, log_file, close_file, fd);
    if (ret) {
        free(fd->filename);
        free(fd);
    } else if (disp & FILEDISP_KEEPOPEN) {
        log_file(context, NULL, NULL, fd);
    }
    return ret;
}

heim_error_code
heim_addlog_dest(heim_context context, heim_log_facility *f, const char *orig)
{
    heim_error_code ret = 0;
    int min = 0, max = 3, n;
    char c;
    const char *p = orig;
#ifdef _WIN32
    const char *q;
#endif

    n = sscanf(p, "%d%c%d/", &min, &c, &max);
    if (n == 2) {
        if (ISPATHSEP(c)) {
            if (min < 0) {
                max = -min;
                min = 0;
            } else {
                max = min;
            }
        }
        if (c == '-')
            max = -1;
    }
    if (n) {
#ifdef _WIN32
        q = strrchr(p, '\\');
        if (q != NULL)
            p = q;
        else
#endif
            p = strchr(p, '/');
        if (p == NULL) {
            heim_set_error_message(context, EINVAL /*XXX HEIM_ERR_LOG_PARSE*/,
                                   N_("failed to parse \"%s\"", ""), orig);
            return EINVAL /*XXX HEIM_ERR_LOG_PARSE*/;
        }
        p++;
    }
    if (strcmp(p, "STDERR") == 0) {
        ret = open_file(context, f, min, max, NULL, "a", stderr,
                        FILEDISP_KEEPOPEN, 0);
    } else if (strcmp(p, "CONSOLE") == 0) {
        /* XXX WIN32 */
        ret = open_file(context, f, min, max, "/dev/console", "w", NULL,
                        FILEDISP_KEEPOPEN, 0);
    } else if (strncmp(p, "EFILE:", 5) == 0) {
        ret = open_file(context, f, min, max, p + sizeof("EFILE:") - 1, "a",
                        NULL, FILEDISP_IFEXISTS | FILEDISP_REOPEN, 1);
    } else if (strncmp(p, "EFILE=", 5) == 0) {
        ret = open_file(context, f, min, max, p + sizeof("EFILE=") - 1, "a",
                        NULL, FILEDISP_IFEXISTS | FILEDISP_KEEPOPEN, 1);
    } else if (strncmp(p, "FILE:", sizeof("FILE:") - 1) == 0) {
        ret = open_file(context, f, min, max, p + sizeof("FILE:") - 1, "a",
                        NULL, FILEDISP_REOPEN, 1);
    } else if (strncmp(p, "FILE=", sizeof("FILE=") - 1) == 0) {
        ret = open_file(context, f, min, max, p + sizeof("FILE=") - 1, "a",
                        NULL, FILEDISP_KEEPOPEN, 1);
    } else if (strncmp(p, "DEVICE:", sizeof("DEVICE:") - 1) == 0) {
        ret = open_file(context, f, min, max, p + sizeof("DEVICE:") - 1, "a",
                        NULL, FILEDISP_REOPEN, 0);
    } else if (strncmp(p, "DEVICE=", sizeof("DEVICE=") - 1) == 0) {
        ret = open_file(context, f, min, max, p + sizeof("DEVICE=") - 1, "a",
                        NULL, FILEDISP_KEEPOPEN, 0);
    } else if (strncmp(p, "SYSLOG", 6) == 0 && (p[6] == '\0' || p[6] == ':')) {
        char severity[128] = "";
        char facility[128] = "";
        p += 6;
        if (*p != '\0')
            p++;
        if (strsep_copy(&p, ":", severity, sizeof(severity)) != -1)
            strsep_copy(&p, ":", facility, sizeof(facility));
        if (*severity == '\0')
            strlcpy(severity, "ERR", sizeof(severity));
        if (*facility == '\0')
            strlcpy(facility, "AUTH", sizeof(facility));
        ret = open_syslog(context, f, min, max, severity, facility);
    } else {
        ret = EINVAL; /*XXX HEIM_ERR_LOG_PARSE*/
        heim_set_error_message(context, ret,
                               N_("unknown log type: %s", ""), p);
    }
    return ret;
}

heim_error_code
heim_openlog(heim_context context,
             const char *program,
             const char **specs,
             heim_log_facility **fac)
{
    heim_error_code ret;

    ret = heim_initlog(context, program, fac);
    if (ret)
        return ret;

    if (specs) {
        size_t i;
        for (i = 0; specs[i] && ret == 0; i++)
            ret = heim_addlog_dest(context, *fac, specs[i]);
    } else {
        ret = heim_addlog_dest(context, *fac, "SYSLOG");
    }
    return ret;
}

void
heim_closelog(heim_context context, heim_log_facility *fac)
{
    int i;

    if (!fac || --(fac->refs))
        return;
    for (i = 0; i < fac->len; i++)
        (*fac->val[i].close_func)(fac->val[i].data);
    free(fac->val);
    free(fac->program);
    fac->val = NULL;
    fac->len = 0;
    fac->program = NULL;
    free(fac);
    return;
}

static void
format_time(heim_context context, time_t t, char *s, size_t len)
{
    struct tm *tm = heim_context_get_log_utc(context) ?
        gmtime(&t) : localtime(&t);
    if (tm && strftime(s, len, heim_context_get_time_fmt(context), tm))
        return;
    snprintf(s, len, "%ld", (long)t);
}

#undef __attribute__
#define __attribute__(X)

heim_error_code
heim_vlog_msg(heim_context context,
              heim_log_facility *fac,
              char **reply,
              int level,
              const char *fmt,
              va_list ap)
__attribute__ ((__format__ (__printf__, 5, 0)))
{

    char *msg = NULL;
    const char *actual = NULL;
    char buf[64];
    time_t t = 0;
    int i;

    if (!fac)
        fac = context->log_dest;
    for (i = 0; fac && i < fac->len; i++)
        if (fac->val[i].min <= level &&
            (fac->val[i].max < 0 || fac->val[i].max >= level)) {
            if (t == 0) {
                t = time(NULL);
                format_time(context, t, buf, sizeof(buf));
            }
            if (actual == NULL) {
                int ret = vasprintf(&msg, fmt, ap);
                if (ret < 0 || msg == NULL)
                    actual = fmt;
                else
                    actual = msg;
            }
            (*fac->val[i].log_func)(context, buf, actual, fac->val[i].data);
        }
    if (reply == NULL)
        free(msg);
    else
        *reply = msg;
    return 0;
}

heim_error_code
heim_vlog(heim_context context,
          heim_log_facility *fac,
          int level,
          const char *fmt,
          va_list ap)
__attribute__ ((__format__ (__printf__, 4, 0)))
{
    return heim_vlog_msg(context, fac, NULL, level, fmt, ap);
}

heim_error_code
heim_log_msg(heim_context context,
             heim_log_facility *fac,
             int level,
             char **reply,
             const char *fmt,
             ...)
__attribute__ ((__format__ (__printf__, 5, 6)))
{
    va_list ap;
    heim_error_code ret;

    va_start(ap, fmt);
    ret = heim_vlog_msg(context, fac, reply, level, fmt, ap);
    va_end(ap);
    return ret;
}


heim_error_code
heim_log(heim_context context,
         heim_log_facility *fac,
         int level,
         const char *fmt,
         ...)
__attribute__ ((__format__ (__printf__, 4, 5)))
{
    va_list ap;
    heim_error_code ret;

    va_start(ap, fmt);
    ret = heim_vlog(context, fac, level, fmt, ap);
    va_end(ap);
    return ret;
}

void
heim_debug(heim_context context,
           int level,
           const char *fmt,
           ...)
__attribute__ ((__format__ (__printf__, 3, 4)))
{
    heim_log_facility *fac;
    va_list ap;

    if (context == NULL ||
        (fac = heim_get_debug_dest(context)) == NULL)
        return;

    va_start(ap, fmt);
    heim_vlog(context, fac, level, fmt, ap);
    va_end(ap);
}

void
heim_vdebug(heim_context context,
            int level,
            const char *fmt,
            va_list ap)
__attribute__ ((__format__ (__printf__, 3, 0)))
{
    heim_log_facility *fac;

    if (context == NULL ||
        (fac = heim_get_debug_dest(context)) == NULL)
        return;

    heim_vlog(context, fac, level, fmt, ap);
}

heim_error_code
heim_have_debug(heim_context context, int level)
{
    return (context != NULL && heim_get_debug_dest(context) != NULL);
}

heim_error_code
heim_add_warn_dest(heim_context context, const char *program,
                   const char *log_spec)
{
    heim_log_facility *fac;

    heim_error_code ret;

    if ((fac = heim_get_warn_dest(context)) == NULL) {
        ret = heim_initlog(context, program, &fac);
        if (ret)
            return ret;
        heim_set_warn_dest(context, fac);
    }

    ret = heim_addlog_dest(context, fac, log_spec);
    if (ret)
        return ret;
    return 0;
}

heim_error_code
heim_add_debug_dest(heim_context context, const char *program,
                    const char *log_spec)
{
    heim_log_facility *fac;
    heim_error_code ret;

    if ((fac = heim_get_debug_dest(context)) == NULL) {
        ret = heim_initlog(context, program, &fac);
        if (ret)
            return ret;
        heim_set_debug_dest(context, fac);
    }

    ret = heim_addlog_dest(context, fac, log_spec);
    if (ret)
        return ret;
    return 0;
}

struct heim_audit_kv_tuple {
    heim_string_t key;
    heim_object_t value;
};

static struct heim_audit_kv_tuple zero_tuple;

static struct heim_audit_kv_tuple
fmtkv(int flags, const char *k, const char *fmt, va_list ap)
        __attribute__ ((__format__ (__printf__, 3, 0)))
{
    size_t i;
    ssize_t j;
    struct heim_audit_kv_tuple kv;
    char *value;
    char *value_vis;

    j = vasprintf(&value, fmt, ap);
    if (j < 0 || value == NULL)
	return zero_tuple;

    /* We optionally eat the whitespace. */

    if (flags & HEIM_SVC_AUDIT_EATWHITE) {
	for (i=0, j=0; value[i]; i++)
	    if (value[i] != ' ' && value[i] != '\t')
		value[j++] = value[i];
	value[j] = '\0';
    }

    if (flags & (HEIM_SVC_AUDIT_VIS | HEIM_SVC_AUDIT_VISLAST)) {
        int vis_flags = VIS_CSTYLE | VIS_OCTAL | VIS_NL;

        if (flags & HEIM_SVC_AUDIT_VIS)
            vis_flags |= VIS_WHITE;
	value_vis = malloc((j + 1) * 4 + 1);
        if (value_vis)
            strvisx(value_vis, value, j, vis_flags);
	free(value);
        if (value_vis == NULL)
            return zero_tuple;
    } else
	value_vis = value;

    if (k)
	kv.key = heim_string_create(k);
    else
	kv.key = NULL;
    kv.value = heim_string_ref_create(value_vis, free);

    return kv;
}

void
heim_audit_vaddreason(heim_svc_req_desc r, const char *fmt, va_list ap)
	__attribute__ ((__format__ (__printf__, 2, 0)))
{
    struct heim_audit_kv_tuple kv;

    kv = fmtkv(HEIM_SVC_AUDIT_VISLAST, NULL, fmt, ap);
    if (kv.value == NULL) {
        heim_log(r->hcontext, r->logf, 1, "heim_audit_vaddreason: "
                 "failed to add reason (out of memory)");
        return;
    }

    heim_log(r->hcontext, r->logf, 7, "heim_audit_vaddreason(): "
             "adding reason %s", heim_string_get_utf8(kv.value));
    if (r->reason) {
        heim_string_t str2;

        str2 = heim_string_create_with_format("%s: %s",
                                              heim_string_get_utf8(kv.value),
                                              heim_string_get_utf8(r->reason));
        if (str2) {
            heim_release(kv.value);
            kv.value = str2;
        }
    }
    heim_release(r->reason);
    r->reason = kv.value;
}

void
heim_audit_addreason(heim_svc_req_desc r, const char *fmt, ...)
	__attribute__ ((__format__ (__printf__, 2, 3)))
{
    va_list ap;

    va_start(ap, fmt);
    heim_audit_vaddreason(r, fmt, ap);
    va_end(ap);
}

size_t
addkv(heim_svc_req_desc r, heim_object_t key, heim_object_t value)
{
    size_t index;
    heim_object_t obj;

    obj = heim_dict_get_value(r->kv, key);
    if (obj) {
	if (heim_get_tid(obj) == HEIM_TID_ARRAY) {
	    index = heim_array_get_length(obj);
	    heim_array_append_value(obj, value);
	} else {
	    heim_array_t array = heim_array_create();

	    index = 1;
	    heim_array_append_value(array, obj);
	    heim_array_append_value(array, value);
	    heim_dict_set_value(r->kv, key, array);
	    heim_release(array); /* retained by r->kv */
	}
    } else {
	index = 0;
	heim_dict_set_value(r->kv, key, value);
    }

    return index;
}

/*
 * add a key-value token. if the key already exists, the value is
 * promoted to an array of values.
 */

void
heim_audit_vaddkv(heim_svc_req_desc r, int flags, const char *k,
		  const char *fmt, va_list ap)
	__attribute__ ((__format__ (__printf__, 4, 0)))
{
    struct heim_audit_kv_tuple kv;
    size_t index;

    kv = fmtkv(flags, k, fmt, ap);
    if (kv.key == NULL || kv.value == NULL) {
        heim_log(r->hcontext, r->logf, 1, "heim_audit_vaddkv: "
                 "failed to add kv pair (out of memory)");
	heim_release(kv.key);
	heim_release(kv.value);
        return;
    }

    index = addkv(r, kv.key, kv.value);

    heim_log(r->hcontext, r->logf, 7, "heim_audit_vaddkv(): "
             "kv pair[%zu] %s=%s", index,
	     heim_string_get_utf8(kv.key), heim_string_get_utf8(kv.value));

    heim_release(kv.key);
    heim_release(kv.value);
}

void
heim_audit_addkv(heim_svc_req_desc r, int flags, const char *k,
		 const char *fmt, ...)
	__attribute__ ((__format__ (__printf__, 4, 5)))
{
    va_list ap;

    va_start(ap, fmt);
    heim_audit_vaddkv(r, flags, k, fmt, ap);
    va_end(ap);
}

void
heim_audit_addkv_timediff(heim_svc_req_desc r, const char *k,
			  const struct timeval *start,
			  const struct timeval *end)
{
    time_t sec;
    int usec;
    const char *sign = "";

    if (end->tv_sec > start->tv_sec ||
	(end->tv_sec == start->tv_sec && end->tv_usec >= start->tv_usec)) {
	sec  = end->tv_sec  - start->tv_sec;
	usec = end->tv_usec - start->tv_usec;
    } else {
	sec  = start->tv_sec  - end->tv_sec;
	usec = start->tv_usec - end->tv_usec;
	sign = "-";
    }

    if (usec < 0) {
	usec += 1000000;
	sec  -= 1;
    }

    heim_audit_addkv(r, 0, k, "%s%ld.%06d", sign, (long)sec, usec);
}

void
heim_audit_setkv_bool(heim_svc_req_desc r, const char *k, int v)
{
    heim_string_t key = heim_string_create(k);
    heim_number_t value;

    if (key == NULL)
	return;

    heim_log(r->hcontext, r->logf, 7, "heim_audit_setkv_bool(): "
	     "setting kv pair %s=%s", k, v ? "true" : "false");

    value = heim_bool_create(v);
    heim_dict_set_value(r->kv, key, value);
    heim_release(key);
    heim_release(value);
}

void
heim_audit_addkv_number(heim_svc_req_desc r, const char *k, int64_t v)
{
    heim_string_t key = heim_string_create(k);
    heim_number_t value;

    if (key == NULL)
	return;

    heim_log(r->hcontext, r->logf, 7, "heim_audit_addkv_number(): "
	     "adding kv pair %s=%lld", k, (long long)v);

    value = heim_number_create(v);
    addkv(r, key, value);
    heim_release(key);
    heim_release(value);
}

void
heim_audit_setkv_number(heim_svc_req_desc r, const char *k, int64_t v)
{
    heim_string_t key = heim_string_create(k);
    heim_number_t value;

    if (key == NULL)
	return;

    heim_log(r->hcontext, r->logf, 7, "heim_audit_setkv_number(): "
	     "setting kv pair %s=%lld", k, (long long)v);

    value = heim_number_create(v);
    heim_dict_set_value(r->kv, key, value);
    heim_release(key);
    heim_release(value);
}

void
heim_audit_addkv_object(heim_svc_req_desc r, const char *k, heim_object_t value)
{
    heim_string_t key = heim_string_create(k);
    heim_string_t descr;

    if (key == NULL)
	return;

    descr = heim_json_copy_serialize(value, HEIM_JSON_F_NO_DATA_DICT, NULL);
    heim_log(r->hcontext, r->logf, 7, "heim_audit_addkv_object(): "
	     "adding kv pair %s=%s",
	     k, descr ? heim_string_get_utf8(descr) : "<unprintable>");
    addkv(r, key, value);
    heim_release(key);
    heim_release(descr);
}

void
heim_audit_setkv_object(heim_svc_req_desc r, const char *k, heim_object_t value)
{
    heim_string_t key = heim_string_create(k);
    heim_string_t descr;

    if (key == NULL)
	return;

    descr = heim_json_copy_serialize(value, HEIM_JSON_F_NO_DATA_DICT, NULL);
    heim_log(r->hcontext, r->logf, 7, "heim_audit_setkv_object(): "
	     "setting kv pair %s=%s",
	     k, descr ? heim_string_get_utf8(descr) : "<unprintable>");
    heim_dict_set_value(r->kv, key, value);
    heim_release(key);
    heim_release(descr);
}

heim_object_t
heim_audit_getkv(heim_svc_req_desc r, const char *k)
{
    heim_string_t key;
    heim_object_t value;

    key = heim_string_create(k);
    if (key == NULL)
	return NULL;

    value = heim_dict_get_value(r->kv, key);
    heim_release(key);
    return value;
}

struct heim_audit_kv_buf {
    char buf[1024];
    size_t pos;
    heim_object_t iter;
};

static void
audit_trail_iterator(heim_object_t key, heim_object_t value, void *arg);

static void
audit_trail_iterator_array(heim_object_t value, void *arg, int *stop)
{
    struct heim_audit_kv_buf *kvb = arg;

    audit_trail_iterator(kvb->iter, value, kvb);
}

static void
audit_trail_iterator(heim_object_t key, heim_object_t value, void *arg)
{
    struct heim_audit_kv_buf *kvb = arg;
    char num[32];
    const char *k = heim_string_get_utf8(key), *v = NULL;
    char *b64 = NULL;

    if (k == NULL || *k == '#') /* # keys are hidden */
	return;

    switch (heim_get_tid(value)) {
    case HEIM_TID_STRING:
	v = heim_string_get_utf8(value);
	break;
    case HEIM_TID_NUMBER:
	snprintf(num, sizeof(num), "%lld", (long long)heim_number_get_long(value));
	v = num;
	break;
    case HEIM_TID_NULL:
	v = "null";
	break;
    case HEIM_TID_BOOL:
	v = heim_bool_val(value) ? "true" : "false";
	break;
    case HEIM_TID_ARRAY:
	if (kvb->iter)
	    break; /* arrays cannot be nested */

	kvb->iter = key;
	heim_array_iterate_f(value, kvb, audit_trail_iterator_array);
	kvb->iter = NULL;
	break;
    case HEIM_TID_DATA: {
	const heim_octet_string *data = heim_data_get_data(value);
	if (rk_base64_encode(data->data, data->length, &b64) >= 0)
	    v = b64;
	break;
    }
    default:
	break;
    }

    if (v == NULL)
	return;

    if (kvb->pos < sizeof(kvb->buf) - 1)
	kvb->buf[kvb->pos++] = ' ';
    for (; *k && kvb->pos < sizeof(kvb->buf) - 1; kvb->pos++)
	kvb->buf[kvb->pos] = *k++;
    if (kvb->pos < sizeof(kvb->buf) - 1)
	kvb->buf[kvb->pos++] = '=';
    for (; *v && kvb->pos < sizeof(kvb->buf) - 1; kvb->pos++)
	kvb->buf[kvb->pos] = *v++;

    free(b64);
}

void
heim_audit_trail(heim_svc_req_desc r, heim_error_code ret, const char *retname)
{
    const char *retval;
    struct heim_audit_kv_buf kvb;
    char retvalbuf[30]; /* Enough for UNKNOWN-%d */

#define CASE(x)	case x : retval = #x; break
    if (retname) {
        retval = retname;
    } else switch (ret ? ret : r->error_code) {
    CASE(ENOMEM);
    CASE(ENOENT);
    CASE(EACCES);
    case 0:
	retval = "SUCCESS";
	break;
    default:
        /* Wish we had a com_err number->symbolic name function */
        (void) snprintf(retvalbuf, sizeof(retvalbuf), "UNKNOWN-%d",
                        ret ? ret : r->error_code);
	retval = retvalbuf;
	break;
    }

    heim_audit_addkv_timediff(r, "elapsed", &r->tv_start, &r->tv_end);
    if (r->e_text && r->kv)
	heim_audit_addkv(r, HEIM_SVC_AUDIT_VIS, "e-text", "%s", r->e_text);

    memset(&kvb, 0, sizeof(kvb));
    if (r->kv)
        heim_dict_iterate_f(r->kv, &kvb, audit_trail_iterator);
    kvb.buf[kvb.pos] = '\0';

    heim_log(r->hcontext, r->logf, 3, "%s %s %s %s %s%s%s%s",
             r->reqtype, retval, r->from,
             r->cname ? r->cname : "<unknown>",
             r->sname ? r->sname : "<unknown>",
             kvb.buf, r->reason ? " reason=" : "",
             r->reason ? heim_string_get_utf8(r->reason) : "");
}
