/*
 * Copyright (c) 1995, 1996, 1997 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the Kungliga Tekniska
 *      Högskolan and its contributors.
 * 
 * 4. Neither the name of the Institute nor the names of its contributors
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

#include "krb5_locl.h"

RCSID("$Id");

struct facility {
    void (*log)(struct facility *, const char *, const char *);
    void (*close)(struct facility*);
    void *data;
};

static struct facility*
log_realloc(krb5_log_facility *f)
{
    struct facility *fp;
    f->len++;
    fp = realloc(f->val, f->len * sizeof(*f->val));
    if(fp == NULL)
	return NULL;
    f->val = fp;
    fp += f->len - 1;
    return fp;
}

struct s2i{
    char *s;
    int val;
};

#define L(X) { #X, LOG_ ## X }

struct s2i syslogvals[] = {
    L(EMERG),
    L(ALERT),
    L(CRIT),
    L(ERR),
    L(WARNING),
    L(NOTICE),
    L(INFO),
    L(DEBUG),

    L(AUTH),
    L(AUTHPRIV),
    L(CRON),
    L(DAEMON),
    L(FTP),
    L(KERN),
    L(LPR),
    L(MAIL),
    L(NEWS),
    L(SYSLOG),
    L(USER),
    L(UUCP),
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
    while(table->s && strcasecmp(table->s, s))
	table++;
    return table->val;
}



struct syslog_data{
    int priority;
};

static void
log_syslog(struct facility *fac,
	   const char *time,
	   const char *msg)
     
{
    struct syslog_data *s = fac->data;
    syslog(s->priority, "%s", msg);
}

static void
close_syslog(struct facility *fac)
{
    free(fac->data);
    closelog();
}

static void
open_syslog(const char *id, const char *sev, const char *fac, 
	    struct facility *f)
{
    struct syslog_data *sd = malloc(sizeof(*sd));
    int i;
    i = find_value(sev, syslogvals);
    if(i == -1)
	i = LOG_ERR;
    sd->priority = i;
    i = find_value(fac, syslogvals);
    if(i == -1)
	i = LOG_AUTH;
    sd->priority |= i;
    openlog(id, LOG_PID | LOG_NDELAY, i);
    f->log = log_syslog;
    f->close = close_syslog;
    f->data = sd;
}

struct file_data{
    char *filename;
    char *mode;
    FILE *fd;
    int keep_open;
};

static void
log_file(struct facility *fac,
	 const char *time,
	 const char *msg)
{
    struct file_data *f = fac->data;
    if(f->keep_open == 0)
	f->fd = fopen(f->filename, f->mode);
    fprintf(f->fd, "%s %s\n", time, msg);
    if(f->keep_open == 0)
	fclose(f->fd);
}

static void
close_file(struct facility *fac)
{
    struct file_data *f = fac->data;
    if(f->keep_open && f->filename)
	fclose(f->fd);
    free(fac->data);
}

static void
open_file(struct facility *fac, char *filename, char *mode, 
	  FILE *f, int keep_open)
{
    struct file_data *fd = malloc(sizeof(*fd));
    fac->log = log_file;
    fac->close = close_file;
    fd->filename = filename;
    fd->mode = mode;
    fd->fd = f;
    fd->keep_open = keep_open;
    fac->data = fd;
}

krb5_error_code
krb5_openlog(krb5_context context,
	     const char *program,
	     krb5_log_facility **fac)
{
    const char *p;
    const char *logname = program;
    krb5_log_facility *f;
    struct facility *fp;
    krb5_config_binding *binding = NULL;
    f = calloc(1, sizeof(*f));
    if(krb5_config_get_string(context->cf, "logging", program, NULL) == NULL)
	logname = "default";
    while(p = krb5_config_get_next(context->cf, &binding, STRING, 
				   "logging",
				   logname,
				   NULL)){
	fprintf(stderr, "%s\n", p);
	if(strcmp(p, "STDERR") == 0){
	    struct facility *fp = log_realloc(f);
	    open_file(fp, NULL, NULL, stderr, 1);
	}else if(strcmp(p, "CONSOLE") == 0){
	    struct facility *fp = log_realloc(f);
	    open_file(fp, "/dev/console", "w", NULL, 0);
	}else if(strncmp(p, "FILE:", 4) == 0 && (p[4] == ':' || p[4] == '=')){
	    struct facility *fp = log_realloc(f);
	    char *fn = strdup(p + 5);
	    FILE *file = NULL;
	    int keep_open = 0;
	    if(p[4] == '='){
		int i = open(fn, O_WRONLY | O_CREAT | 
			     O_TRUNC | O_APPEND, 0666);
		file = fdopen(i, "a");
		keep_open = 1;
	    }
	    open_file(fp, fn, "a", file, keep_open);
	}else if(strncmp(p, "DEVICE=", 6) == 0){
	    struct facility *fp = log_realloc(f);
	    open_file(fp, strdup(p + 7), "w", NULL, 0);
	}else if(strncmp(p, "SYSLOG", 6) == 0){
	    char *severity;
	    char *facility;
	    struct facility *fd;
	    severity = strchr(p, ':');
	    if(severity == NULL)
		severity = "ERR";
	    facility = strchr(severity, ':');
	    if(facility == NULL)
		facility = "AUTH";
	    fd = log_realloc(f);
	    open_syslog(program, severity, facility, fd);
	}
    }
    *fac = f;
    return 0;
}

krb5_error_code
krb5_closelog(krb5_context context,
	      krb5_log_facility *fac)
{
    int i;
    for(i = 0; i < fac->len; i++)
	(*fac->val[i].close)(&fac->val[i]);
    return 0;
}

krb5_error_code
krb5_log(krb5_context context,
	 krb5_log_facility *fac,
	 const char *fmt,
	 ...)
{
    char *msg;
    char buf[64];
    time_t t;
    int i;
    va_list ap;

    va_start(ap, fmt);
    vasprintf(&msg, fmt, ap);
    va_end(ap);
    t = time(NULL);
    strftime(buf, sizeof(buf), "%d-%b-%Y %H:%M:%S", localtime(&t));
    for(i = 0; i < fac->len; i++)
	(*fac->val[i].log)(&fac->val[i], buf, msg);
    free(msg);
    return 0;
}
