/*
 * Copyright (c) 1997 - 2004 Kungliga Tekniska Högskolan
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
#include <assert.h>
#include <ctype.h>
#include <parse_time.h>

#if defined(HAVE_FRAMEWORK_COREFOUNDATION)
#include <CoreFoundation/CoreFoundation.h>
#endif

/* Gaah! I want a portable funopen */
struct fileptr {
    heim_context context;
    const char *s;
    FILE *f;
};

static char *
config_fgets(char *str, size_t len, struct fileptr *ptr)
{
    /* XXX this is not correct, in that they don't do the same if the
       line is longer than len */
    if(ptr->f != NULL)
        return fgets(str, len, ptr->f);
    else {
        /* this is almost strsep_copy */
        const char *p;
        ssize_t l;
        if(*ptr->s == '\0')
            return NULL;
        p = ptr->s + strcspn(ptr->s, "\n");
        if(*p == '\n')
            p++;
        l = min(len, (size_t)(p - ptr->s));
        if(len > 0) {
            memcpy(str, ptr->s, l);
            str[l] = '\0';
        }
        ptr->s = p;
        return str;
    }
}

static heim_error_code parse_section(char *p, heim_config_section **s,
                                     heim_config_section **res,
                                     const char **err_message);
static heim_error_code parse_binding(struct fileptr *f, unsigned *lineno, char *p,
                                     heim_config_binding **b,
                                     heim_config_binding **parent,
                                     const char **err_message);
static heim_error_code parse_list(struct fileptr *f, unsigned *lineno,
                                  heim_config_binding **parent,
                                  const char **err_message);

heim_config_section *
heim_config_get_entry(heim_config_section **parent, const char *name, int type)
{
    heim_config_section **q;

    for (q = parent; *q != NULL; q = &(*q)->next)
        if (type == heim_config_list &&
            (unsigned)type == (*q)->type &&
            strcmp(name, (*q)->name) == 0)
            return *q;
    *q = calloc(1, sizeof(**q));
    if (*q == NULL)
        return NULL;
    (*q)->name = strdup(name);
    (*q)->type = type;
    if ((*q)->name == NULL) {
        free(*q);
        *q = NULL;
        return NULL;
    }
    return *q;
}

/*
 * Parse a section:
 *
 * [section]
 *      foo = bar
 *      b = {
 *              a
 *          }
 * ...
 *
 * starting at the line in `p', storing the resulting structure in
 * `s' and hooking it into `parent'.
 * Store the error message in `err_message'.
 */

static heim_error_code
parse_section(char *p, heim_config_section **s, heim_config_section **parent,
              const char **err_message)
{
    char *p1;
    heim_config_section *tmp;

    p1 = strchr (p + 1, ']');
    if (p1 == NULL) {
        *err_message = "missing ]";
        return HEIM_ERR_CONFIG_BADFORMAT;
    }
    *p1 = '\0';
    tmp = heim_config_get_entry(parent, p + 1, heim_config_list);
    if(tmp == NULL) {
        *err_message = "out of memory";
        return HEIM_ERR_CONFIG_BADFORMAT;
    }
    *s = tmp;
    return 0;
}

/*
 * Parse a brace-enclosed list from `f', hooking in the structure at
 * `parent'.
 * Store the error message in `err_message'.
 */

static heim_error_code
parse_list(struct fileptr *f, unsigned *lineno, heim_config_binding **parent,
           const char **err_message)
{
    char buf[2048];
    heim_error_code ret;
    heim_config_binding *b = NULL;
    unsigned beg_lineno = *lineno;

    while(config_fgets(buf, sizeof(buf), f) != NULL) {
        char *p;

        ++*lineno;
        buf[strcspn(buf, "\r\n")] = '\0';
        p = buf;
        while(isspace((unsigned char)*p))
            ++p;
        if (*p == '#' || *p == ';' || *p == '\0')
            continue;
        while(isspace((unsigned char)*p))
            ++p;
        if (*p == '}')
            return 0;
        if (*p == '\0')
            continue;
        ret = parse_binding (f, lineno, p, &b, parent, err_message);
        if (ret)
            return ret;
    }
    *lineno = beg_lineno;
    *err_message = "unclosed {";
    return HEIM_ERR_CONFIG_BADFORMAT;
}

/*
 *
 */

static heim_error_code
parse_binding(struct fileptr *f, unsigned *lineno, char *p,
              heim_config_binding **b, heim_config_binding **parent,
              const char **err_message)
{
    heim_config_binding *tmp;
    char *p1, *p2;
    heim_error_code ret = 0;

    p1 = p;
    while (*p && *p != '=' && !isspace((unsigned char)*p))
        ++p;
    if (*p == '\0') {
        *err_message = "missing =";
        return HEIM_ERR_CONFIG_BADFORMAT;
    }
    p2 = p;
    while (isspace((unsigned char)*p))
        ++p;
    if (*p != '=') {
        *err_message = "missing =";
        return HEIM_ERR_CONFIG_BADFORMAT;
    }
    ++p;
    while(isspace((unsigned char)*p))
        ++p;
    *p2 = '\0';
    if (*p == '{') {
        tmp = heim_config_get_entry(parent, p1, heim_config_list);
        if (tmp == NULL) {
            *err_message = "out of memory";
            return HEIM_ERR_CONFIG_BADFORMAT;
        }
        ret = parse_list (f, lineno, &tmp->u.list, err_message);
    } else {
        tmp = heim_config_get_entry(parent, p1, heim_config_string);
        if (tmp == NULL) {
            *err_message = "out of memory";
            return HEIM_ERR_CONFIG_BADFORMAT;
        }
        p1 = p;
        p = p1 + strlen(p1);
        while(p > p1 && isspace((unsigned char)*(p-1)))
            --p;
        *p = '\0';
        tmp->u.string = strdup(p1);
    }
    *b = tmp;
    return ret;
}

#if defined(HAVE_FRAMEWORK_COREFOUNDATION)

#if MAC_OS_X_VERSION_MIN_REQUIRED >= 1060
#define HAVE_CFPROPERTYLISTCREATEWITHSTREAM 1
#endif

static char *
cfstring2cstring(CFStringRef string)
{
    CFIndex len;
    char *str;

    str = (char *) CFStringGetCStringPtr(string, kCFStringEncodingUTF8);
    if (str)
        return strdup(str);

    len = CFStringGetLength(string);
    len = 1 + CFStringGetMaximumSizeForEncoding(len, kCFStringEncodingUTF8);
    str = malloc(len);
    if (str == NULL)
        return NULL;

    if (!CFStringGetCString (string, str, len, kCFStringEncodingUTF8)) {
        free (str);
        return NULL;
    }
    return str;
}

static void
convert_content(const void *key, const void *value, void *context)
{
    heim_config_section *tmp, **parent = context;
    char *k;

    if (CFGetTypeID(key) != CFStringGetTypeID())
        return;

    k = cfstring2cstring(key);
    if (k == NULL)
        return;

    if (CFGetTypeID(value) == CFStringGetTypeID()) {
        tmp = heim_config_get_entry(parent, k, heim_config_string);
        tmp->u.string = cfstring2cstring(value);
    } else if (CFGetTypeID(value) == CFDictionaryGetTypeID()) {
        tmp = heim_config_get_entry(parent, k, heim_config_list);
        CFDictionaryApplyFunction(value, convert_content, &tmp->u.list);
    } else {
        /* log */
    }
    free(k);
}

static heim_error_code
parse_plist_config(heim_context context, const char *path, heim_config_section **parent)
{
    CFReadStreamRef s;
    CFDictionaryRef d;
    CFURLRef url;

    url = CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault, (UInt8 *)path, strlen(path), 0);
    if (url == NULL) {
        heim_clear_error_message(context);
        return ENOMEM;
    }

    s = CFReadStreamCreateWithFile(kCFAllocatorDefault, url);
    CFRelease(url);
    if (s == NULL) {
        heim_clear_error_message(context);
	if (path[0] != '/') {
	    char cwd[PATH_MAX];
	    if (getcwd(cwd, sizeof(cwd)) == NULL)
		return errno;
	}
        return ENOMEM;
    }

    if (!CFReadStreamOpen(s)) {
        CFRelease(s);
        heim_clear_error_message(context);
        return ENOENT;
    }

#ifdef HAVE_CFPROPERTYLISTCREATEWITHSTREAM
    d = (CFDictionaryRef)CFPropertyListCreateWithStream(NULL, s, 0, kCFPropertyListImmutable, NULL, NULL);
#else
    d = (CFDictionaryRef)CFPropertyListCreateFromStream(NULL, s, 0, kCFPropertyListImmutable, NULL, NULL);
#endif
    CFRelease(s);
    if (d == NULL) {
        heim_clear_error_message(context);
        return ENOENT;
    }

    CFDictionaryApplyFunction(d, convert_content, parent);
    CFRelease(d);

    return 0;
}

#endif

static int
is_absolute_path(const char *path)
{
    /*
     * An absolute path is one that refers to an explicit object
     * without ambiguity.
     */
#ifdef WIN32
    size_t len = strlen(path);

    /* UNC path is by definition absolute */
    if (len > 2
         && ISPATHSEP(path[0])
         && ISPATHSEP(path[1]))
        return 1;

    /* A drive letter path might be absolute */
    if (len > 3
         && isalpha((unsigned char)path[0])
         && path[1] == ':'
         && ISPATHSEP(path[2]))
        return 1;

    /*
     * if no drive letter but first char is a path
     * separator then the drive letter must be obtained
     * from the including file.
     */
#else
    /* UNIX is easy, first char '/' is absolute */
    if (ISPATHSEP(path[0]))
        return 1;
#endif
    return 0;
}

/*
 * Parse the config file `fname', generating the structures into `res'
 * returning error messages in `err_message'
 */

static heim_error_code
heim_config_parse_debug(struct fileptr *f,
                        heim_config_section **res,
                        unsigned *lineno,
                        const char **err_message)
{
    heim_config_section *s = NULL;
    heim_config_binding *b = NULL;
    char buf[2048];
    heim_error_code ret;

    *lineno = 0;
    *err_message = "";

    while (config_fgets(buf, sizeof(buf), f) != NULL) {
        char *p;

        ++*lineno;
        buf[strcspn(buf, "\r\n")] = '\0';
        p = buf;
        while(isspace((unsigned char)*p))
            ++p;
        if (*p == '#' || *p == ';')
            continue;
        if (*p == '[') {
            ret = parse_section(p, &s, res, err_message);
            if (ret)
                return ret;
            b = NULL;
        } else if (*p == '}') {
            *err_message = "unmatched }";
            return 2048;
        } else if (strncmp(p, "include", sizeof("include") - 1) == 0 &&
            isspace((unsigned char)p[sizeof("include") - 1])) {
            p += sizeof("include");
            while (isspace((unsigned char)*p))
                p++;
            if (!is_absolute_path(p)) {
                heim_set_error_message(f->context, HEIM_ERR_CONFIG_BADFORMAT,
                                       "Configuration include path must be "
                                       "absolute");
                return HEIM_ERR_CONFIG_BADFORMAT;
            }
            ret = heim_config_parse_file_multi(f->context, p, res);
            if (ret)
                return ret;
        } else if (strncmp(p, "includedir", sizeof("includedir") - 1) == 0 &&
            isspace((unsigned char)p[sizeof("includedir") - 1])) {
            p += sizeof("includedir");
            while (isspace((unsigned char)*p))
                p++;
            if (!is_absolute_path(p)) {
                heim_set_error_message(f->context, HEIM_ERR_CONFIG_BADFORMAT,
                                       "Configuration includedir path must be "
                                       "absolute");
                return HEIM_ERR_CONFIG_BADFORMAT;
            }
            ret = heim_config_parse_dir_multi(f->context, p, res);
            if (ret)
                return ret;
        } else if(*p != '\0') {
            if (s == NULL) {
                *err_message = "binding before section";
                return 2048;
            }
            ret = parse_binding(f, lineno, p, &b, &s->u.list, err_message);
            if (ret)
                return ret;
        }
    }
    return 0;
}

static int
is_plist_file(const char *fname)
{
    size_t len = strlen(fname);
    char suffix[] = ".plist";
    if (len < sizeof(suffix))
        return 0;
    if (strcasecmp(&fname[len - (sizeof(suffix) - 1)], suffix) != 0)
        return 0;
    return 1;
}

/**
 * Parse configuration files in the given directory and add the result
 * into res.  Only files whose names consist only of alphanumeric
 * characters, hyphen, and underscore, will be parsed, though files
 * ending in ".conf" will also be parsed.
 *
 * This interface can be used to parse several configuration directories
 * into one resulting heim_config_section by calling it repeatably.
 *
 * @param context a Kerberos 5 context.
 * @param dname a directory name to a Kerberos configuration file
 * @param res the returned result, must be free with heim_free_config_files().
 * @return Return an error code or 0, see heim_get_error_message().
 *
 * @ingroup heim_support
 */

heim_error_code
heim_config_parse_dir_multi(heim_context context,
                            const char *dname,
                            heim_config_section **res)
{
    struct dirent *entry;
    heim_error_code ret;
    DIR *d;

    if ((d = opendir(dname)) == NULL)
        return errno;

    while ((entry = readdir(d)) != NULL) {
        char *p = entry->d_name;
        char *path;
        int is_valid = 1;

        while (*p) {
            /*
             * Here be dragons.  The call to heim_config_parse_file_multi()
             * below expands path tokens.  Because of the limitations here
             * on file naming, we can't have path tokens in the file name,
             * so we're safe.  Anyone changing this if condition here should
             * be aware.
             */
            if (!isalnum((unsigned char)*p) && *p != '_' && *p != '-' &&
                strcmp(p, ".conf") != 0) {
                is_valid = 0;
                break;
            }
            p++;
        }
        if (!is_valid)
            continue;

        if (asprintf(&path, "%s/%s", dname, entry->d_name) == -1 ||
            path == NULL) {
            (void) closedir(d);
            return heim_enomem(context);
        }
        ret = heim_config_parse_file_multi(context, path, res);
        free(path);
        if (ret == ENOMEM) {
            (void) closedir(d);
            return ENOMEM;
        }
        /* Ignore malformed config files so we don't lock out admins, etc... */
    }
    (void) closedir(d);
    return 0;
}

static int
is_devnull(struct stat *st)
{
#ifdef WIN32
    return 0;
#else
    struct stat devnullst;

    if (stat("/dev/null", &devnullst) == -1)
        return 0;
    return st->st_dev == devnullst.st_dev && st->st_ino == devnullst.st_ino;
#endif
}

HEIMDAL_THREAD_LOCAL int config_include_depth = 0;

/**
 * Parse a configuration file and add the result into res. This
 * interface can be used to parse several configuration files into one
 * resulting heim_config_section by calling it repeatably.
 *
 * @param context a Kerberos 5 context.
 * @param fname a file name to a Kerberos configuration file
 * @param res the returned result, must be free with heim_free_config_files().
 * @return Return an error code or 0, see heim_get_error_message().
 *
 * @ingroup heim_support
 */

heim_error_code
heim_config_parse_file_multi(heim_context context,
                             const char *fname,
                             heim_config_section **res)
{
    const char *str;
    char *newfname = NULL;
    char *exp_fname = NULL;
    unsigned lineno = 0;
    heim_error_code ret = 0;
    struct fileptr f;
    struct stat st;

    if (config_include_depth > 5) {
        heim_warnx(context, "Maximum config file include depth reached; "
                   "not including %s", fname);
        return 0;
    }
    config_include_depth++;

    /**
     * If the fname starts with "~/" parse configuration file in the
     * current users home directory. The behavior can be disabled and
     * enabled by calling heim_set_home_dir_access().
     */
    if (ISTILDE(fname[0]) && ISPATHSEP(fname[1])) {
        if (!heim_context_get_homedir_access(context)) {
            heim_set_error_message(context, EPERM,
                                   "Access to home directory not allowed");
	    ret = EPERM;
	    goto out;
        }
        if (asprintf(&newfname, "%%{USERCONFIG}%s", &fname[1]) < 0 ||
            newfname == NULL) {
	    ret = heim_enomem(context);
	    goto out;
        }
        fname = newfname;
    }

    /*
     * Note that heim_config_parse_dir_multi() doesn't want tokens
     * expanded here, but it happens to limit the names of files to
     * include such that there can be no tokens to expand.  Don't
     * add token expansion for tokens using _, say.
     */
    ret = heim_expand_path_tokens(context, fname, 1, &exp_fname, NULL);
    if (ret)
	goto out;
    free(newfname);
    fname = newfname = exp_fname;


    if (is_plist_file(fname)) {
#if defined(HAVE_FRAMEWORK_COREFOUNDATION)
        ret = parse_plist_config(context, fname, res);
        if (ret) {
            heim_set_error_message(context, ret,
                                   "Failed to parse plist %s", fname);
            goto out;
        }
#else
        heim_set_error_message(context, ENOENT,
                               "no support for plist configuration files");
        ret = ENOENT;
	goto out;
#endif
    } else {
        f.context = context;
        f.f = fopen(fname, "r");
        f.s = NULL;
        if (f.f == NULL || fstat(fileno(f.f), &st) == -1) {
            if (f.f != NULL)
                (void) fclose(f.f);
            ret = errno;
            heim_set_error_message(context, ret, "open or stat %s: %s",
                                   fname, strerror(ret));
            goto out;
        }

        if (!S_ISREG(st.st_mode) && !is_devnull(&st)) {
            (void) fclose(f.f);
            heim_set_error_message(context, EISDIR, "not a regular file %s: %s",
                                   fname, strerror(EISDIR));
            ret = EISDIR;
	    goto out;
        }

        ret = heim_config_parse_debug(&f, res, &lineno, &str);
        fclose(f.f);
        if (ret) {
	    if (ret != HEIM_ERR_CONFIG_BADFORMAT)
                ret = HEIM_ERR_CONFIG_BADFORMAT;
	    heim_set_error_message(context, ret, "%s:%u: %s",
				   fname, lineno, str);
            goto out;
        }
    }

  out:
    config_include_depth--;
    if (ret == HEIM_ERR_CONFIG_BADFORMAT || (ret && config_include_depth > 0)) {
	heim_warn(context, ret, "Ignoring");
	if (config_include_depth > 0)
	    ret = 0;
    }
    free(newfname);
    return ret;
}

heim_error_code
heim_config_parse_file(heim_context context,
                       const char *fname,
                       heim_config_section **res)
{
    *res = NULL;
    return heim_config_parse_file_multi(context, fname, res);
}

static void
free_binding(heim_context context, heim_config_binding *b)
{
    heim_config_binding *next_b;

    while (b) {
        free (b->name);
        assert(b->type == heim_config_string || b->type == heim_config_list);
        if (b->type == heim_config_string)
            free (b->u.string);
        else
            free_binding (context, b->u.list);
        next_b = b->next;
        free (b);
        b = next_b;
    }
}

/**
 * Free configuration file section, the result of
 * heim_config_parse_file() and heim_config_parse_file_multi().
 *
 * @param context A Kerberos 5 context
 * @param s the configuration section to free
 *
 * @return returns 0 on successes, otherwise an error code, see
 *          heim_get_error_message()
 *
 * @ingroup heim_support
 */

heim_error_code
heim_config_file_free(heim_context context, heim_config_section *s)
{
    free_binding (context, s);
    return 0;
}

#ifndef HEIMDAL_SMALLER

heim_error_code
heim_config_copy(heim_context context,
                 heim_config_section *c,
                 heim_config_section **head)
{
    heim_config_binding *d, *previous = NULL;

    *head = NULL;

    while (c) {
        d = calloc(1, sizeof(*d));

        if (*head == NULL)
            *head = d;

        d->name = strdup(c->name);
        d->type = c->type;
        assert(d->type == heim_config_string || d->type == heim_config_list);
        if (d->type == heim_config_string)
            d->u.string = strdup(c->u.string);
        else
            heim_config_copy (context, c->u.list, &d->u.list);
        if (previous)
            previous->next = d;

        previous = d;
        c = c->next;
    }
    return 0;
}

#endif /* HEIMDAL_SMALLER */

const void *
heim_config_get_next(heim_context context,
                     const heim_config_section *c,
                     const heim_config_binding **pointer,
                     int type,
                     ...)
{
    const char *ret;
    va_list args;

    va_start(args, type);
    ret = heim_config_vget_next(context, c, pointer, type, args);
    va_end(args);
    return ret;
}

static const void *
vget_next(heim_context context,
          const heim_config_binding *b,
          const heim_config_binding **pointer,
          int type,
          const char *name,
          va_list args)
{
    const char *p = va_arg(args, const char *);

    while (b != NULL) {
        if (strcmp(b->name, name) == 0) {
            if (b->type == (unsigned)type && p == NULL) {
                *pointer = b;
                return b->u.generic;
            } else if (b->type == heim_config_list && p != NULL) {
                return vget_next(context, b->u.list, pointer, type, p, args);
            }
        }
        b = b->next;
    }
    return NULL;
}

const void *
heim_config_vget_next(heim_context context,
                      const heim_config_section *c,
                      const heim_config_binding **pointer,
                      int type,
                      va_list args)
{
    const heim_config_binding *b;
    const char *p;

    if (c == NULL)
        return NULL;

    if (*pointer == NULL) {
        /* first time here, walk down the tree looking for the right
           section */
        p = va_arg(args, const char *);
        if (p == NULL)
            return NULL;
        return vget_next(context, c, pointer, type, p, args);
    }

    /* we were called again, so just look for more entries with the
       same name and type */
    for (b = (*pointer)->next; b != NULL; b = b->next) {
        if(strcmp(b->name, (*pointer)->name) == 0 && b->type == (unsigned)type) {
            *pointer = b;
            return b->u.generic;
        }
    }
    return NULL;
}

const void *
heim_config_get(heim_context context,
                const heim_config_section *c,
                int type,
                ...)
{
    const void *ret;
    va_list args;

    va_start(args, type);
    ret = heim_config_vget(context, c, type, args);
    va_end(args);
    return ret;
}


const void *
heim_config_vget(heim_context context,
                 const heim_config_section *c,
                 int type,
                 va_list args)
{
    const heim_config_binding *foo = NULL;

    return heim_config_vget_next(context, c, &foo, type, args);
}

/**
 * Get a list of configuration binding list for more processing
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param ... a list of names, terminated with NULL.
 *
 * @return NULL if configuration list is not found, a list otherwise
 *
 * @ingroup heim_support
 */

const heim_config_binding *
heim_config_get_list(heim_context context,
                     const heim_config_section *c,
                     ...)
{
    const heim_config_binding *ret;
    va_list args;

    va_start(args, c);
    ret = heim_config_vget_list(context, c, args);
    va_end(args);
    return ret;
}

/**
 * Get a list of configuration binding list for more processing
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param args a va_list of arguments
 *
 * @return NULL if configuration list is not found, a list otherwise
 *
 * @ingroup heim_support
 */

const heim_config_binding *
heim_config_vget_list(heim_context context,
                      const heim_config_section *c,
                      va_list args)
{
    return heim_config_vget(context, c, heim_config_list, args);
}

/**
 * Returns a "const char *" to a string in the configuration database.
 * The string may not be valid after a reload of the configuration
 * database so a caller should make a local copy if it needs to keep
 * the string.
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param ... a list of names, terminated with NULL.
 *
 * @return NULL if configuration string not found, a string otherwise
 *
 * @ingroup heim_support
 */

const char *
heim_config_get_string(heim_context context,
                       const heim_config_section *c,
                       ...)
{
    const char *ret;
    va_list args;

    va_start(args, c);
    ret = heim_config_vget_string(context, c, args);
    va_end(args);
    return ret;
}

/**
 * Like heim_config_get_string(), but uses a va_list instead of ...
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param args a va_list of arguments
 *
 * @return NULL if configuration string not found, a string otherwise
 *
 * @ingroup heim_support
 */

const char *
heim_config_vget_string(heim_context context,
                        const heim_config_section *c,
                        va_list args)
{
    return heim_config_vget(context, c, heim_config_string, args);
}

/**
 * Like heim_config_vget_string(), but instead of returning NULL,
 * instead return a default value.
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param def_value the default value to return if no configuration
 *        found in the database.
 * @param args a va_list of arguments
 *
 * @return a configuration string
 *
 * @ingroup heim_support
 */

const char *
heim_config_vget_string_default(heim_context context,
                                const heim_config_section *c,
                                const char *def_value,
                                va_list args)
{
    const char *ret;

    ret = heim_config_vget_string(context, c, args);
    if (ret == NULL)
        ret = def_value;
    return ret;
}

/**
 * Like heim_config_get_string(), but instead of returning NULL,
 * instead return a default value.
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param def_value the default value to return if no configuration
 *        found in the database.
 * @param ... a list of names, terminated with NULL.
 *
 * @return a configuration string
 *
 * @ingroup heim_support
 */

const char *
heim_config_get_string_default(heim_context context,
                               const heim_config_section *c,
                               const char *def_value,
                               ...)
{
    const char *ret;
    va_list args;

    va_start(args, def_value);
    ret = heim_config_vget_string_default (context, c, def_value, args);
    va_end(args);
    return ret;
}

static char *
next_component_string(char * begin, const char * delims, char **state)
{
    char * end;

    if (begin == NULL)
        begin = *state;

    if (*begin == '\0')
        return NULL;

    end = begin;
    while (*end == '"') {
        char * t = strchr(end + 1, '"');

        if (t)
            end = ++t;
        else
            end += strlen(end);
    }

    if (*end != '\0') {
        size_t pos;

        pos = strcspn(end, delims);
        end = end + pos;
    }

    if (*end != '\0') {
        *end = '\0';
        *state = end + 1;
        if (*begin == '"' && *(end - 1) == '"' && begin + 1 < end) {
            begin++; *(end - 1) = '\0';
        }
        return begin;
    }

    *state = end;
    if (*begin == '"' && *(end - 1) == '"' && begin + 1 < end) {
        begin++; *(end - 1) = '\0';
    }
    return begin;
}

/**
 * Get a list of configuration strings, free the result with
 * heim_config_free_strings().
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param args a va_list of arguments
 *
 * @return TRUE or FALSE
 *
 * @ingroup heim_support
 */

char **
heim_config_vget_strings(heim_context context,
                         const heim_config_section *c,
                         va_list args)
{
    char **strings = NULL;
    size_t nstr = 0;
    const heim_config_binding *b = NULL;
    const char *p;

    while((p = heim_config_vget_next(context, c, &b,
                                     heim_config_string, args))) {
        char *tmp = strdup(p);
        char *pos = NULL;
        char *s;
        if(tmp == NULL)
            goto cleanup;
        s = next_component_string(tmp, " \t", &pos);
        while(s){
            char **tmp2 = realloc(strings, (nstr + 1) * sizeof(*strings));
            if(tmp2 == NULL) {
                free(tmp);
                goto cleanup;
            }
            strings = tmp2;
            strings[nstr] = strdup(s);
            nstr++;
            if(strings[nstr-1] == NULL) {
                free(tmp);
                goto cleanup;
            }
            s = next_component_string(NULL, " \t", &pos);
        }
        free(tmp);
    }
    if(nstr){
        char **tmp = realloc(strings, (nstr + 1) * sizeof(*strings));
        if(tmp == NULL)
            goto cleanup;
        strings = tmp;
        strings[nstr] = NULL;
    }
    return strings;
cleanup:
    while(nstr--)
        free(strings[nstr]);
    free(strings);
    return NULL;

}

/**
 * Get a list of configuration strings, free the result with
 * heim_config_free_strings().
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param ... a list of names, terminated with NULL.
 *
 * @return TRUE or FALSE
 *
 * @ingroup heim_support
 */

char **
heim_config_get_strings(heim_context context,
                        const heim_config_section *c,
                        ...)
{
    va_list ap;
    char **ret;
    va_start(ap, c);
    ret = heim_config_vget_strings(context, c, ap);
    va_end(ap);
    return ret;
}

/**
 * Free the resulting strings from heim_config-get_strings() and
 * heim_config_vget_strings().
 *
 * @param strings strings to free
 *
 * @ingroup heim_support
 */

void
heim_config_free_strings(char **strings)
{
    char **s = strings;

    while (s && *s) {
        free(*s);
        s++;
    }
    free(strings);
}

/**
 * Like heim_config_get_bool_default() but with a va_list list of
 * configuration selection.
 *
 * Configuration value to a boolean value, where yes/true and any
 * non-zero number means TRUE and other value is FALSE.
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param def_value the default value to return if no configuration
 *        found in the database.
 * @param args a va_list of arguments
 *
 * @return TRUE or FALSE
 *
 * @ingroup heim_support
 */

int
heim_config_vget_bool_default(heim_context context,
                              const heim_config_section *c,
                              int def_value,
                              va_list args)
{
    const char *str;
    str = heim_config_vget_string(context, c, args);
    if (str == NULL)
        return def_value;
    return !!(strcasecmp(str, "yes") == 0 ||
              strcasecmp(str, "true") == 0 ||
              atoi(str));
}

/**
 * heim_config_get_bool() will convert the configuration
 * option value to a boolean value, where yes/true and any non-zero
 * number means TRUE and other value is FALSE.
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param args a va_list of arguments
 *
 * @return TRUE or FALSE
 *
 * @ingroup heim_support
 */

int
heim_config_vget_bool(heim_context context,
                      const heim_config_section *c,
                      va_list args)
{
    return heim_config_vget_bool_default(context, c, 0, args);
}

/**
 * heim_config_get_bool_default() will convert the configuration
 * option value to a boolean value, where yes/true and any non-zero
 * number means TRUE and other value is FALSE.
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param def_value the default value to return if no configuration
 *        found in the database.
 * @param ... a list of names, terminated with NULL.
 *
 * @return TRUE or FALSE
 *
 * @ingroup heim_support
 */

int
heim_config_get_bool_default(heim_context context,
                             const heim_config_section *c,
                             int def_value,
                             ...)
{
    va_list ap;
    int ret;

    va_start(ap, def_value);
    ret = heim_config_vget_bool_default(context, c, def_value, ap);
    va_end(ap);
    return ret;
}

/**
 * Like heim_config_get_bool() but with a va_list list of
 * configuration selection.
 *
 * Configuration value to a boolean value, where yes/true and any
 * non-zero number means TRUE and other value is FALSE.
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param ... a list of names, terminated with NULL.
 *
 * @return TRUE or FALSE
 *
 * @ingroup heim_support
 */

int
heim_config_get_bool(heim_context context,
                     const heim_config_section *c,
                     ...)
{
    va_list ap;
    int ret;
    va_start(ap, c);
    ret = heim_config_vget_bool (context, c, ap);
    va_end(ap);
    return ret;
}

/**
 * Get the time from the configuration file using a relative time.
 *
 * Like heim_config_get_time_default() but with a va_list list of
 * configuration selection.
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param def_value the default value to return if no configuration
 *        found in the database.
 * @param args a va_list of arguments
 *
 * @return parsed the time (or def_value on parse error)
 *
 * @ingroup heim_support
 */

time_t
heim_config_vget_time_default(heim_context context,
                              const heim_config_section *c,
                              int def_value,
                              va_list args)
{
    const char *str;
    time_t t = -1;

    if ((str = heim_config_vget_string(context, c, args)))
        t = parse_time(str, "s");
    return t != -1 ? t : def_value;
}

/**
 * Get the time from the configuration file using a relative time, for example: 1h30s
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param args a va_list of arguments
 *
 * @return parsed the time or -1 on error
 *
 * @ingroup heim_support
 */

time_t
heim_config_vget_time(heim_context context,
                      const heim_config_section *c,
                      va_list args)
{
    return heim_config_vget_time_default(context, c, -1, args);
}

/**
 * Get the time from the configuration file using a relative time, for example: 1h30s
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param def_value the default value to return if no configuration
 *        found in the database.
 * @param ... a list of names, terminated with NULL.
 *
 * @return parsed the time (or def_value on parse error)
 *
 * @ingroup heim_support
 */

time_t
heim_config_get_time_default(heim_context context,
                             const heim_config_section *c,
                             int def_value,
                             ...)
{
    va_list ap;
    time_t ret;

    va_start(ap, def_value);
    ret = heim_config_vget_time_default(context, c, def_value, ap);
    va_end(ap);
    return ret;
}

/**
 * Get the time from the configuration file using a relative time, for example: 1h30s
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param ... a list of names, terminated with NULL.
 *
 * @return parsed the time or -1 on error
 *
 * @ingroup heim_support
 */

time_t
heim_config_get_time(heim_context context,
                     const heim_config_section *c,
                     ...)
{
    va_list ap;
    int ret;
    va_start(ap, c);
    ret = heim_config_vget_time(context, c, ap);
    va_end(ap);
    return ret;
}


int
heim_config_vget_int_default(heim_context context,
                             const heim_config_section *c,
                             int def_value,
                             va_list args)
{
    const char *str;
    str = heim_config_vget_string (context, c, args);
    if(str == NULL)
        return def_value;
    else {
        char *endptr;
        long l;
        l = strtol(str, &endptr, 0);
        if (endptr == str)
            return def_value;
        else
            return l;
    }
}

int
heim_config_vget_int(heim_context context,
                     const heim_config_section *c,
                     va_list args)
{
    return heim_config_vget_int_default(context, c, -1, args);
}

int
heim_config_get_int_default(heim_context context,
                            const heim_config_section *c,
                            int def_value,
                            ...)
{
    va_list ap;
    int ret;

    va_start(ap, def_value);
    ret = heim_config_vget_int_default(context, c, def_value, ap);
    va_end(ap);
    return ret;
}

int
heim_config_get_int(heim_context context,
                    const heim_config_section *c,
                    ...)
{
    va_list ap;
    int ret;
    va_start(ap, c);
    ret = heim_config_vget_int (context, c, ap);
    va_end(ap);
    return ret;
}

#ifndef HEIMDAL_SMALLER
heim_error_code
heim_config_parse_string_multi(heim_context context,
                               const char *string,
                               heim_config_section **res)
{
    const char *str;
    unsigned lineno = 0;
    heim_error_code ret;
    struct fileptr f;

    f.context = context;
    f.f = NULL;
    f.s = string;

    ret = heim_config_parse_debug(&f, res, &lineno, &str);
    if (ret) {
	if (ret != HEIM_ERR_CONFIG_BADFORMAT) {
	    ret = HEIM_ERR_CONFIG_BADFORMAT;
	    heim_set_error_message(context, ret, "%s:%u: %s",
				   "<constant>", lineno, str);
	}
        return ret;
    }
    return 0;
}
#endif
