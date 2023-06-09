/*
 * Copyright (c) 1997 - 2008 Kungliga Tekniska Högskolan
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

#include "krb5_locl.h"

typedef struct krb5_dcache{
    krb5_ccache fcache;
    char *name;
    char *dir;
    char *sub;
    unsigned int default_candidate:1;
} krb5_dcache;

#define DCACHE(X) ((krb5_dcache*)(X)->data.data)
#define D2FCACHE(X) ((X)->fcache)

static krb5_error_code KRB5_CALLCONV dcc_close(krb5_context, krb5_ccache);
static krb5_error_code KRB5_CALLCONV dcc_get_default_name(krb5_context, char **);
static krb5_error_code KRB5_CALLCONV dcc_set_default(krb5_context, krb5_ccache);

/*
 * Make subsidiary filesystem safe by mapping / and : to -.  If the subsidiary
 * is longer than 128 bytes, then truncate.
 * In all cases, "tkt." is prefixed to be compatible with the DIR requirement
 * that subsidiary ccache files be named tkt*.
 *
 * Thus host/foo.bar.baz@BAR.BAZ -> tkt.host-foo.bar.baz@BAR.BAZ.
 *
 * In particular, no filesystem component separators will be emitted, and . and
 * .. will never be traversed.
 */
static krb5_error_code
fs_encode_subsidiary(krb5_context context,
                     krb5_dcache *dc,
                     const char *subsidiary,
                     char **res)
{
    size_t len = strlen(subsidiary);
    size_t i;

    *res = NULL;
    if (asprintf(res, "tkt.%s", subsidiary) == -1 || *res == NULL)
        return krb5_enomem(context);
    for (i = sizeof("tkt.") - 1; i < len; i++) {
        switch ((*res)[i]) {
#ifdef WIN32
        case '\\':  (*res)[0] = '-'; break;
#endif
        case '/':   (*res)[0] = '-'; break;
        case ':':   (*res)[0] = '-'; break;
        default:                     break;
        }
    }

    /* Hopefully this will work on all filesystems */
    if (len > 128 - sizeof("tkt.") - 1)
        (*res)[127] = '\0';
    return 0;
}

static char *
primary_create(krb5_dcache *dc)
{
    char *primary = NULL;
    int asprintf_ret = asprintf(&primary, "%s/primary", dc->dir);
    if (asprintf_ret == -1 || primary == NULL) {
	return NULL;
    }

    return primary;
}

static int
is_filename_cacheish(const char *name)
{
    size_t i;

    if (strncmp(name, "tkt", sizeof("tkt") - 1) != 0)
        return 0;
    for (i = sizeof("tkt") - 1; name[i]; i++)
        if (ISPATHSEP(name[i]))
            return 0;
    return 1;
}

static krb5_error_code
set_default_cache(krb5_context context, krb5_dcache *dc, const char *residual)
{
    char *path = NULL, *primary = NULL;
    krb5_error_code ret;
    struct iovec iov[2];
    size_t len;
    int fd = -1;
    int asprintf_ret;

    asprintf_ret = asprintf(&path, "%s/primary-XXXXXX", dc->dir);
    if (asprintf_ret == -1 || path == NULL) {
	return krb5_enomem(context);
    }

    fd = mkstemp(path);
    if (fd < 0) {
	ret = errno;
	goto out;
    }
    rk_cloexec(fd);
#ifndef _WIN32
    if (fchmod(fd, S_IRUSR | S_IWUSR) < 0) {
	ret = errno;
	goto out;
    }
#endif
    len = strlen(residual);

    iov[0].iov_base = rk_UNCONST(residual);
    iov[0].iov_len = len;
    iov[1].iov_base = "\n";
    iov[1].iov_len = 1;

    if (writev(fd, iov, sizeof(iov)/sizeof(iov[0])) != len + 1) {
	ret = errno;
	goto out;
    }
    
    primary = primary_create(dc);
    if (primary == NULL) {
	ret = krb5_enomem(context);
	goto out;
    }

    if (rename(path, primary) < 0) {
	ret = errno;
	goto out;
    }

    close(fd);
    fd = -1;

    ret = 0;
 out:
    if (fd >= 0) {
	(void)unlink(path);
	close(fd);
    }
    if (path)
	free(path);
    if (primary)
	free(primary);

    return ret;
}

static krb5_error_code
get_default_cache(krb5_context context, krb5_dcache *dc,
                  const char *subsidiary, char **residual)
{
    krb5_error_code ret;
    char buf[MAXPATHLEN];
    char *primary = NULL;
    FILE *f;

    *residual = NULL;
    if (subsidiary)
        return fs_encode_subsidiary(context, dc, subsidiary, residual);

    primary = primary_create(dc);
    if (primary == NULL)
	return krb5_enomem(context);

    f = fopen(primary, "r");
    if (f == NULL) {
	if (errno == ENOENT) {
	    free(primary);
	    *residual = strdup("tkt");
	    if (*residual == NULL)
		return krb5_enomem(context);
	    return 0;
	}
	ret = errno;
	krb5_set_error_message(context, ret, "failed to open %s", primary);
	free(primary);
	return ret;
    }

    if (fgets(buf, sizeof(buf), f) == NULL) {
	ret = ferror(f);
	fclose(f);
	krb5_set_error_message(context, ret, "read file %s", primary);
	free(primary);
	return ret;
    }
    fclose(f);
	
    buf[strcspn(buf, "\r\n")] = '\0';

    if (!is_filename_cacheish(buf)) {
	krb5_set_error_message(context, KRB5_CC_FORMAT,
			       "name in %s is not a cache (doesn't start with tkt)", primary);
	free(primary);
        return KRB5_CC_FORMAT;
    }

    free(primary);

    *residual = strdup(buf);
    if (*residual == NULL)
	return krb5_enomem(context);

    return 0;
}



static krb5_error_code KRB5_CALLCONV
dcc_get_name_2(krb5_context context,
	       krb5_ccache id,
	       const char **name,
	       const char **dir,
	       const char **sub)
{
    krb5_dcache *dc = DCACHE(id);

    if (name)
        *name = dc->name;
    if (dir)
        *dir = dc->dir;
    if (sub)
        *sub = dc->sub;
    return 0;
}


static krb5_error_code
verify_directory(krb5_context context, const char *path)
{
    struct stat sb;

    if (!path[0]) {
        krb5_set_error_message(context, EINVAL,
                               N_("DIR empty directory component", ""));
        return EINVAL;
    }

    /* XXX should use mkdirx_np()  */
    if (rk_mkdir(path, S_IRWXU) == 0)
        return 0;

    if (stat(path, &sb) != 0) {
	if (errno == ENOENT) {
	    krb5_set_error_message(context, ENOENT,
				   N_("DIR directory %s doesn't exists", ""), path);
	    return ENOENT;
	} else {
	    krb5_set_error_message(context, errno,
				   N_("DIR directory %s is bad: %s", ""), path, strerror(errno));
	    return errno;
	}
    }
    if (!S_ISDIR(sb.st_mode)) {
	krb5_set_error_message(context, KRB5_CC_BADNAME, 
			       N_("DIR directory %s is not a directory", ""), path);
	return KRB5_CC_BADNAME;
    }

    return 0;
}

static void
dcc_release(krb5_context context, krb5_dcache *dc)
{
    if (dc->fcache)
	krb5_cc_close(context, dc->fcache);
    free(dc->sub);
    free(dc->dir);
    free(dc->name);
    memset(dc, 0, sizeof(*dc));
    free(dc);
}

static krb5_error_code
get_default_dir(krb5_context context, char **res)
{
    krb5_error_code ret;
    char *s;

    if ((ret = dcc_get_default_name(context, &s)))
        return ret;
    if (strncmp(s, "DIR:", sizeof("DIR:") - 1) != 0) {
        *res = s;
        s = NULL;
    } else if ((*res = strdup(s + sizeof("DIR:") - 1)) == NULL) {
        ret = krb5_enomem(context);
    }
    free(s);
    return ret;
}

static krb5_error_code KRB5_CALLCONV
dcc_resolve_2(krb5_context context,
	      krb5_ccache *id,
	      const char *res,
	      const char *sub)
{
    krb5_error_code ret;
    krb5_dcache *dc = NULL;
    char *filename = NULL;
    size_t len;
    int has_pathsep = 0;

    if (sub) {
        /*
         * Here `res' has the directory name (or, if NULL, refers to the
         * default DIR cccol), and `sub' has the "subsidiary" name, to which
         * we'll prefix "tkt." (though we will insist only on "tkt" later).
         */
        if ((dc = calloc(1, sizeof(*dc))) == NULL ||
            asprintf(&dc->sub, "tkt.%s", sub) == -1 || dc->sub == NULL) {
            free(dc);
            return krb5_enomem(context);
        }
        if (res && res[0] && (dc->dir = strdup(res)) == NULL) {
            free(dc->sub);
            free(dc);
            return krb5_enomem(context);
        } else if ((!res || !res[0]) && (ret = get_default_dir(context, &dc->dir))) {
            free(dc->sub);
            free(dc);
            return ret;
        }
    } else {
        const char *p;
        int is_drive_letter_colon = 0;

        /*
         * Here `res' has whatever string followed "DIR:", and we need to parse
         * it into `dc->dir' and `dc->sub'.
         *
         * Conventions we support for DIR cache naming:
         *
         *  - DIR:path:NAME     ---> FILE:path/tktNAME
         *  - DIR::path/tktNAME ---> FILE:path/tktNAME
         *  - DIR::NAME         ---> FILE:${default_DIR_cccol_path}/tktNAME
         *                       \-> FILE:/tmp/krb5cc_${uid}_dir/tktNAME
         *  - DIR:path          ---> FILE:path/$(cat primary) or FILE:path/tkt
         *
         */

        if (res == NULL || *res == '\0' || (res[0] == ':' && res[1] == '\0')) {
            /* XXX Why not? */
            krb5_set_error_message(context, KRB5_CC_FORMAT,
                                   N_("\"DIR:\" is not a valid ccache name", ""));
            return KRB5_CC_FORMAT;
        }

#ifdef WIN32
        has_pathsep = strchr(res, '\\') != NULL;
#endif
        has_pathsep |= strchr(res, '/') != NULL;

        if ((dc = calloc(1, sizeof(*dc))) == NULL)
            return krb5_enomem(context);

        p = strrchr(res, ':');
#ifdef WIN32
        is_drive_letter_colon =
            p && ((res[0] == ':' && res[1] != ':' && p - res == 2) ||
                  (res[0] != ':' && p - res == 1));
#endif

        if (res[0] != ':' && p && !is_drive_letter_colon) {
            /* DIR:path:NAME */
            if ((dc->dir = strndup(res, (p - res))) == NULL ||
                asprintf(&dc->sub, "tkt.%s", p + 1) < 0 || dc->sub == NULL) {
                dcc_release(context, dc);
                return krb5_enomem(context);
            }
        } else if (res[0] == ':' && has_pathsep) {
            char *q;

            /* DIR::path/tktNAME (the "tkt" must be there; we'll check) */
            if ((dc->dir = strdup(&res[1])) == NULL) {
                dcc_release(context, dc);
                return krb5_enomem(context);
            }
#ifdef _WIN32
            q = strrchr(dc->dir, '\\');
            if (q == NULL || ((p = strrchr(dc->dir, '/')) && q < p))
#endif
                q = strrchr(dc->dir, '/');
            *q++ = '\0';
            if ((dc->sub = strdup(q)) == NULL) {
                dcc_release(context, dc);
                return krb5_enomem(context);
            }
        } else if (res[0] == ':') {
            /* DIR::NAME -- no path component separators in NAME */
            if ((ret = get_default_dir(context, &dc->dir))) {
                dcc_release(context, dc);
                return ret;
            }
            if (asprintf(&dc->sub, "tkt.%s", res + 1) < 0 || dc->sub == NULL) {
                dcc_release(context, dc);
                return krb5_enomem(context);
            }
        } else {
            /* DIR:path */
            if ((dc->dir = strdup(res)) == NULL) {
                dcc_release(context, dc);
                return krb5_enomem(context);
            }

            if ((ret = get_default_cache(context, dc, NULL, &dc->sub))) {
                dcc_release(context, dc);
                return ret;
            }
        }
    }

    /* Strip off extra slashes on the end */
    for (len = strlen(dc->dir);
         len && ISPATHSEP(dc->dir[len - 1]);
         len--)
        dc->dir[len - 1] = '\0';

    /* If we got here then `dc->dir' and `dc->sub' must both be set */

    if ((ret = verify_directory(context, dc->dir))) {
        dcc_release(context, dc);
        return ret;
    }
    if (!is_filename_cacheish(dc->sub)) {
        krb5_set_error_message(context, KRB5_CC_FORMAT,
                               N_("Name %s is not a cache "
                                  "(doesn't start with tkt)", ""), dc->sub);
        dcc_release(context, dc);
        return KRB5_CC_FORMAT;
    }
    if (asprintf(&dc->name, ":%s/%s", dc->dir, dc->sub) == -1 ||
        dc->name == NULL ||
        asprintf(&filename, "FILE%s", dc->name) == -1 || filename == NULL) {
        dcc_release(context, dc);
        return krb5_enomem(context);
    }

    ret = krb5_cc_resolve(context, filename, &dc->fcache);
    free(filename);
    if (ret) {
	dcc_release(context, dc);
	return ret;
    }

    dc->default_candidate = 1;
    (*id)->data.data = dc;
    (*id)->data.length = sizeof(*dc);
    return 0;
}

static krb5_error_code KRB5_CALLCONV
dcc_gen_new(krb5_context context, krb5_ccache *id)
{
    krb5_error_code ret;
    char *def_dir = NULL;
    char *name = NULL;
    int fd = -1;

    ret = get_default_dir(context, &def_dir);
    if (ret == 0)
        ret = verify_directory(context, def_dir);
    if (ret == 0 &&
        (asprintf(&name, "DIR::%s/tktXXXXXX", def_dir) == -1 || name == NULL))
	ret = krb5_enomem(context);
    if (ret == 0 && (fd = mkstemp(name + sizeof("DIR::") - 1)) == -1)
	ret = errno;
    if (ret == 0)
	ret = dcc_resolve_2(context, id, name + sizeof("DIR:") - 1, NULL);

    free(def_dir);
    free(name);
    if (fd != -1)
        close(fd);
    return ret;
}

static krb5_error_code KRB5_CALLCONV
dcc_initialize(krb5_context context,
	       krb5_ccache id,
	       krb5_principal primary_principal)
{
    krb5_dcache *dc = DCACHE(id);
    return krb5_cc_initialize(context, D2FCACHE(dc), primary_principal);
}

static krb5_error_code KRB5_CALLCONV
dcc_close(krb5_context context,
	  krb5_ccache id)
{
    krb5_dcache *dc = DCACHE(id);
    krb5_principal p = NULL;
    struct stat st;
    char *primary = NULL;

    /*
     * If there's no default cache, but we're closing one, and the one we're
     * closing has been initialized, then make it the default.  This makes the
     * first cache created the default.
     *
     * FIXME We should check if `D2FCACHE(dc)' has live credentials.
     */
    if (dc->default_candidate && D2FCACHE(dc) &&
        krb5_cc_get_principal(context, D2FCACHE(dc), &p) == 0 &&
        (primary = primary_create(dc)) &&
        (stat(primary, &st) == -1 || !S_ISREG(st.st_mode) || st.st_size == 0))
        dcc_set_default(context, id);
    krb5_free_principal(context, p);
    free(primary);
    dcc_release(context, DCACHE(id));
    return 0;
}

static krb5_error_code KRB5_CALLCONV
dcc_destroy(krb5_context context,
	    krb5_ccache id)
{
    krb5_dcache *dc = DCACHE(id);
    krb5_ccache fcache = D2FCACHE(dc);
    dc->fcache = NULL;
    return krb5_cc_destroy(context, fcache);
}

static krb5_error_code KRB5_CALLCONV
dcc_store_cred(krb5_context context,
	       krb5_ccache id,
	       krb5_creds *creds)
{
    krb5_dcache *dc = DCACHE(id);
    return krb5_cc_store_cred(context, D2FCACHE(dc), creds);
}

static krb5_error_code KRB5_CALLCONV
dcc_get_principal(krb5_context context,
		  krb5_ccache id,
		  krb5_principal *principal)
{
    krb5_dcache *dc = DCACHE(id);
    return krb5_cc_get_principal(context, D2FCACHE(dc), principal);
}

static krb5_error_code KRB5_CALLCONV
dcc_get_first (krb5_context context,
	       krb5_ccache id,
	       krb5_cc_cursor *cursor)
{
    krb5_dcache *dc = DCACHE(id);
    return krb5_cc_start_seq_get(context, D2FCACHE(dc), cursor);
}

static krb5_error_code KRB5_CALLCONV
dcc_get_next (krb5_context context,
	      krb5_ccache id,
	      krb5_cc_cursor *cursor,
	      krb5_creds *creds)
{
    krb5_dcache *dc = DCACHE(id);
    return krb5_cc_next_cred(context, D2FCACHE(dc), cursor, creds);
}

static krb5_error_code KRB5_CALLCONV
dcc_end_get (krb5_context context,
	     krb5_ccache id,
	     krb5_cc_cursor *cursor)
{
    krb5_dcache *dc = DCACHE(id);
    return krb5_cc_end_seq_get(context, D2FCACHE(dc), cursor);
}

static krb5_error_code KRB5_CALLCONV
dcc_remove_cred(krb5_context context,
		 krb5_ccache id,
		 krb5_flags which,
		 krb5_creds *cred)
{
    krb5_dcache *dc = DCACHE(id);
    return krb5_cc_remove_cred(context, D2FCACHE(dc), which, cred);
}

static krb5_error_code KRB5_CALLCONV
dcc_set_flags(krb5_context context,
	      krb5_ccache id,
	      krb5_flags flags)
{
    krb5_dcache *dc = DCACHE(id);
    return krb5_cc_set_flags(context, D2FCACHE(dc), flags);
}

static int KRB5_CALLCONV
dcc_get_version(krb5_context context,
		krb5_ccache id)
{
    krb5_dcache *dc = DCACHE(id);
    return krb5_cc_get_version(context, D2FCACHE(dc));
}

struct dcache_iter {
    char *primary;
    krb5_dcache *dc;
    DIR *d;
    unsigned int first:1;
};

static krb5_error_code KRB5_CALLCONV
dcc_get_cache_first(krb5_context context, krb5_cc_cursor *cursor)
{
    struct dcache_iter *iter = NULL;
    const char *name = krb5_cc_default_name(context);
    size_t len;
    char *p;

    *cursor = NULL;

    if (strncmp(name, "DIR:", sizeof("DIR:") - 1) != 0) {
	krb5_set_error_message(context, KRB5_CC_FORMAT,
			       N_("Can't list DIR caches unless its the default type", ""));
	return KRB5_CC_FORMAT;
    }

    if ((iter = calloc(1, sizeof(*iter))) == NULL ||
        (iter->dc = calloc(1, sizeof(iter->dc[0]))) == NULL ||
        (iter->dc->dir = strdup(name + sizeof("DIR:") - 1)) == NULL) {
        if (iter)
            free(iter->dc);
        free(iter);
	return krb5_enomem(context);
    }
    iter->first = 1;
    p = strrchr(iter->dc->dir, ':');
#ifdef WIN32
    if (p == iter->dc->dir + 1)
        p = NULL;
#endif
    if (p)
        *p = '\0';

    /* Strip off extra slashes on the end */
    for (len = strlen(iter->dc->dir);
         len && ISPATHSEP(iter->dc->dir[len - 1]);
         len--) {
        iter->dc->dir[len - 1] = '\0';
    }

    if ((iter->d = opendir(iter->dc->dir)) == NULL) {
	krb5_set_error_message(context, KRB5_CC_FORMAT,
                               N_("Can't open DIR %s: %s", ""),
                               iter->dc->dir, strerror(errno));
        free(iter->dc->dir);
        free(iter->dc);
        free(iter);
	return KRB5_CC_FORMAT;
    }

    *cursor = iter;
    return 0;
}

static krb5_error_code KRB5_CALLCONV
dcc_get_cache_next(krb5_context context, krb5_cc_cursor cursor, krb5_ccache *id)
{
    struct dcache_iter *iter = cursor;
    krb5_error_code ret;
    struct stat st;
    struct dirent *dentry;
    char *p = NULL;

    *id = NULL;
    if (iter == NULL)
        return krb5_einval(context, 2);

    /* Emit primary subsidiary first */
    if (iter->first &&
        get_default_cache(context, iter->dc, NULL, &iter->primary) == 0 &&
        iter->primary && is_filename_cacheish(iter->primary)) {
        iter->first = 0;
        ret = KRB5_CC_END;
        if (asprintf(&p, "FILE:%s/%s", iter->dc->dir, iter->primary) > -1 && p != NULL &&
            stat(p + sizeof("FILE:") - 1, &st) == 0 && S_ISREG(st.st_mode))
            ret = krb5_cc_resolve(context, p, id);
        if (p == NULL)
            return krb5_enomem(context);
        free(p);
        if (ret == 0)
            return ret;
        p = NULL;
    }

    iter->first = 0;
    for (dentry = readdir(iter->d); dentry; dentry = readdir(iter->d)) {
        if (!is_filename_cacheish(dentry->d_name) ||
            (iter->primary && strcmp(dentry->d_name, iter->primary) == 0))
            continue;
        p = NULL;
        ret = KRB5_CC_END;
        if (asprintf(&p, "FILE:%s/%s", iter->dc->dir, dentry->d_name) > -1 &&
            p != NULL &&
            stat(p + sizeof("FILE:") - 1, &st) == 0 && S_ISREG(st.st_mode))
            ret = krb5_cc_resolve(context, p, id);
        free(p);
        if (p == NULL)
            return krb5_enomem(context);
        if (ret == 0)
            return ret;
    }
    return KRB5_CC_END;
}

static krb5_error_code KRB5_CALLCONV
dcc_end_cache_get(krb5_context context, krb5_cc_cursor cursor)
{
    struct dcache_iter *iter = cursor;

    if (iter == NULL)
        return krb5_einval(context, 2);

    (void) closedir(iter->d);
    free(iter->dc->dir);
    free(iter->dc);
    free(iter->primary);
    free(iter);
    return 0;
}

static krb5_error_code KRB5_CALLCONV
dcc_move(krb5_context context, krb5_ccache from, krb5_ccache to)
{
    krb5_dcache *dcfrom = DCACHE(from);
    krb5_dcache *dcto = DCACHE(to);

    dcfrom->default_candidate = 0;
    dcto->default_candidate = 1;
    return krb5_cc_move(context, D2FCACHE(dcfrom), D2FCACHE(dcto));
}

static krb5_error_code KRB5_CALLCONV
dcc_get_default_name(krb5_context context, char **str)
{
    const char *def_cc_colname =
        krb5_config_get_string_default(context, NULL, KRB5_DEFAULT_CCNAME_DIR,
                                       "libdefaults", "default_cc_collection",
                                       NULL);

    /* [libdefaults] default_cc_collection is for testing */
    if (strncmp(def_cc_colname, "DIR:", sizeof("DIR:") - 1) != 0)
        def_cc_colname = KRB5_DEFAULT_CCNAME_DIR;
    return _krb5_expand_default_cc_name(context, def_cc_colname, str);
}

static krb5_error_code KRB5_CALLCONV
dcc_set_default(krb5_context context, krb5_ccache id)
{
    krb5_dcache *dc = DCACHE(id);

    if (dc->sub == NULL)
	return ENOENT;
    return set_default_cache(context, dc, dc->sub);
}

static krb5_error_code KRB5_CALLCONV
dcc_lastchange(krb5_context context, krb5_ccache id, krb5_timestamp *mtime)
{
    krb5_dcache *dc = DCACHE(id);
    return krb5_cc_last_change_time(context, D2FCACHE(dc), mtime);
}

static krb5_error_code KRB5_CALLCONV
dcc_set_kdc_offset(krb5_context context, krb5_ccache id, krb5_deltat kdc_offset)
{
    krb5_dcache *dc = DCACHE(id);
    return krb5_cc_set_kdc_offset(context, D2FCACHE(dc), kdc_offset);
}

static krb5_error_code KRB5_CALLCONV
dcc_get_kdc_offset(krb5_context context, krb5_ccache id, krb5_deltat *kdc_offset)
{
    krb5_dcache *dc = DCACHE(id);
    return krb5_cc_get_kdc_offset(context, D2FCACHE(dc), kdc_offset);
}


/**
 * Variable containing the DIR based credential cache implemention.
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_VARIABLE const krb5_cc_ops krb5_dcc_ops = {
    KRB5_CC_OPS_VERSION_5,
    "DIR",
    NULL,
    NULL,
    dcc_gen_new,
    dcc_initialize,
    dcc_destroy,
    dcc_close,
    dcc_store_cred,
    NULL, /* dcc_retrieve */
    dcc_get_principal,
    dcc_get_first,
    dcc_get_next,
    dcc_end_get,
    dcc_remove_cred,
    dcc_set_flags,
    dcc_get_version,
    dcc_get_cache_first,
    dcc_get_cache_next,
    dcc_end_cache_get,
    dcc_move,
    dcc_get_default_name,
    dcc_set_default,
    dcc_lastchange,
    dcc_set_kdc_offset,
    dcc_get_kdc_offset,
    dcc_get_name_2,
    dcc_resolve_2
};
