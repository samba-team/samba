/*
 * Copyright (c) 1997 - 2017 Kungliga Tekniska Högskolan
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

typedef struct krb5_fcache{
    char *filename;
    char *res;
    char *sub;
    char *tmpfn;
    int version;
}krb5_fcache;

struct fcc_cursor {
    int fd;
    off_t cred_start;
    off_t cred_end;
    krb5_storage *sp;
};

#define KRB5_FCC_FVNO_1 1
#define KRB5_FCC_FVNO_2 2
#define KRB5_FCC_FVNO_3 3
#define KRB5_FCC_FVNO_4 4

#define FCC_TAG_DELTATIME 1

#define FCACHE(X) ((krb5_fcache*)(X)->data.data)

#define FILENAME(X) (FCACHE(X)->filename)
#define TMPFILENAME(X) (FCACHE(X)->tmpfn)
#define RESFILENAME(X) (FCACHE(X)->res)
#define SUBFILENAME(X) (FCACHE(X)->sub)

#define FCC_CURSOR(C) ((struct fcc_cursor*)(C))

static krb5_error_code KRB5_CALLCONV
fcc_get_name_2(krb5_context context,
	       krb5_ccache id,
	       const char **name,
	       const char **colname,
	       const char **sub)
{
    if (FCACHE(id) == NULL)
        return KRB5_CC_NOTFOUND;

    if (name)
        *name = FILENAME(id);
    if (colname)
        *colname = FILENAME(id);
    if (sub)
        *sub = NULL;
    return 0;
}

KRB5_LIB_FUNCTION int KRB5_LIB_CALL
_krb5_xlock(krb5_context context, int fd, krb5_boolean exclusive,
	    const char *filename)
{
    int ret;
#ifdef HAVE_FCNTL
    struct flock l;

    l.l_start = 0;
    l.l_len = 0;
    l.l_type = exclusive ? F_WRLCK : F_RDLCK;
    l.l_whence = SEEK_SET;
    ret = fcntl(fd, F_SETLKW, &l);
#else
    ret = flock(fd, exclusive ? LOCK_EX : LOCK_SH);
#endif
    if(ret < 0)
	ret = errno;
    if(ret == EACCES) /* fcntl can return EACCES instead of EAGAIN */
	ret = EAGAIN;

    switch (ret) {
    case 0:
	break;
    case EINVAL: /* filesystem doesn't support locking, let the user have it */
	ret = 0;
	break;
    case EAGAIN:
	krb5_set_error_message(context, ret,
			       N_("timed out locking cache file %s", "file"),
			       filename);
	break;
    default: {
	char buf[128];
	rk_strerror_r(ret, buf, sizeof(buf));
	krb5_set_error_message(context, ret,
			       N_("error locking cache file %s: %s",
				  "file, error"), filename, buf);
	break;
    }
    }
    return ret;
}

KRB5_LIB_FUNCTION int KRB5_LIB_CALL
_krb5_xunlock(krb5_context context, int fd)
{
    int ret;
#ifdef HAVE_FCNTL
    struct flock l;
    l.l_start = 0;
    l.l_len = 0;
    l.l_type = F_UNLCK;
    l.l_whence = SEEK_SET;
    ret = fcntl(fd, F_SETLKW, &l);
#else
    ret = flock(fd, LOCK_UN);
#endif
    if (ret < 0)
	ret = errno;
    switch (ret) {
    case 0:
	break;
    case EINVAL: /* filesystem doesn't support locking, let the user have it */
	ret = 0;
	break;
    default: {
	char buf[128];
	rk_strerror_r(ret, buf, sizeof(buf));
	krb5_set_error_message(context, ret,
			       N_("Failed to unlock file: %s", ""), buf);
	break;
    }
    }
    return ret;
}

static krb5_error_code
write_storage(krb5_context context, krb5_storage *sp, int fd)
{
    krb5_error_code ret;
    krb5_data data;
    ssize_t sret;

    ret = krb5_storage_to_data(sp, &data);
    if (ret) {
	krb5_set_error_message(context, ret, N_("malloc: out of memory", ""));
	return ret;
    }
    sret = write(fd, data.data, data.length);
    ret = (sret != (ssize_t)data.length);
    krb5_data_free(&data);
    if (ret) {
	ret = errno;
	krb5_set_error_message(context, ret,
			       N_("Failed to write FILE credential data", ""));
	return ret;
    }
    return 0;
}


static krb5_error_code KRB5_CALLCONV
fcc_lock(krb5_context context, krb5_ccache id,
	 int fd, krb5_boolean exclusive)
{
    krb5_error_code ret;
    const char *name;

    if (exclusive == FALSE)
        return 0;
    ret = fcc_get_name_2(context, id, &name, NULL, NULL);
    if (ret == 0)
        ret = _krb5_xlock(context, fd, exclusive, name);
    return ret;
}

static krb5_error_code KRB5_CALLCONV
fcc_get_default_name(krb5_context, char **);

/*
 * This is the character used to separate the residual from the subsidiary name
 * when both are given.  It's tempting to use ':' just as we do in the ccache
 * names, but we can't on Windows.
 */
#define FILESUBSEP "+"
#define FILESUBSEPCHR ((FILESUBSEP)[0])

static krb5_error_code KRB5_CALLCONV
fcc_resolve_2(krb5_context context,
	      krb5_ccache *id,
	      const char *res,
	      const char *sub)
{
    krb5_fcache *f;
    char *freeme = NULL;

    if (res == NULL && sub == NULL)
        return krb5_einval(context, 3);
    if (res == NULL) {
        krb5_error_code ret;

        if ((ret = fcc_get_default_name(context, &freeme)))
            return ret;
        res = freeme + sizeof("FILE:") - 1;
    } else if (!sub && (sub = strchr(res, FILESUBSEPCHR))) {
        if (sub[1] == '\0') {
            sub = NULL;
        } else {
            /* `res' has a subsidiary component, so split on it */
            if ((freeme = strndup(res, sub - res)) == NULL)
                return krb5_enomem(context);
            res = freeme;
            sub++;
        }
    }

    if ((f = calloc(1, sizeof(*f))) == NULL ||
        (f->res = strdup(res)) == NULL ||
        (f->sub = sub ? strdup(sub) : NULL) == (sub ? NULL : "") ||
        asprintf(&f->filename, "%s%s%s",
                 res, sub ? FILESUBSEP : "", sub ? sub : "") == -1 ||
        f->filename == NULL) {
        if (f) {
            free(f->filename);
            free(f->res);
            free(f->sub);
        }
        free(f);
        free(freeme);
        return krb5_enomem(context);
    }
    f->tmpfn = NULL;
    f->version = 0;
    (*id)->data.data = f;
    (*id)->data.length = sizeof(*f);

    free(freeme);
    return 0;
}

/*
 * Try to scrub the contents of `filename' safely.
 */

static int
scrub_file (int fd)
{
    off_t pos;
    char buf[128];

    pos = lseek(fd, 0, SEEK_END);
    if (pos < 0)
        return errno;
    if (lseek(fd, 0, SEEK_SET) < 0)
        return errno;
    memset(buf, 0, sizeof(buf));
    while(pos > 0) {
	ssize_t tmp;
	size_t wr = sizeof(buf);
	if (wr > pos)
	    wr = (size_t)pos;
        tmp = write(fd, buf, wr);

	if (tmp < 0)
	    return errno;
	pos -= tmp;
    }
#ifdef _MSC_VER
    _commit (fd);
#else
    fsync (fd);
#endif
    return 0;
}

/*
 * Erase `filename' if it exists, trying to remove the contents if
 * it's `safe'.  We always try to remove the file, it it exists.  It's
 * only overwritten if it's a regular file (not a symlink and not a
 * hardlink)
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_erase_file(krb5_context context, const char *filename)
{
    int fd;
    struct stat sb1, sb2;
    int ret;

    ret = lstat (filename, &sb1);
    if (ret < 0) {
	if(errno == ENOENT)
	    return 0;
	else
	    return errno;
    }

    fd = open(filename, O_RDWR | O_BINARY | O_CLOEXEC | O_NOFOLLOW);
    if(fd < 0) {
	if(errno == ENOENT)
	    return 0;
	else
	    return errno;
    }
    rk_cloexec(fd);
    ret = _krb5_xlock(context, fd, 1, filename);
    if (ret) {
	close(fd);
	return ret;
    }
    if (unlink(filename) < 0) {
	ret = errno;
        close (fd);
	krb5_set_error_message(context, errno,
	    N_("krb5_cc_destroy: unlinking \"%s\": %s", ""),
	    filename, strerror(ret));
        return ret;
    }
    ret = fstat(fd, &sb2);
    if (ret < 0) {
	ret = errno;
	close (fd);
	return ret;
    }

    /* check if someone was playing with symlinks */

    if (sb1.st_dev != sb2.st_dev || sb1.st_ino != sb2.st_ino) {
	close(fd);
	return EPERM;
    }

    /* there are still hard links to this file */

    if (sb2.st_nlink != 0) {
        close(fd);
        return 0;
    }

    ret = scrub_file(fd);
    close(fd);
    return ret;
}

static krb5_error_code KRB5_CALLCONV
fcc_gen_new(krb5_context context, krb5_ccache *id)
{
    char *file = NULL, *exp_file = NULL;
    krb5_error_code ret;
    krb5_fcache *f;
    int fd;

    f = calloc(1, sizeof(*f));
    if(f == NULL) {
	krb5_set_error_message(context, KRB5_CC_NOMEM,
			       N_("malloc: out of memory", ""));
	return KRB5_CC_NOMEM;
    }
    f->tmpfn = NULL;
    /*
     * XXX We should asprintf(&file, "%s:XXXXXX", KRB5_DEFAULT_CCNAME_FILE)
     * instead so that new unique FILE ccaches can be found in the user's
     * default collection.
     * */
    ret = asprintf(&file, "%sXXXXXX", KRB5_DEFAULT_CCFILE_ROOT);
    if(ret < 0 || file == NULL) {
	free(f);
	krb5_set_error_message(context, KRB5_CC_NOMEM,
			       N_("malloc: out of memory", ""));
	return KRB5_CC_NOMEM;
    }
    ret = _krb5_expand_path_tokens(context, file, 1, &exp_file);
    free(file);
    if (ret) {
	free(f);
	return ret;
    }

    file = exp_file;

    fd = mkostemp(exp_file, O_CLOEXEC);
    if(fd < 0) {
	ret = (krb5_error_code)errno;
	krb5_set_error_message(context, ret, N_("mkstemp %s failed", ""), exp_file);
	free(f);
	free(exp_file);
	return ret;
    }
    close(fd);
    f->filename = exp_file;
    f->res = strdup(exp_file); /* XXX See above commentary about collection */
    f->sub = NULL;
    f->version = 0;
    (*id)->data.data = f;
    (*id)->data.length = sizeof(*f);
    return 0;
}

static void
storage_set_flags(krb5_context context, krb5_storage *sp, int vno)
{
    int flags = 0;
    switch(vno) {
    case KRB5_FCC_FVNO_1:
	flags |= KRB5_STORAGE_PRINCIPAL_WRONG_NUM_COMPONENTS;
	flags |= KRB5_STORAGE_PRINCIPAL_NO_NAME_TYPE;
	flags |= KRB5_STORAGE_HOST_BYTEORDER;
	break;
    case KRB5_FCC_FVNO_2:
	flags |= KRB5_STORAGE_HOST_BYTEORDER;
	break;
    case KRB5_FCC_FVNO_3:
	flags |= KRB5_STORAGE_KEYBLOCK_KEYTYPE_TWICE;
	break;
    case KRB5_FCC_FVNO_4:
	break;
    default:
	krb5_abortx(context,
		    "storage_set_flags called with bad vno (%x)", vno);
    }
    krb5_storage_set_flags(sp, flags);
}

static krb5_error_code KRB5_CALLCONV
fcc_open(krb5_context context,
	 krb5_ccache id,
	 const char *operation,
	 int *fd_ret,
	 int flags,
	 mode_t mode)
{
    krb5_boolean exclusive = ((flags | O_WRONLY) == flags ||
			      (flags | O_RDWR) == flags);
    krb5_error_code ret;
    const char *filename;
    struct stat sb1, sb2;
#ifndef _WIN32
    struct stat sb3;
    size_t tries = 3;
#endif
    int strict_checking;
    int fd;

    flags |= O_BINARY | O_CLOEXEC | O_NOFOLLOW;

    *fd_ret = -1;

    if (FCACHE(id) == NULL)
        return krb5_einval(context, 2);

    if ((flags & O_EXCL)) {
        /*
         * FIXME Instead of mkostemp()... we could instead try to use a .new
         * file... with care.  Or the O_TMPFILE / linkat() extensions.  We need
         * a roken / heimbase abstraction for that.
         */
        if (TMPFILENAME(id))
            (void) unlink(TMPFILENAME(id));
        free(TMPFILENAME(id));
        TMPFILENAME(id) = NULL;
        if (asprintf(&TMPFILENAME(id), "%s-XXXXXX", FILENAME(id)) < 0 ||
            TMPFILENAME(id) == NULL)
            return krb5_enomem(context);
        if ((fd = mkostemp(TMPFILENAME(id), O_CLOEXEC)) == -1) {
            krb5_set_error_message(context, ret = errno,
                                   N_("Could not make temp ccache FILE:%s", ""),
                                   TMPFILENAME(id));
            free(TMPFILENAME(id));
            TMPFILENAME(id) = NULL;
            return ret;
        }
        goto out;
    }

    filename = TMPFILENAME(id) ? TMPFILENAME(id) : FILENAME(id);
    strict_checking = (flags & O_CREAT) == 0 &&
	(context->flags & KRB5_CTX_F_FCACHE_STRICT_CHECKING) != 0;

#ifndef WIN32
again:
#endif
    memset(&sb1, 0, sizeof(sb1));
    ret = lstat(filename, &sb1);
    if (ret == 0) {
	if (!S_ISREG(sb1.st_mode)) {
	    krb5_set_error_message(context, EPERM,
				   N_("Refuses to open symlinks for caches FILE:%s", ""), filename);
	    return EPERM;
	}
    } else if (errno != ENOENT || !(flags & O_CREAT)) {
	krb5_set_error_message(context, errno, N_("%s lstat(%s)", "file, error"),
			       operation, filename);
	return errno;
    }

    fd = open(filename, flags, mode);
    if(fd < 0) {
	char buf[128];
	ret = errno;
	rk_strerror_r(ret, buf, sizeof(buf));
	krb5_set_error_message(context, ret, N_("%s open(%s): %s", "file, error"),
			       operation, filename, buf);
	return ret;
    }
    rk_cloexec(fd);

    ret = fstat(fd, &sb2);
    if (ret < 0) {
	krb5_clear_error_message(context);
	close(fd);
	return errno;
    }

    if (!S_ISREG(sb2.st_mode)) {
	krb5_set_error_message(context, EPERM, N_("Refuses to open non files caches: FILE:%s", ""), filename);
	close(fd);
	return EPERM;
    }

#ifndef _WIN32
    if (sb1.st_dev && sb1.st_ino &&
	(sb1.st_dev != sb2.st_dev || sb1.st_ino != sb2.st_ino)) {
	/*
	 * Perhaps we raced with a rename().  To complain about
	 * symlinks in that case would cause unnecessary concern, so
	 * we check for that possibility and loop.  This has no
	 * TOCTOU problems because we redo the open().  We could also
	 * not do any of this checking if O_NOFOLLOW != 0...
	 */
	close(fd);
	ret = lstat(filename, &sb3);
	if (ret || sb1.st_dev != sb2.st_dev ||
	    sb3.st_dev != sb2.st_dev || sb3.st_ino != sb2.st_ino) {
	    krb5_set_error_message(context, EPERM, N_("Refuses to open possible symlink for caches: FILE:%s", ""), filename);
	    return EPERM;
	}
	if (--tries == 0) {
	    krb5_set_error_message(context, EPERM, N_("Raced too many times with renames of FILE:%s", ""), filename);
	    return EPERM;
	}
	goto again;
    }
#endif

    /*
     * /tmp (or wherever default ccaches go) might not be on its own
     * filesystem, or on a filesystem different /etc, say, and even if
     * it were, suppose a user hard-links another's ccache to her
     * default ccache, then runs a set-uid program that will user her
     * default ccache (even if it ignores KRB5CCNAME)...
     *
     * Default ccache locations should really be on per-user non-tmp
     * locations on tmpfs "run" directories.  But we don't know here
     * that this is the case.  Thus: no hard-links, no symlinks.
     */
    if (sb2.st_nlink > 1) {
	krb5_set_error_message(context, EPERM, N_("Refuses to open hardlinks for caches FILE:%s", ""), filename);
	close(fd);
	return EPERM;
    }

    if (strict_checking) {
#ifndef _WIN32
	/*
	 * XXX WIN32: Needs to have ACL checking code!
	 * st_mode comes out as 100666, and st_uid is no use.
	 */
	/*
	 * XXX Should probably add options to improve control over this
	 * check.  We might want strict checking of everything except
	 * this.
	 */
	if (sb2.st_uid != geteuid()) {
	    krb5_set_error_message(context, EPERM, N_("Refuses to open cache files not own by myself FILE:%s (owned by %d)", ""), filename, (int)sb2.st_uid);
	    close(fd);
	    return EPERM;
	}
	if ((sb2.st_mode & 077) != 0) {
	    krb5_set_error_message(context, EPERM,
				   N_("Refuses to open group/other readable files FILE:%s", ""), filename);
	    close(fd);
	    return EPERM;
	}
#endif
    }

out:
    if((ret = fcc_lock(context, id, fd, exclusive)) != 0) {
	close(fd);
	return ret;
    }
    *fd_ret = fd;
    return 0;
}

static krb5_error_code KRB5_CALLCONV
fcc_initialize(krb5_context context,
	       krb5_ccache id,
	       krb5_principal primary_principal)
{
    krb5_fcache *f = FCACHE(id);
    int ret = 0;
    int fd;

    if (f == NULL)
        return krb5_einval(context, 2);

    /*
     * fcc_open() will notice the O_EXCL and will make a temporary file that
     * will later be renamed into place.
     */
    ret = fcc_open(context, id, "initialize", &fd, O_RDWR | O_CREAT | O_EXCL, 0600);
    if(ret)
	return ret;
    {
	krb5_storage *sp;
	sp = krb5_storage_emem();
	if (sp == NULL)
	    return krb5_enomem(context);
	krb5_storage_set_eof_code(sp, KRB5_CC_END);
	if(context->fcache_vno != 0)
	    f->version = context->fcache_vno;
	else
	    f->version = KRB5_FCC_FVNO_4;
        if (ret == 0)
            ret = krb5_store_int8(sp, 5);
        if (ret == 0)
            ret = krb5_store_int8(sp, f->version);
	storage_set_flags(context, sp, f->version);
	if(f->version == KRB5_FCC_FVNO_4 && ret == 0) {
	    /* V4 stuff */
	    if (context->kdc_sec_offset) {
                if (ret == 0)
                    ret = krb5_store_int16 (sp, 12); /* length */
                if (ret == 0)
                    ret = krb5_store_int16 (sp, FCC_TAG_DELTATIME); /* Tag */
                if (ret == 0)
                    ret = krb5_store_int16 (sp, 8); /* length of data */
                if (ret == 0)
                    ret = krb5_store_int32 (sp, context->kdc_sec_offset);
                if (ret == 0)
                    ret = krb5_store_int32 (sp, context->kdc_usec_offset);
	    } else {
                if (ret == 0)
                    ret = krb5_store_int16 (sp, 0);
	    }
	}
        if (ret == 0)
            ret = krb5_store_principal(sp, primary_principal);

        if (ret == 0)
            ret = write_storage(context, sp, fd);

	krb5_storage_free(sp);
    }
    if (close(fd) < 0)
	if (ret == 0) {
	    char buf[128];
	    ret = errno;
	    rk_strerror_r(ret, buf, sizeof(buf));
	    krb5_set_error_message(context, ret, N_("close %s: %s", ""),
				   FILENAME(id), buf);
	}
    return ret;
}

static krb5_error_code KRB5_CALLCONV
fcc_close(krb5_context context,
	  krb5_ccache id)
{
    if (FCACHE(id) == NULL)
        return krb5_einval(context, 2);

    if (TMPFILENAME(id))
        (void) unlink(TMPFILENAME(id));
    free(TMPFILENAME(id));
    free(RESFILENAME(id));
    free(SUBFILENAME(id));
    free(FILENAME(id));
    krb5_data_free(&id->data);
    return 0;
}

static krb5_error_code KRB5_CALLCONV
fcc_destroy(krb5_context context,
	    krb5_ccache id)
{
    if (FCACHE(id) == NULL)
        return krb5_einval(context, 2);

    if (TMPFILENAME(id))
        (void) _krb5_erase_file(context, TMPFILENAME(id));
    return _krb5_erase_file(context, FILENAME(id));
}

static krb5_error_code KRB5_CALLCONV
fcc_store_cred(krb5_context context,
	       krb5_ccache id,
	       krb5_creds *creds)
{
    int ret;
    int fd;

    ret = fcc_open(context, id, "store", &fd, O_WRONLY | O_APPEND, 0);
    if(ret)
	return ret;
    {
	krb5_storage *sp;

	sp = krb5_storage_emem();
	if (sp == NULL)
	    return krb5_enomem(context);
	krb5_storage_set_eof_code(sp, KRB5_CC_END);
	storage_set_flags(context, sp, FCACHE(id)->version);
	ret = krb5_store_creds(sp, creds);
	if (ret == 0)
	    ret = write_storage(context, sp, fd);
	krb5_storage_free(sp);
    }
    if (close(fd) < 0) {
	if (ret == 0) {
	    char buf[128];
	    ret = errno;
	    rk_strerror_r(ret, buf, sizeof(buf));
	    krb5_set_error_message(context, ret, N_("close %s: %s", ""),
				   FILENAME(id), buf);
	}
    }
    if (ret == 0 && TMPFILENAME(id) &&
        !krb5_is_config_principal(context, creds->server)) {

        /*
         * Portability note: there's no need to have WIN32 or other code here
         * for odd rename cases because rk_rename() is meant to handle that.
         */
        ret = rk_rename(TMPFILENAME(id), FILENAME(id));
        if (ret == 0) {
            free(TMPFILENAME(id));
            TMPFILENAME(id) = NULL;
        } else {
            ret = errno;
        }
    }
    return ret;
}

static krb5_error_code
init_fcc(krb5_context context,
	 krb5_ccache id,
	 const char *operation,
	 krb5_storage **ret_sp,
	 int *ret_fd,
	 krb5_deltat *kdc_offset)
{
    int fd;
    int8_t pvno, tag;
    krb5_storage *sp;
    krb5_error_code ret;

    *ret_fd = -1;
    *ret_sp = NULL;
    if (kdc_offset)
	*kdc_offset = 0;

    ret = fcc_open(context, id, operation, &fd, O_RDONLY, 0);
    if(ret)
	return ret;

    sp = krb5_storage_stdio_from_fd(fd, "r");
    if(sp == NULL) {
	krb5_clear_error_message(context);
	ret = ENOMEM;
	goto out;
    }
    krb5_storage_set_eof_code(sp, KRB5_CC_END);
    ret = krb5_ret_int8(sp, &pvno);
    if (ret != 0) {
	if(ret == KRB5_CC_END) {
	    ret = ENOENT;
	    krb5_set_error_message(context, ret,
				   N_("Empty credential cache file: %s", ""),
				   FILENAME(id));
	} else
	    krb5_set_error_message(context, ret, N_("Error reading pvno "
						    "in cache file: %s", ""),
				   FILENAME(id));
	goto out;
    }
    if (pvno != 5) {
	ret = KRB5_CCACHE_BADVNO;
	krb5_set_error_message(context, ret, N_("Bad version number in credential "
						"cache file: %s", ""),
			       FILENAME(id));
	goto out;
    }
    ret = krb5_ret_int8(sp, &tag); /* should not be host byte order */
    if (ret != 0) {
	ret = KRB5_CC_FORMAT;
	krb5_set_error_message(context, ret, "Error reading tag in "
			      "cache file: %s", FILENAME(id));
	goto out;
    }
    FCACHE(id)->version = tag;
    storage_set_flags(context, sp, FCACHE(id)->version);
    switch (tag) {
    case KRB5_FCC_FVNO_4: {
	int16_t length;

	ret = krb5_ret_int16 (sp, &length);
	if(ret) {
	    ret = KRB5_CC_FORMAT;
	    krb5_set_error_message(context, ret,
				   N_("Error reading tag length in "
				      "cache file: %s", ""), FILENAME(id));
	    goto out;
	}
	while(length > 0) {
	    int16_t dtag, data_len;
	    int i;
	    int8_t dummy;

	    ret = krb5_ret_int16 (sp, &dtag);
	    if(ret) {
		ret = KRB5_CC_FORMAT;
		krb5_set_error_message(context, ret, N_("Error reading dtag in "
							"cache file: %s", ""),
				       FILENAME(id));
		goto out;
	    }
	    ret = krb5_ret_int16 (sp, &data_len);
	    if(ret) {
		ret = KRB5_CC_FORMAT;
		krb5_set_error_message(context, ret,
				       N_("Error reading dlength "
					  "in cache file: %s",""),
				       FILENAME(id));
		goto out;
	    }
	    switch (dtag) {
	    case FCC_TAG_DELTATIME : {
		int32_t offset;

		ret = krb5_ret_int32 (sp, &offset);
		ret |= krb5_ret_int32 (sp, &context->kdc_usec_offset);
		if(ret) {
		    ret = KRB5_CC_FORMAT;
		    krb5_set_error_message(context, ret,
					   N_("Error reading kdc_sec in "
					      "cache file: %s", ""),
					   FILENAME(id));
		    goto out;
		}
		context->kdc_sec_offset = offset;
		if (kdc_offset)
		    *kdc_offset = offset;
		break;
	    }
	    default :
		for (i = 0; i < data_len; ++i) {
		    ret = krb5_ret_int8 (sp, &dummy);
		    if(ret) {
			ret = KRB5_CC_FORMAT;
			krb5_set_error_message(context, ret,
					       N_("Error reading unknown "
						  "tag in cache file: %s", ""),
					       FILENAME(id));
			goto out;
		    }
		}
		break;
	    }
	    length -= 4 + data_len;
	}
	break;
    }
    case KRB5_FCC_FVNO_3:
    case KRB5_FCC_FVNO_2:
    case KRB5_FCC_FVNO_1:
	break;
    default :
	ret = KRB5_CCACHE_BADVNO;
	krb5_set_error_message(context, ret,
			       N_("Unknown version number (%d) in "
				  "credential cache file: %s", ""),
			       (int)tag, FILENAME(id));
	goto out;
    }
    *ret_sp = sp;
    *ret_fd = fd;

    return 0;
  out:
    if(sp != NULL)
	krb5_storage_free(sp);
    close(fd);
    return ret;
}

static krb5_error_code KRB5_CALLCONV
fcc_get_principal(krb5_context context,
		  krb5_ccache id,
		  krb5_principal *principal)
{
    krb5_error_code ret;
    int fd;
    krb5_storage *sp;

    ret = init_fcc (context, id, "get-principal", &sp, &fd, NULL);
    if (ret)
	return ret;
    ret = krb5_ret_principal(sp, principal);
    if (ret)
	krb5_clear_error_message(context);
    krb5_storage_free(sp);
    close(fd);
    return ret;
}

static krb5_error_code KRB5_CALLCONV
fcc_end_get(krb5_context context,
	    krb5_ccache id,
	    krb5_cc_cursor *cursor);

static krb5_error_code KRB5_CALLCONV
fcc_get_first(krb5_context context,
	      krb5_ccache id,
	      krb5_cc_cursor *cursor)
{
    krb5_error_code ret;
    krb5_principal principal;

    if (FCACHE(id) == NULL)
        return krb5_einval(context, 2);

    *cursor = calloc(1, sizeof(struct fcc_cursor));
    if (*cursor == NULL) {
        krb5_set_error_message(context, ENOMEM, N_("malloc: out of memory", ""));
	return ENOMEM;
    }

    ret = init_fcc(context, id, "get-first", &FCC_CURSOR(*cursor)->sp,
		   &FCC_CURSOR(*cursor)->fd, NULL);
    if (ret) {
	free(*cursor);
	*cursor = NULL;
	return ret;
    }
    ret = krb5_ret_principal (FCC_CURSOR(*cursor)->sp, &principal);
    if(ret) {
	krb5_clear_error_message(context);
	fcc_end_get(context, id, cursor);
	return ret;
    }
    krb5_free_principal (context, principal);
    return 0;
}

/*
 * Return true if cred is a removed entry.  We assume that any active entry
 * with endtime=0 (such as a config entry or gssproxy encrypted credential)
 * will also have authtime=0.
 */
static inline krb5_boolean
cred_removed(krb5_creds *c)
{
    return c->times.endtime == 0 && c->times.authtime != 0;
}

static krb5_error_code KRB5_CALLCONV
fcc_get_next (krb5_context context,
	      krb5_ccache id,
	      krb5_cc_cursor *cursor,
	      krb5_creds *creds)
{
    krb5_error_code ret;

    if (FCACHE(id) == NULL)
        return krb5_einval(context, 2);

    if (FCC_CURSOR(*cursor) == NULL)
        return krb5_einval(context, 3);

    while (1) {
	FCC_CURSOR(*cursor)->cred_start =
	    krb5_storage_seek(FCC_CURSOR(*cursor)->sp, 0, SEEK_CUR);

	ret = krb5_ret_creds(FCC_CURSOR(*cursor)->sp, creds);

	FCC_CURSOR(*cursor)->cred_end =
	    krb5_storage_seek(FCC_CURSOR(*cursor)->sp, 0, SEEK_CUR);

	if (ret) {
	    krb5_clear_error_message(context);
	    break;
	}

	if (!cred_removed(creds))
	    break;

	krb5_free_cred_contents(context, creds);
    }

    return ret;
}

static krb5_error_code KRB5_CALLCONV
fcc_end_get (krb5_context context,
	     krb5_ccache id,
	     krb5_cc_cursor *cursor)
{

    if (FCACHE(id) == NULL)
        return krb5_einval(context, 2);

    if (FCC_CURSOR(*cursor) == NULL)
        return krb5_einval(context, 3);

    krb5_storage_free(FCC_CURSOR(*cursor)->sp);
    close (FCC_CURSOR(*cursor)->fd);
    free(*cursor);
    *cursor = NULL;
    return 0;
}

static void KRB5_CALLCONV
cred_delete(krb5_context context,
	    krb5_ccache id,
	    krb5_cc_cursor *cursor,
	    krb5_creds *cred)
{
    krb5_error_code ret;
    krb5_storage *sp;
    krb5_data orig_cred_data;
    unsigned char *cred_data_in_file = NULL;
    off_t new_cred_sz;
    struct stat sb1, sb2;
    int fd = -1;
    ssize_t bytes;
    krb5_const_realm srealm = krb5_principal_get_realm(context, cred->server);

    /* This is best-effort code; if we lose track of errors here it's OK */

    heim_assert(FCC_CURSOR(*cursor)->cred_start < FCC_CURSOR(*cursor)->cred_end,
		"fcache internal error");

    krb5_data_zero(&orig_cred_data);

    sp = krb5_storage_emem();
    if (sp == NULL)
	return;
    krb5_storage_set_eof_code(sp, KRB5_CC_END);
    storage_set_flags(context, sp, FCACHE(id)->version);

    /* Get a copy of what the cred should look like in the file; see below */
    ret = krb5_store_creds(sp, cred);
    if (ret)
	goto out;

    ret = krb5_storage_to_data(sp, &orig_cred_data);
    if (ret)
	goto out;
    krb5_storage_free(sp);

    cred_data_in_file = malloc(orig_cred_data.length);
    if (cred_data_in_file == NULL)
	goto out;

    /*
     * Mark the cred expired; krb5_cc_retrieve_cred() callers should use
     * KRB5_TC_MATCH_TIMES, so this should be good enough...
     */
    cred->times.endtime = 0;

    /* For compatibility with MIT d3b39a8bac6206b5ea78b0bf6a2958c1df0b0dd5 */
    cred->times.authtime = -1;

    /* ...except for config creds because we don't check their endtimes */
    if (srealm && strcmp(srealm, "X-CACHECONF:") == 0) {
	ret = krb5_principal_set_realm(context, cred->server, "X-RMED-CONF:");
	if (ret)
	    goto out;
    }

    sp = krb5_storage_emem();
    if (sp == NULL)
	goto out;
    krb5_storage_set_eof_code(sp, KRB5_CC_END);
    storage_set_flags(context, sp, FCACHE(id)->version);

    ret = krb5_store_creds(sp, cred);

    /* The new cred must be the same size as the old cred */
    new_cred_sz = krb5_storage_seek(sp, 0, SEEK_END);
    if (new_cred_sz != orig_cred_data.length || new_cred_sz !=
	(FCC_CURSOR(*cursor)->cred_end - FCC_CURSOR(*cursor)->cred_start)) {
	/* XXX This really can't happen.  Assert like above? */
	krb5_set_error_message(context, EINVAL,
			       N_("Credential deletion failed on ccache "
				  "FILE:%s: new credential size did not "
				  "match old credential size", ""),
			       FILENAME(id));
	goto out;
    }

    ret = fcc_open(context, id, "remove_cred", &fd, O_RDWR, 0);
    if (ret)
	goto out;

    /*
     * Check that we're updating the same file where we got the
     * cred's offset, else we'd be corrupting a new ccache.
     */
    if (fstat(FCC_CURSOR(*cursor)->fd, &sb1) == -1 ||
	fstat(fd, &sb2) == -1)
	goto out;
    if (sb1.st_dev != sb2.st_dev || sb1.st_ino != sb2.st_ino)
	goto out;

    /*
     * Make sure what we overwrite is what we expected.
     *
     * FIXME: We *really* need the ccache v4 tag for ccache ID.  This
     * check that we're only overwriting something that looks exactly
     * like what we want to is probably good enough in practice, but
     * it's not guaranteed to work.
     */
    if (lseek(fd, FCC_CURSOR(*cursor)->cred_start, SEEK_SET) == (off_t)-1)
	goto out;
    bytes = read(fd, cred_data_in_file, orig_cred_data.length);
    if (bytes != orig_cred_data.length)
	goto out;
    if (memcmp(orig_cred_data.data, cred_data_in_file, bytes) != 0)
	goto out;
    if (lseek(fd, FCC_CURSOR(*cursor)->cred_start, SEEK_SET) == (off_t)-1)
	goto out;
    ret = write_storage(context, sp, fd);
out:
    if (fd > -1) {
	if (close(fd) < 0 && ret == 0) {
	    krb5_set_error_message(context, errno, N_("close %s", ""),
				   FILENAME(id));
	}
    }
    krb5_data_free(&orig_cred_data);
    free(cred_data_in_file);
    krb5_storage_free(sp);
    return;
}

static krb5_error_code KRB5_CALLCONV
fcc_remove_cred(krb5_context context,
		krb5_ccache id,
		krb5_flags which,
		krb5_creds *mcred)
{
    krb5_error_code ret, ret2;
    krb5_cc_cursor cursor;
    krb5_creds found_cred;

    if (FCACHE(id) == NULL)
	return krb5_einval(context, 2);

    ret = krb5_cc_start_seq_get(context, id, &cursor);
    if (ret)
	return ret;
    while ((ret = krb5_cc_next_cred(context, id, &cursor, &found_cred)) == 0) {
	if (!krb5_compare_creds(context, which, mcred, &found_cred)) {
            krb5_free_cred_contents(context, &found_cred);
	    continue;
        }
	cred_delete(context, id, &cursor, &found_cred);
	krb5_free_cred_contents(context, &found_cred);
    }
    ret2 = krb5_cc_end_seq_get(context, id, &cursor);
    if (ret2)	/* not expected to fail */
	return ret2;
    if (ret == KRB5_CC_END)
	return 0;
    return ret;
}

static krb5_error_code KRB5_CALLCONV
fcc_set_flags(krb5_context context,
	      krb5_ccache id,
	      krb5_flags flags)
{
    if (FCACHE(id) == NULL)
        return krb5_einval(context, 2);

    return 0; /* XXX */
}

static int KRB5_CALLCONV
fcc_get_version(krb5_context context,
		krb5_ccache id)
{
    if (FCACHE(id) == NULL)
        return -1;

    return FCACHE(id)->version;
}

static const char *
my_basename(const char *fn)
{
    const char *base, *p;

    if (strncmp(fn, "FILE:", sizeof("FILE:") - 1) == 0)
        fn += sizeof("FILE:") - 1;
    for (p = base = fn; *p; p++) {
#ifdef WIN32
        if (*p == '/' || *p == '\\')
            base = p + 1;
#else
        if (*p == '/')
            base = p + 1;
#endif
    }
    return base;
}

/* We could use an rk_dirname()... */
static char *
my_dirname(const char *fn)
{
    size_t len, i;
    char *dname;

    if (strncmp(fn, "FILE:", sizeof("FILE:") - 1) == 0)
        fn += sizeof("FILE:") - 1;

    if ((dname = strdup(fn)) == NULL)
        return NULL;
    len = strlen(dname);
    for (i = 0; i < len; i++) {
#ifdef WIN32
        if (dname[len - i] == '\\' ||
            dname[len - i] == '/') {
            dname[len - i] = '\0';
            break;
        }
#else
        if (dname[len - i] == '/') {
            dname[len - i] = '\0';
            break;
        }
#endif
    }
    if (i < len)
        return dname;
    free(dname);
    return strdup(".");
}

/*
 * This checks that a directory entry matches a required basename and has a
 * non-empty subsidiary component.
 */
static int
matchbase(const char *fn, const char *base, size_t baselen)
{
    return strncmp(fn, base, baselen) == 0 &&
        (fn[baselen] == FILESUBSEPCHR && fn[baselen + 1] != '\0');
}

/*
 * Check if `def_locs' contains `name' (which must be the default ccache name),
 * in which case the caller may look for subsidiaries of all of `def_locs'.
 *
 * This is needed because the collection iterators don't take a base location
 * as an argument, so we can only search default locations, but only if the
 * current default ccache name is indeed a default (as opposed to from
 * KRB5CCNAME being set in the environment pointing to a non-default name).
 */
static krb5_error_code
is_default_collection(krb5_context context, const char *name,
                      const char * const *def_locs, int *res)
{
    krb5_error_code ret;
    const char *def_loc[2] = { KRB5_DEFAULT_CCNAME_FILE, NULL };
    const char *sep;
    size_t namelen;
    size_t i;

    *res = 0;
    if (name == NULL) {
        *res = 1;
        return 0;
    }
    if ((sep = strchr(name, FILESUBSEPCHR)))
        namelen = (size_t)(sep - name);
    else
        namelen = strlen(name);
    if (def_locs == NULL)
        def_locs = def_loc;
    for (i = 0; !(*res) && def_locs[i]; i++) {
        char *e = NULL;

        if ((ret = _krb5_expand_default_cc_name(context, def_locs[i], &e)))
            return ret;
        *res = strncmp(e, name, namelen) == 0 &&
        (sep == NULL || e[namelen] == FILESUBSEPCHR || e[namelen] == '\0');
        free(e);
    }
    return 0;
}

/*
 * Collection iterator cursor.
 *
 * There may be an array of locations, and for each location we'll try
 * resolving it, as well as doing a readdir() of the dirname of it and output
 * all ccache names in that directory that begin with the current location and
 * end in "+${subsidiary}".
 */
struct fcache_iter {
    const char *curr_location;
    char *def_ccname;   /* The default ccname */
    char **locations;   /* All the other places we'll look for a ccache */
    char *dname;        /* dirname() of curr_location */
    DIR *d;
    struct dirent *dentry;
    int location;       /* Index of `locations' */
    unsigned int first:1;
    unsigned int dead:1;
};

/* Initiate FILE collection iteration */
static krb5_error_code KRB5_CALLCONV
fcc_get_cache_first(krb5_context context, krb5_cc_cursor *cursor)
{
    struct fcache_iter *iter = NULL;
    krb5_error_code ret;
    const char *def_ccname = NULL;
    char **def_locs = NULL;
    int is_def_coll = 0;

    if (krb5_config_get_bool_default(context, NULL, FALSE, "libdefaults",
                                     "enable_file_cache_iteration", NULL)) {
        def_ccname = krb5_cc_default_name(context);
        def_locs = krb5_config_get_strings(context, NULL, "libdefaults",
                                           "default_file_cache_collections",
                                           NULL);
    }

    /*
     * Note: do not allow krb5_cc_default_name() to recurse via
     * krb5_cc_cache_match().
     * Note that context->default_cc_name will be NULL even though
     * KRB5CCNAME is set in the environment if neither krb5_cc_default_name()
     * nor krb5_cc_set_default_name() have been called.
     */

    /*
     * Figure out if the current default ccache name is a really a default one
     * so we know whether to search any other default FILE collection
     * locations.
     */
    if ((ret = is_default_collection(context, def_ccname,
                                     (const char **)def_locs,
                                     &is_def_coll)))
        goto out;

    /* Setup the cursor */
    if ((iter = calloc(1, sizeof(*iter))) == NULL ||
        (def_ccname && (iter->def_ccname = strdup(def_ccname)) == NULL)) {
        ret = krb5_enomem(context);
        goto out;
    }

    if (is_def_coll) {
        /* Since def_ccname is in the `def_locs', we'll include those */
        iter->locations = def_locs;
        free(iter->def_ccname);
        iter->def_ccname = NULL;
        def_locs = NULL;
    } else {
        /* Since def_ccname is NOT in the `def_locs', we'll exclude those */
        iter->locations = NULL;
    }
    iter->curr_location = NULL;
    iter->location = -1; /* Pre-incremented */
    iter->first = 1;
    iter->dname = NULL;
    iter->d = NULL;
    *cursor = iter;
    iter = NULL;
    ret = 0;

out:
    krb5_config_free_strings(def_locs);
    free(iter);
    return ret;
}

/* Pick the next location as the `iter->curr_location' */
static krb5_error_code
next_location(krb5_context context, struct fcache_iter *iter)
{
    if (iter->first && iter->def_ccname) {
        iter->curr_location = iter->def_ccname;
        iter->first = 0;
        return 0;
    }
    iter->first = 0;

    if (iter->d)
        closedir(iter->d);
    iter->d = NULL;
    iter->curr_location = NULL;
    if (iter->locations &&
        (iter->curr_location = iter->locations[++(iter->location)]))
        return 0;

    iter->dead = 1; /* Do not run off the end of iter->locations */
    return KRB5_CC_END;
}

/* Output the next match for `iter->curr_location' from readdir() */
static krb5_error_code
next_dir_match(krb5_context context, struct fcache_iter *iter, char **fn)
{
    struct stat st;
    const char *base = my_basename(iter->curr_location);
    size_t baselen = strlen(base);
    char *s;

    *fn = NULL;
    if (iter->d == NULL)
        return 0;
    for (iter->dentry = readdir(iter->d);
         iter->dentry;
         iter->dentry = readdir(iter->d)) {
        if (!matchbase(iter->dentry->d_name, base, baselen))
            continue;
        if (asprintf(&s, "FILE:%s/%s", iter->dname, iter->dentry->d_name) == -1 ||
            s == NULL)
            return krb5_enomem(context);
        if (stat(s + sizeof("FILE:") - 1, &st) == 0 && S_ISREG(st.st_mode)) {
            *fn = s;
            return 0;
        }
        free(s);
    }
    iter->curr_location = NULL;
    closedir(iter->d);
    iter->d = NULL;
    return 0;
}

/* See if the given `ccname' is a FILE ccache we can resolve */
static krb5_error_code
try1(krb5_context context, const char *ccname, krb5_ccache *id)
{
    krb5_error_code ret;
    krb5_ccache cc;

    ret = krb5_cc_resolve(context, ccname, &cc);
    if (ret == ENOMEM)
        return ret;
    if (ret == 0) {
        if (strcmp(krb5_cc_get_type(context, cc), "FILE") == 0) {
            *id = cc;
            cc = NULL;
        }
        krb5_cc_close(context, cc);
    }
    return 0;
}

/* Output the next FILE ccache in the FILE ccache collection */
static krb5_error_code KRB5_CALLCONV
fcc_get_cache_next(krb5_context context, krb5_cc_cursor cursor, krb5_ccache *id)
{
    struct fcache_iter *iter = cursor;
    krb5_error_code ret;
    char *name = NULL;

    *id = NULL;
    if (iter == NULL)
        return krb5_einval(context, 2);

    /* Do not run off the end of iter->locations */
    if (iter->dead)
        return KRB5_CC_END;

    if (!iter->curr_location) {
        /* Next base location */
        if ((ret = next_location(context, iter)))
            return ret;
        /* Output the current base location */
        if ((ret = try1(context, iter->curr_location, id)) || *id)
            return ret;
    }

    /* Look for subsidiaries of iter->curr_location */
    if (!iter->d) {
        free(iter->dname);
        if ((iter->dname = my_dirname(iter->curr_location)) == NULL)
            return krb5_enomem(context);
        if ((iter->d = opendir(iter->dname)) == NULL) {
            /* Dirname ENOENT -> next location */
            if ((ret = next_location(context, iter)))
                return ret;
            /* Tail-recurse */
            return fcc_get_cache_next(context, cursor, id);
        }
    }
    for (ret = next_dir_match(context, iter, &name);
         ret == 0 && name != NULL;
         ret = next_dir_match(context, iter, &name)) {
        if ((ret = try1(context, name, id)) || *id) {
            free(name);
            return ret;
        }
        free(name);
    }

    /* Directory listing exhausted -> go to next location, tail-recurse */
    if ((ret = next_location(context, iter)))
        return ret;
    return fcc_get_cache_next(context, cursor, id);
}

static krb5_error_code KRB5_CALLCONV
fcc_end_cache_get(krb5_context context, krb5_cc_cursor cursor)
{
    struct fcache_iter *iter = cursor;

    if (iter == NULL)
        return krb5_einval(context, 2);

    krb5_config_free_strings(iter->locations);
    if (iter->d)
        closedir(iter->d);
    free(iter->def_ccname);
    free(iter->dname);
    free(iter);
    return 0;
}

static krb5_error_code KRB5_CALLCONV
fcc_move(krb5_context context, krb5_ccache from, krb5_ccache to)
{
    krb5_error_code ret = 0;
    krb5_fcache *f = FCACHE(from);
    krb5_fcache *t = FCACHE(to);

    if (f->tmpfn) {
        /*
         * If `from' has a temp file and we haven't renamed it into place yet,
         * then we should rename TMPFILENAME(from) to FILENAME(to).
         *
         * This can only happen if we're moving a ccache where only cc config
         * entries, or no entries, have been written.  That's not likely.
         */
        if (rk_rename(f->tmpfn, t->filename)) {
            ret = errno;
        } else {
            free(f->tmpfn);
            f->tmpfn = NULL;
        }
    } else if (rk_rename(f->filename, t->filename)) {
        ret = errno;
    }
    /*
     * We need only close from -- we can't destroy it since the rename
     * succeeded, which "destroyed" it at its old name.
     */
    if (ret == 0)
        krb5_cc_close(context, from);
    return ret;
}

static krb5_error_code KRB5_CALLCONV
fcc_get_default_name(krb5_context context, char **str)
{
    return _krb5_expand_default_cc_name(context,
					KRB5_DEFAULT_CCNAME_FILE,
					str);
}

static krb5_error_code KRB5_CALLCONV
fcc_set_default_cache(krb5_context context, krb5_ccache id)
{
    krb5_error_code ret;
    krb5_ccache dest;
    char *s = NULL;

    if (SUBFILENAME(id) == NULL)
        return 0; /* Already a primary */
    if (asprintf(&s, "FILE:%s", RESFILENAME(id)) == -1 || s == NULL)
        return krb5_enomem(context);

    /*
     * We can't hard-link, since we refuse to open ccaches with st_nlink > 1,
     * and we can't rename() the ccache because the old name should remain
     * available.  Ergo, we copy the ccache.
     */
    ret = krb5_cc_resolve(context, s, &dest);
    if (ret == 0)
        ret = krb5_cc_copy_cache(context, id, dest);
    free(s);
    if (ret)
	krb5_set_error_message(context, ret,
                               N_("Failed to copy subsidiary cache file %s to "
                                  "default %s", ""), FILENAME(id),
                               RESFILENAME(id));
    return ret;
}

static krb5_error_code KRB5_CALLCONV
fcc_lastchange(krb5_context context, krb5_ccache id, krb5_timestamp *mtime)
{
    krb5_error_code ret;
    struct stat sb;
    int fd;

    ret = fcc_open(context, id, "lastchange", &fd, O_RDONLY, 0);
    if(ret)
	return ret;
    ret = fstat(fd, &sb);
    close(fd);
    if (ret) {
	ret = errno;
	krb5_set_error_message(context, ret, N_("Failed to stat cache file", ""));
	return ret;
    }
    *mtime = sb.st_mtime;
    return 0;
}

static krb5_error_code KRB5_CALLCONV
fcc_set_kdc_offset(krb5_context context, krb5_ccache id, krb5_deltat kdc_offset)
{
    return 0;
}

static krb5_error_code KRB5_CALLCONV
fcc_get_kdc_offset(krb5_context context, krb5_ccache id, krb5_deltat *kdc_offset)
{
    krb5_error_code ret;
    krb5_storage *sp = NULL;
    int fd;
    ret = init_fcc(context, id, "get-kdc-offset", &sp, &fd, kdc_offset);
    if (sp)
	krb5_storage_free(sp);
    close(fd);

    return ret;
}


/**
 * Variable containing the FILE based credential cache implementation.
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_VARIABLE const krb5_cc_ops krb5_fcc_ops = {
    KRB5_CC_OPS_VERSION_5,
    "FILE",
    NULL,
    NULL,
    fcc_gen_new,
    fcc_initialize,
    fcc_destroy,
    fcc_close,
    fcc_store_cred,
    NULL, /* fcc_retrieve */
    fcc_get_principal,
    fcc_get_first,
    fcc_get_next,
    fcc_end_get,
    fcc_remove_cred,
    fcc_set_flags,
    fcc_get_version,
    fcc_get_cache_first,
    fcc_get_cache_next,
    fcc_end_cache_get,
    fcc_move,
    fcc_get_default_name,
    fcc_set_default_cache,
    fcc_lastchange,
    fcc_set_kdc_offset,
    fcc_get_kdc_offset,
    fcc_get_name_2,
    fcc_resolve_2
};
