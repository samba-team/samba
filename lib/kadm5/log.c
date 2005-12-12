/*
 * Copyright (c) 1997 - 2005 Kungliga Tekniska Högskolan
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

#include "kadm5_locl.h"

RCSID("$Id$");

/*
 * A log record consists of:
 *
 * version number		4 bytes
 * time in seconds		4 bytes
 * operation (enum kadm_ops)	4 bytes
 * length of record		4 bytes
 * data...			n bytes
 * length of record		4 bytes
 * version number		4 bytes
 *
 */

kadm5_ret_t
kadm5_log_get_version_fd (int fd,
			  u_int32_t *ver)
{
    int ret;
    krb5_storage *sp;
    int32_t old_version;

    ret = lseek (fd, 0, SEEK_END);
    if(ret < 0)
	return errno;
    if(ret == 0) {
	*ver = 0;
	return 0;
    }
    sp = krb5_storage_from_fd (fd);
    krb5_storage_seek(sp, -4, SEEK_CUR);
    krb5_ret_int32 (sp, &old_version);
    *ver = old_version;
    krb5_storage_free(sp);
    lseek (fd, 0, SEEK_END);
    return 0;
}

kadm5_ret_t
kadm5_log_get_version (kadm5_server_context *context, u_int32_t *ver)
{
    return kadm5_log_get_version_fd (context->log_context.log_fd, ver);
}

kadm5_ret_t
kadm5_log_set_version (kadm5_server_context *context, u_int32_t vno)
{
    kadm5_log_context *log_context = &context->log_context;

    log_context->version = vno;
    return 0;
}

kadm5_ret_t
kadm5_log_init (kadm5_server_context *context)
{
    int fd;
    kadm5_ret_t ret;
    kadm5_log_context *log_context = &context->log_context;

    if (log_context->log_fd != -1)
	return 0;
    fd = open (log_context->log_file, O_RDWR | O_CREAT, 0600);
    if (fd < 0) {
	krb5_set_error_string(context->context, "kadm5_log_init: open %s",
			      log_context->log_file);
	return errno;
    }
    if (flock (fd, LOCK_EX) < 0) {
	krb5_set_error_string(context->context, "kadm5_log_init: flock %s",
			      log_context->log_file);
	close (fd);
	return errno;
    }

    ret = kadm5_log_get_version_fd (fd, &log_context->version);
    if (ret)
	return ret;

    log_context->log_fd  = fd;
    return 0;
}

kadm5_ret_t
kadm5_log_reinit (kadm5_server_context *context)
{
    int fd;
    kadm5_log_context *log_context = &context->log_context;

    if (log_context->log_fd != -1) {
	close (log_context->log_fd);
	log_context->log_fd = -1;
    }
    fd = open (log_context->log_file, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
	return errno;
    if (flock (fd, LOCK_EX) < 0) {
	close (fd);
	return errno;
    }

    log_context->version = 0;
    log_context->log_fd  = fd;
    return 0;
}


kadm5_ret_t
kadm5_log_end (kadm5_server_context *context)
{
    kadm5_log_context *log_context = &context->log_context;
    int fd = log_context->log_fd;

    flock (fd, LOCK_UN);
    close(fd);
    log_context->log_fd = -1;
    return 0;
}

static kadm5_ret_t
kadm5_log_preamble (kadm5_server_context *context,
		    krb5_storage *sp,
		    enum kadm_ops op)
{
    kadm5_log_context *log_context = &context->log_context;
    kadm5_ret_t kadm_ret;

    kadm_ret = kadm5_log_init (context);
    if (kadm_ret)
	return kadm_ret;

    krb5_store_int32 (sp, ++log_context->version);
    krb5_store_int32 (sp, time(NULL));
    krb5_store_int32 (sp, op);
    return 0;
}

static kadm5_ret_t
kadm5_log_postamble (kadm5_log_context *context,
		     krb5_storage *sp)
{
    krb5_store_int32 (sp, context->version);
    return 0;
}

/*
 * flush the log record in `sp'.
 */

static kadm5_ret_t
kadm5_log_flush (kadm5_log_context *log_context,
		 krb5_storage *sp)
{
    krb5_data data;
    size_t len;
    int ret;

    krb5_storage_to_data(sp, &data);
    len = data.length;
    ret = write (log_context->log_fd, data.data, len);
    if (ret != len) {
	krb5_data_free(&data);
	return errno;
    }
    if (fsync (log_context->log_fd) < 0) {
	krb5_data_free(&data);
	return errno;
    }
    /*
     * Try to send a signal to any running `ipropd-master'
     */
    sendto (log_context->socket_fd,
	    (void *)&log_context->version,
	    sizeof(log_context->version),
	    0,
	    (struct sockaddr *)&log_context->socket_name,
	    sizeof(log_context->socket_name));

    krb5_data_free(&data);
    return 0;
}

/*
 * Add a `create' operation to the log.
 */

kadm5_ret_t
kadm5_log_create (kadm5_server_context *context,
		  hdb_entry *ent)
{
    krb5_storage *sp;
    kadm5_ret_t ret;
    krb5_data value;
    kadm5_log_context *log_context = &context->log_context;

    sp = krb5_storage_emem();
    ret = hdb_entry2value (context->context, ent, &value);
    if (ret) {
	krb5_storage_free(sp);
	return ret;
    }
    ret = kadm5_log_preamble (context, sp, kadm_create);
    if (ret) {
	krb5_data_free (&value);
	krb5_storage_free(sp);
	return ret;
    }
    krb5_store_int32 (sp, value.length);
    krb5_storage_write(sp, value.data, value.length);
    krb5_store_int32 (sp, value.length);
    krb5_data_free (&value);
    ret = kadm5_log_postamble (log_context, sp);
    if (ret) {
	krb5_storage_free (sp);
	return ret;
    }
    ret = kadm5_log_flush (log_context, sp);
    krb5_storage_free (sp);
    if (ret)
	return ret;
    ret = kadm5_log_end (context);
    return ret;
}

/*
 * Read the data of a create log record from `sp' and change the
 * database.
 */

kadm5_ret_t
kadm5_log_replay_create (kadm5_server_context *context,
			 u_int32_t ver,
			 u_int32_t len,
			 krb5_storage *sp)
{
    krb5_error_code ret;
    krb5_data data;
    hdb_entry_ex ent;

    memset(&ent, 0, sizeof(ent));

    ret = krb5_data_alloc (&data, len);
    if (ret)
	return ret;
    krb5_storage_read (sp, data.data, len);
    ret = hdb_value2entry (context->context, &data, &ent.entry);
    krb5_data_free(&data);
    if (ret)
	return ret;
    ret = context->db->hdb_store(context->context, context->db, 0, &ent);
    hdb_free_entry (context->context, &ent);
    return ret;
}

/*
 * Add a `delete' operation to the log.
 */

kadm5_ret_t
kadm5_log_delete (kadm5_server_context *context,
		  krb5_principal princ)
{
    krb5_storage *sp;
    kadm5_ret_t ret;
    off_t off;
    off_t len;
    kadm5_log_context *log_context = &context->log_context;

    sp = krb5_storage_emem();
    ret = kadm5_log_preamble (context, sp, kadm_delete);
    if (ret) {
	krb5_storage_free(sp);
	return ret;
    }
    krb5_store_int32 (sp, 0);
    off = krb5_storage_seek (sp, 0, SEEK_CUR);
    krb5_store_principal (sp, princ);
    len = krb5_storage_seek (sp, 0, SEEK_CUR) - off;
    krb5_storage_seek(sp, -(len + 4), SEEK_CUR);
    krb5_store_int32 (sp, len);
    krb5_storage_seek(sp, len, SEEK_CUR);
    krb5_store_int32 (sp, len);
    if (ret) {
	krb5_storage_free (sp);
	return ret;
    }
    ret = kadm5_log_postamble (log_context, sp);
    if (ret) {
	krb5_storage_free (sp);
	return ret;
    }
    ret = kadm5_log_flush (log_context, sp);
    krb5_storage_free (sp);
    if (ret)
	return ret;
    ret = kadm5_log_end (context);
    return ret;
}

/*
 * Read a `delete' log operation from `sp' and apply it.
 */

kadm5_ret_t
kadm5_log_replay_delete (kadm5_server_context *context,
			 u_int32_t ver,
			 u_int32_t len,
			 krb5_storage *sp)
{
    krb5_error_code ret;
    hdb_entry_ex ent;

    krb5_ret_principal (sp, &ent.entry.principal);

    ret = context->db->hdb_remove(context->context, context->db, &ent);
    krb5_free_principal (context->context, ent.entry.principal);
    return ret;
}

/*
 * Add a `rename' operation to the log.
 */

kadm5_ret_t
kadm5_log_rename (kadm5_server_context *context,
		  krb5_principal source,
		  hdb_entry *ent)
{
    krb5_storage *sp;
    kadm5_ret_t ret;
    off_t off;
    off_t len;
    krb5_data value;
    kadm5_log_context *log_context = &context->log_context;

    sp = krb5_storage_emem();
    ret = hdb_entry2value (context->context, ent, &value);
    if (ret) {
	krb5_storage_free(sp);
	return ret;
    }
    ret = kadm5_log_preamble (context, sp, kadm_rename);
    if (ret) {
	krb5_storage_free(sp);
	krb5_data_free (&value);
	return ret;
    }
    krb5_store_int32 (sp, 0);
    off = krb5_storage_seek (sp, 0, SEEK_CUR);
    krb5_store_principal (sp, source);
    krb5_storage_write(sp, value.data, value.length);
    krb5_data_free (&value);
    len = krb5_storage_seek (sp, 0, SEEK_CUR) - off;

    krb5_storage_seek(sp, -(len + 4), SEEK_CUR);
    krb5_store_int32 (sp, len);
    krb5_storage_seek(sp, len, SEEK_CUR);
    krb5_store_int32 (sp, len);
    if (ret) {
	krb5_storage_free (sp);
	return ret;
    }
    ret = kadm5_log_postamble (log_context, sp);
    if (ret) {
	krb5_storage_free (sp);
	return ret;
    }
    ret = kadm5_log_flush (log_context, sp);
    krb5_storage_free (sp);
    if (ret)
	return ret;
    ret = kadm5_log_end (context);
    return ret;
}

/*
 * Read a `rename' log operation from `sp' and apply it.
 */

kadm5_ret_t
kadm5_log_replay_rename (kadm5_server_context *context,
			 u_int32_t ver,
			 u_int32_t len,
			 krb5_storage *sp)
{
    krb5_error_code ret;
    krb5_principal source;
    hdb_entry_ex source_ent, target_ent;
    krb5_data value;
    off_t off;
    size_t princ_len, data_len;

    memset(&target_ent, 0, sizeof(target_ent));

    off = krb5_storage_seek(sp, 0, SEEK_CUR);
    krb5_ret_principal (sp, &source);
    princ_len = krb5_storage_seek(sp, 0, SEEK_CUR) - off;
    data_len = len - princ_len;
    ret = krb5_data_alloc (&value, data_len);
    if (ret) {
	krb5_free_principal (context->context, source);
	return ret;
    }
    krb5_storage_read (sp, value.data, data_len);
    ret = hdb_value2entry (context->context, &value, &target_ent.entry);
    krb5_data_free(&value);
    if (ret) {
	krb5_free_principal (context->context, source);
	return ret;
    }
    ret = context->db->hdb_store (context->context, context->db, 
				  0, &target_ent);
    hdb_free_entry (context->context, &target_ent);
    if (ret) {
	krb5_free_principal (context->context, source);
	return ret;
    }
    source_ent.entry.principal = source;
    ret = context->db->hdb_remove (context->context, context->db, &source_ent);
    krb5_free_principal (context->context, source);
    return ret;
}


/*
 * Add a `modify' operation to the log.
 */

kadm5_ret_t
kadm5_log_modify (kadm5_server_context *context,
		  hdb_entry *ent,
		  u_int32_t mask)
{
    krb5_storage *sp;
    kadm5_ret_t ret;
    krb5_data value;
    u_int32_t len;
    kadm5_log_context *log_context = &context->log_context;

    sp = krb5_storage_emem();
    ret = hdb_entry2value (context->context, ent, &value);
    if (ret) {
	krb5_storage_free(sp);
	return ret;
    }
    ret = kadm5_log_preamble (context, sp, kadm_modify);
    if (ret) {
	krb5_data_free (&value);
	krb5_storage_free(sp);
	return ret;
    }
    len = value.length + 4;
    krb5_store_int32 (sp, len);
    krb5_store_int32 (sp, mask);
    krb5_storage_write (sp, value.data, value.length);
    krb5_data_free (&value);
    krb5_store_int32 (sp, len);
    if (ret) {
	krb5_storage_free (sp);
	return ret;
    }
    ret = kadm5_log_postamble (log_context, sp);
    if (ret) {
	krb5_storage_free (sp);
	return ret;
    }
    ret = kadm5_log_flush (log_context, sp);
    krb5_storage_free (sp);
    if (ret)
	return ret;
    ret = kadm5_log_end (context);
    return ret;
}

/*
 * Read a `modify' log operation from `sp' and apply it.
 */

kadm5_ret_t
kadm5_log_replay_modify (kadm5_server_context *context,
			 u_int32_t ver,
			 u_int32_t len,
			 krb5_storage *sp)
{
    krb5_error_code ret;
    int32_t mask;
    krb5_data value;
    hdb_entry_ex ent, log_ent;

    memset(&log_ent, 0, sizeof(log_ent));

    krb5_ret_int32 (sp, &mask);
    len -= 4;
    ret = krb5_data_alloc (&value, len);
    if (ret)
	return ret;
    krb5_storage_read (sp, value.data, len);
    ret = hdb_value2entry (context->context, &value, &log_ent.entry);
    krb5_data_free(&value);
    if (ret)
	return ret;
    ent.entry.principal = log_ent.entry.principal;
    log_ent.entry.principal = NULL;
    ret = context->db->hdb_fetch(context->context, context->db, 
				 HDB_F_DECRYPT, &ent);
    if (ret)
	goto out;
    if (mask & KADM5_PRINC_EXPIRE_TIME) {
	if (log_ent.entry.valid_end == NULL) {
	    ent.entry.valid_end = NULL;
	} else {
	    if (ent.entry.valid_end == NULL) {
		ent.entry.valid_end = malloc(sizeof(*ent.entry.valid_end));
		if (ent.entry.valid_end == NULL) {
		    ret = ENOMEM;
		    goto out;
		}
	    }
	    *ent.entry.valid_end = *log_ent.entry.valid_end;
	}
    }
    if (mask & KADM5_PW_EXPIRATION) {
	if (log_ent.entry.pw_end == NULL) {
	    ent.entry.pw_end = NULL;
	} else {
	    if (ent.entry.pw_end == NULL) {
		ent.entry.pw_end = malloc(sizeof(*ent.entry.pw_end));
		if (ent.entry.pw_end == NULL) {
		    ret = ENOMEM;
		    goto out;
		}
	    }
	    *ent.entry.pw_end = *log_ent.entry.pw_end;
	}
    }
    if (mask & KADM5_LAST_PWD_CHANGE) {
	abort ();		/* XXX */
    }
    if (mask & KADM5_ATTRIBUTES) {
	ent.entry.flags = log_ent.entry.flags;
    }
    if (mask & KADM5_MAX_LIFE) {
	if (log_ent.entry.max_life == NULL) {
	    ent.entry.max_life = NULL;
	} else {
	    if (ent.entry.max_life == NULL) {
		ent.entry.max_life = malloc (sizeof(*ent.entry.max_life));
		if (ent.entry.max_life == NULL) {
		    ret = ENOMEM;
		    goto out;
		}
	    }
	    *ent.entry.max_life = *log_ent.entry.max_life;
	}
    }
    if ((mask & KADM5_MOD_TIME) && (mask & KADM5_MOD_NAME)) {
	if (ent.entry.modified_by == NULL) {
	    ent.entry.modified_by = malloc(sizeof(*ent.entry.modified_by));
	    if (ent.entry.modified_by == NULL) {
		ret = ENOMEM;
		goto out;
	    }
	} else
	    free_Event(ent.entry.modified_by);
	ret = copy_Event(log_ent.entry.modified_by, ent.entry.modified_by);
	if (ret)
	    goto out;
    }
    if (mask & KADM5_KVNO) {
	ent.entry.kvno = log_ent.entry.kvno;
    }
    if (mask & KADM5_MKVNO) {
	abort ();		/* XXX */
    }
    if (mask & KADM5_AUX_ATTRIBUTES) {
	abort ();		/* XXX */
    }
    if (mask & KADM5_POLICY) {
	abort ();		/* XXX */
    }
    if (mask & KADM5_POLICY_CLR) {
	abort ();		/* XXX */
    }
    if (mask & KADM5_MAX_RLIFE) {
	if (log_ent.entry.max_renew == NULL) {
	    ent.entry.max_renew = NULL;
	} else {
	    if (ent.entry.max_renew == NULL) {
		ent.entry.max_renew = malloc (sizeof(*ent.entry.max_renew));
		if (ent.entry.max_renew == NULL) {
		    ret = ENOMEM;
		    goto out;
		}
	    }
	    *ent.entry.max_renew = *log_ent.entry.max_renew;
	}
    }
    if (mask & KADM5_LAST_SUCCESS) {
	abort ();		/* XXX */
    }
    if (mask & KADM5_LAST_FAILED) {
	abort ();		/* XXX */
    }
    if (mask & KADM5_FAIL_AUTH_COUNT) {
	abort ();		/* XXX */
    }
    if (mask & KADM5_KEY_DATA) {
	size_t num;
	int i;

	for (i = 0; i < ent.entry.keys.len; ++i)
	    free_Key(&ent.entry.keys.val[i]);
	free (ent.entry.keys.val);

	num = log_ent.entry.keys.len;

	ent.entry.keys.len = num;
	ent.entry.keys.val = malloc(len * sizeof(*ent.entry.keys.val));
	for (i = 0; i < ent.entry.keys.len; ++i) {
	    ret = copy_Key(&log_ent.entry.keys.val[i],
			   &ent.entry.keys.val[i]);
	    if (ret)
		goto out;
	}
    }
    if ((mask & KADM5_TL_DATA) && log_ent.entry.extensions) {
	HDB_extensions *es = ent.entry.extensions;

	if (ent.entry.extensions == NULL) {
	    ent.entry.extensions = calloc(1, sizeof(*ent.entry.extensions));
	    if (ent.entry.extensions == NULL)
		goto out;
	}

	ret = copy_HDB_extensions(es, ent.entry.extensions);
	if (ret) {
	    free(ent.entry.extensions);
	    ent.entry.extensions = es;
	    goto out;
	}
	if (es) {
	    free_HDB_extensions(es);
	    free(es);
	}
    }
    ret = context->db->hdb_store(context->context, context->db, 
				 HDB_F_REPLACE, &ent);
 out:
    hdb_free_entry (context->context, &ent);
    hdb_free_entry (context->context, &log_ent);
    return ret;
}

/*
 * Add a `nop' operation to the log.
 */

kadm5_ret_t
kadm5_log_nop (kadm5_server_context *context)
{
    krb5_storage *sp;
    kadm5_ret_t ret;
    kadm5_log_context *log_context = &context->log_context;

    sp = krb5_storage_emem();
    ret = kadm5_log_preamble (context, sp, kadm_nop);
    if (ret) {
	krb5_storage_free (sp);
	return ret;
    }
    krb5_store_int32 (sp, 0);
    krb5_store_int32 (sp, 0);
    ret = kadm5_log_postamble (log_context, sp);
    if (ret) {
	krb5_storage_free (sp);
	return ret;
    }
    ret = kadm5_log_flush (log_context, sp);
    krb5_storage_free (sp);
    if (ret)
	return ret;
    ret = kadm5_log_end (context);
    return ret;
}

/*
 * Read a `nop' log operation from `sp' and apply it.
 */

kadm5_ret_t
kadm5_log_replay_nop (kadm5_server_context *context,
		      u_int32_t ver,
		      u_int32_t len,
		      krb5_storage *sp)
{
    return 0;
}

/*
 * Call `func' for each log record in the log in `context'
 */

kadm5_ret_t
kadm5_log_foreach (kadm5_server_context *context,
		   void (*func)(kadm5_server_context *server_context,
				u_int32_t ver,
				time_t timestamp,
				enum kadm_ops op,
				u_int32_t len,
				krb5_storage *,
				void *),
		   void *ctx)
{
    int fd = context->log_context.log_fd;
    krb5_storage *sp;

    lseek (fd, 0, SEEK_SET);
    sp = krb5_storage_from_fd (fd);
    for (;;) {
	int32_t ver, timestamp, op, len;

	if(krb5_ret_int32 (sp, &ver) != 0)
	    break;
	krb5_ret_int32 (sp, &timestamp);
	krb5_ret_int32 (sp, &op);
	krb5_ret_int32 (sp, &len);
	(*func)(context, ver, timestamp, op, len, sp, ctx);
	krb5_storage_seek(sp, 8, SEEK_CUR);
    }
    return 0;
}

/*
 * Go to end of log.
 */

krb5_storage *
kadm5_log_goto_end (int fd)
{
    krb5_storage *sp;

    sp = krb5_storage_from_fd (fd);
    krb5_storage_seek(sp, 0, SEEK_END);
    return sp;
}

/*
 * Return previous log entry.
 */

kadm5_ret_t
kadm5_log_previous (krb5_context context,
		    krb5_storage *sp,
		    u_int32_t *ver,
		    time_t *timestamp,
		    enum kadm_ops *op,
		    u_int32_t *len)
{
    krb5_error_code ret;
    off_t off;
    int32_t tmp;

    krb5_storage_seek(sp, -8, SEEK_CUR);
    ret = krb5_ret_int32 (sp, &tmp);
    if (ret)
	goto end_of_storage;
    *len = tmp;
    ret = krb5_ret_int32 (sp, &tmp);
    *ver = tmp;
    off = 24 + *len;
    krb5_storage_seek(sp, -off, SEEK_CUR);
    ret = krb5_ret_int32 (sp, &tmp);
    if (ret)
	goto end_of_storage;
    if (tmp != *ver) {
	krb5_set_error_string(context, "kadm5_log_previous: log entry "
			      "have consistency failure, version number wrong");
	return KADM5_BAD_DB;
    }
    ret = krb5_ret_int32 (sp, &tmp);
    if (ret)
	goto end_of_storage;
    *timestamp = tmp;
    ret = krb5_ret_int32 (sp, &tmp);
    *op = tmp;
    ret = krb5_ret_int32 (sp, &tmp);
    if (ret)
	goto end_of_storage;
    if (tmp != *ver) {
	krb5_set_error_string(context, "kadm5_log_previous: log entry "
			      "have consistency failure, length wrong");
	return KADM5_BAD_DB;
    }
    return 0;

 end_of_storage:
    krb5_set_error_string(context, "kadm5_log_previous: end of storage "
			  "reached before end");
    return ret;
}

/*
 * Replay a record from the log
 */

kadm5_ret_t
kadm5_log_replay (kadm5_server_context *context,
		  enum kadm_ops op,
		  u_int32_t ver,
		  u_int32_t len,
		  krb5_storage *sp)
{
    switch (op) {
    case kadm_create :
	return kadm5_log_replay_create (context, ver, len, sp);
    case kadm_delete :
	return kadm5_log_replay_delete (context, ver, len, sp);
    case kadm_rename :
	return kadm5_log_replay_rename (context, ver, len, sp);
    case kadm_modify :
	return kadm5_log_replay_modify (context, ver, len, sp);
    case kadm_nop :
	return kadm5_log_replay_nop (context, ver, len, sp);
    default :
	return KADM5_FAILURE;
    }
}

/*
 * truncate the log - i.e. create an empty file with just (nop vno + 2)
 */

kadm5_ret_t
kadm5_log_truncate (kadm5_server_context *server_context)
{
    kadm5_ret_t ret;
    u_int32_t vno;

    ret = kadm5_log_init (server_context);
    if (ret)
	return ret;

    ret = kadm5_log_get_version (server_context, &vno);
    if (ret)
	return ret;

    ret = kadm5_log_reinit (server_context);
    if (ret)
	return ret;

    ret = kadm5_log_set_version (server_context, vno + 1);
    if (ret)
	return ret;

    ret = kadm5_log_nop (server_context);
    if (ret)
	return ret;

    ret = kadm5_log_end (server_context);
    if (ret)
	return ret;
    return 0;

}
