/*
 * Copyright (c) 2009 Kungliga Tekniska Högskolan
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

#include "mech_locl.h"
#include "heim_threads.h"
#include <krb5.h>
#include "krb5_locl.h"
#include "negoex_err.h"

struct mg_thread_ctx {
    gss_OID mech;
    OM_uint32 min_stat;
    gss_buffer_desc min_error;
    krb5_context context;
};

static HEIMDAL_MUTEX context_mutex = HEIMDAL_MUTEX_INITIALIZER;
static int created_key;
static HEIMDAL_thread_key context_key;


static void
destroy_context(void *ptr)
{
    struct mg_thread_ctx *mg = ptr;
    OM_uint32 junk;

    if (mg == NULL)
	return;

    gss_release_buffer(&junk, &mg->min_error);

    if (mg->context)
	krb5_free_context(mg->context);

    free(mg);
}


static struct mg_thread_ctx *
_gss_mechglue_thread(void)
{
    struct mg_thread_ctx *ctx;
    int ret = 0;

    HEIMDAL_MUTEX_lock(&context_mutex);

    if (!created_key) {
	HEIMDAL_key_create(&context_key, destroy_context, ret);
	if (ret) {
	    HEIMDAL_MUTEX_unlock(&context_mutex);
	    return NULL;
	}
	created_key = 1;
    }
    HEIMDAL_MUTEX_unlock(&context_mutex);

    ctx = HEIMDAL_getspecific(context_key);
    if (ctx == NULL) {

	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL)
	    return NULL;

	ret = krb5_init_context(&ctx->context);
	if (ret) {
	    free(ctx);
	    return NULL;
	}

	krb5_add_et_list(ctx->context, initialize_ngex_error_table_r);

	HEIMDAL_setspecific(context_key, ctx, ret);
	if (ret) {
	    krb5_free_context(ctx->context);
	    free(ctx);
	    return NULL;
	}
    }
    return ctx;
}

krb5_context
_gss_mg_krb5_context(void)
{
    struct mg_thread_ctx *mg;

    mg = _gss_mechglue_thread();

    return mg ? mg->context : NULL;
}

OM_uint32
_gss_mg_get_error(const gss_OID mech,
		  OM_uint32 value,
		  gss_buffer_t string)
{
    struct mg_thread_ctx *mg;

    mg = _gss_mechglue_thread();
    if (mg == NULL)
	return GSS_S_BAD_STATUS;

    if (value != mg->min_stat || mg->min_error.length == 0) {
	_mg_buffer_zero(string);
	return GSS_S_BAD_STATUS;
    }
    string->value = malloc(mg->min_error.length);
    if (string->value == NULL) {
	_mg_buffer_zero(string);
	return GSS_S_FAILURE;
    }
    string->length = mg->min_error.length;
    memcpy(string->value, mg->min_error.value, mg->min_error.length);
    return GSS_S_COMPLETE;
}

void
_gss_mg_error(struct gssapi_mech_interface_desc *m, OM_uint32 min)
{
    OM_uint32 major_status, minor_status;
    OM_uint32 message_content = 0;
    struct mg_thread_ctx *mg;

    /*
     * Mechs without gss_display_status() does
     * gss_mg_collect_error() by themself.
     */
    if (m->gm_display_status == NULL)
	return ;

    mg = _gss_mechglue_thread();
    if (mg == NULL)
	return;

    gss_release_buffer(&minor_status, &mg->min_error);

    mg->mech = &m->gm_mech_oid;
    mg->min_stat = min;

    major_status = m->gm_display_status(&minor_status,
					min,
					GSS_C_MECH_CODE,
					&m->gm_mech_oid,
					&message_content,
					&mg->min_error);
    if (major_status != GSS_S_COMPLETE) {
	_mg_buffer_zero(&mg->min_error);
    } else {
	_gss_mg_log(5, "_gss_mg_error: captured %.*s (%d) from underlying mech %s",
		    (int)mg->min_error.length, (const char *)mg->min_error.value,
		    (int)min, m->gm_name);
    }
}

void
gss_mg_collect_error(gss_OID mech, OM_uint32 maj, OM_uint32 min)
{
    gssapi_mech_interface m = __gss_get_mechanism(mech);
    if (m == NULL)
	return;
    _gss_mg_error(m, min);
}

OM_uint32
gss_mg_set_error_string(gss_OID mech,
			OM_uint32 maj, OM_uint32 min,
			const char *fmt, ...)
{
    struct mg_thread_ctx *mg;
    char *str = NULL;
    OM_uint32 junk;
    va_list ap;
    int vasprintf_ret;

    mg = _gss_mechglue_thread();
    if (mg == NULL)
	return maj;

    va_start(ap, fmt);
    vasprintf_ret = vasprintf(&str, fmt, ap);
    va_end(ap);

    if (vasprintf_ret >= 0 && str) {
	gss_release_buffer(&junk, &mg->min_error);

	mg->mech = mech;
	mg->min_stat = min;

	mg->min_error.value = str;
	mg->min_error.length = strlen(str);

	_gss_mg_log(5, "gss_mg_set_error_string: %.*s (%d/%d)",
		    (int)mg->min_error.length, (const char *)mg->min_error.value,
		    (int)maj, (int)min);
    }
    return maj;
}

static void *log_ctx = NULL;
static void (*log_func)(void *ctx, int level, const char *fmt, va_list) = NULL;

void GSSAPI_LIB_CALL
gss_set_log_function(void *ctx, void (*func)(void * ctx, int level, const char *fmt, va_list))
{
    if (log_func == NULL) {
	log_func = func;
	log_ctx = ctx;
    }
}

int
_gss_mg_log_level(int level)
{
    struct mg_thread_ctx *mg;

    mg = _gss_mechglue_thread();
    if (mg == NULL)
	return 0;

    return _krb5_have_debug(mg->context, level);
}

/*
 * TODO: refactor logging so that it no longer depends on libkrb5
 * and can be configured independently.
 */
void
_gss_mg_log(int level, const char *fmt, ...)
{
    struct mg_thread_ctx *mg;
    va_list ap;

    if (!_gss_mg_log_level(level))
	return;

    mg = _gss_mechglue_thread();
    if (mg == NULL)
	return;

    if (mg->context && _krb5_have_debug(mg->context, level)) {
	va_start(ap, fmt);
        krb5_vlog(mg->context, heim_get_debug_dest(mg->context->hcontext),
                  level, fmt, ap);
	va_end(ap);
    }

    if (log_func) {
	va_start(ap, fmt);
	log_func(log_ctx, level, fmt, ap);
	va_end(ap);
    }
}

void
_gss_mg_log_name(int level,
		 struct _gss_name *name,
		 gss_OID mech_type,
		 const char *fmt, ...)
{
    struct _gss_mechanism_name *mn = NULL;
    gssapi_mech_interface m;
    OM_uint32 junk;

    if (!_gss_mg_log_level(level))
        return;

    m = __gss_get_mechanism(mech_type);
    if (m == NULL)
        return;

    if (_gss_find_mn(&junk, name, mech_type, &mn) == GSS_S_COMPLETE) {
	OM_uint32 maj_stat = GSS_S_COMPLETE;
	gss_buffer_desc namebuf;
	int ret;

	if (mn == NULL) {
	    namebuf.value = "no name";
	    namebuf.length = strlen((char *)namebuf.value);
	} else {
	    maj_stat = m->gm_display_name(&junk, mn->gmn_name,
					  &namebuf, NULL);
	}
	if (maj_stat == GSS_S_COMPLETE) {
	    char *str = NULL;
	    va_list ap;

	    va_start(ap, fmt);
	    ret = vasprintf(&str, fmt, ap);
	    va_end(ap);

	    if (ret >= 0 && str)
	        _gss_mg_log(level, "%s %.*s", str,
			    (int)namebuf.length, (char *)namebuf.value);
	    free(str);
	    if (mn != NULL)
		gss_release_buffer(&junk, &namebuf);
	}
    }

}

void
_gss_mg_log_cred(int level,
		 struct _gss_cred *cred,
		 const char *fmt, ...)
{
    struct _gss_mechanism_cred *mc;
    char *str;
    va_list ap;
    int ret;

    if (!_gss_mg_log_level(level))
        return;

    va_start(ap, fmt);
    ret = vasprintf(&str, fmt, ap);
    va_end(ap);

    if (ret >=0 && cred) {
	HEIM_TAILQ_FOREACH(mc, &cred->gc_mc, gmc_link) {
	    _gss_mg_log(1, "%s: %s", str, mc->gmc_mech->gm_name);
	}
    } else {
	_gss_mg_log(1, "%s: GSS_C_NO_CREDENTIAL", str);
    }
    free(str);
}

