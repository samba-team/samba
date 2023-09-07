/*
 *  Unix SMB/CIFS implementation.
 *  NetApi Support
 *  Copyright (C) Guenther Deschner 2007-2008
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "../libcli/auth/netlogon_creds_cli.h"
#include "lib/netapi/netapi.h"
#include "lib/netapi/netapi_private.h"
#include "secrets.h"
#include "krb5_env.h"
#include "source3/param/loadparm.h"
#include "lib/param/param.h"
#include "auth/gensec/gensec.h"

struct libnetapi_ctx *stat_ctx = NULL;
static bool libnetapi_initialized = false;

/****************************************************************
****************************************************************/

static NET_API_STATUS libnetapi_init_private_context(struct libnetapi_ctx *ctx)
{
	struct libnetapi_private_ctx *priv;

	if (!ctx) {
		return W_ERROR_V(WERR_INVALID_PARAMETER);
	}

	priv = talloc_zero(ctx, struct libnetapi_private_ctx);
	if (!priv) {
		return W_ERROR_V(WERR_NOT_ENOUGH_MEMORY);
	}

	ctx->private_data = priv;

	return NET_API_STATUS_SUCCESS;
}

/****************************************************************
Create a libnetapi context, for use in non-Samba applications.  This
loads the smb.conf file and sets the debug level to 0, so that
applications are not flooded with debug logs at level 10, when they
were not expecting it.
****************************************************************/

NET_API_STATUS libnetapi_init(struct libnetapi_ctx **context)
{
	NET_API_STATUS ret;
	TALLOC_CTX *frame;
	struct loadparm_context *lp_ctx = NULL;

	if (stat_ctx && libnetapi_initialized) {
		*context = stat_ctx;
		return NET_API_STATUS_SUCCESS;
	}

#if 0
	talloc_enable_leak_report();
#endif
	frame = talloc_stackframe();

	/* When libnetapi is invoked from an application, it does not
	 * want to be swamped with level 10 debug messages, even if
	 * this has been set for the server in smb.conf */
	lp_set_cmdline("log level", "0");
	setup_logging("libnetapi", DEBUG_STDERR);

	if (!lp_load_global(get_dyn_CONFIGFILE())) {
		TALLOC_FREE(frame);
		fprintf(stderr, "error loading %s\n", get_dyn_CONFIGFILE() );
		return W_ERROR_V(WERR_GEN_FAILURE);
	}

	load_interfaces();
	reopen_logs();

	BlockSignals(True, SIGPIPE);

	lp_ctx = loadparm_init_s3(frame, loadparm_s3_helpers());
	if (lp_ctx == NULL) {
		TALLOC_FREE(frame);
		return W_ERROR_V(WERR_NOT_ENOUGH_MEMORY);
	}

	ret = libnetapi_net_init(context, lp_ctx);
	TALLOC_FREE(frame);
	return ret;
}

/****************************************************************
Create a libnetapi context, for use inside the 'net' binary.

As we know net has already loaded the smb.conf file, and set the debug
level etc, this avoids doing so again (which causes trouble with -d on
the command line).
****************************************************************/

NET_API_STATUS libnetapi_net_init(struct libnetapi_ctx **context,
				  struct loadparm_context *lp_ctx)
{
	NET_API_STATUS status;
	struct libnetapi_ctx *ctx = NULL;
	TALLOC_CTX *frame = talloc_stackframe();

	ctx = talloc_zero(frame, struct libnetapi_ctx);
	if (!ctx) {
		TALLOC_FREE(frame);
		return W_ERROR_V(WERR_NOT_ENOUGH_MEMORY);
	}

	ctx->creds = cli_credentials_init(ctx);
	if (ctx->creds == NULL) {
		TALLOC_FREE(frame);
		return W_ERROR_V(WERR_NOT_ENOUGH_MEMORY);
	}

	BlockSignals(True, SIGPIPE);

	/* Ignore return code, as we might not have a smb.conf */
	(void)cli_credentials_guess(ctx->creds, lp_ctx);

	status = libnetapi_init_private_context(ctx);
	if (status != 0) {
		TALLOC_FREE(frame);
		return status;
	}

	libnetapi_initialized = true;

	talloc_steal(NULL, ctx);
	*context = stat_ctx = ctx;
	
	TALLOC_FREE(frame);
	return NET_API_STATUS_SUCCESS;
}

/****************************************************************
 Return the static libnetapi context
****************************************************************/

NET_API_STATUS libnetapi_getctx(struct libnetapi_ctx **ctx)
{
	if (stat_ctx) {
		*ctx = stat_ctx;
		return NET_API_STATUS_SUCCESS;
	}

	return libnetapi_init(ctx);
}

/****************************************************************
 Free the static libnetapi context
****************************************************************/

NET_API_STATUS libnetapi_free(struct libnetapi_ctx *ctx)
{
	TALLOC_CTX *frame;

	if (!ctx) {
		return NET_API_STATUS_SUCCESS;
	}

	frame = talloc_stackframe();
	libnetapi_samr_free(ctx);

	libnetapi_shutdown_cm(ctx);

	gfree_loadparm();
	gfree_charcnv();
	gfree_interfaces();

	secrets_shutdown();

	netlogon_creds_cli_close_global_db();

	if (ctx == stat_ctx) {
		stat_ctx = NULL;
	}
	TALLOC_FREE(ctx);

	gfree_debugsyms();
	talloc_free(frame);

	return NET_API_STATUS_SUCCESS;
}

/****************************************************************
 Override the current log level for libnetapi
****************************************************************/

NET_API_STATUS libnetapi_set_debuglevel(struct libnetapi_ctx *ctx,
					const char *debuglevel)
{
	TALLOC_CTX *frame = talloc_stackframe();
	ctx->debuglevel = talloc_strdup(ctx, debuglevel);
	
	if (!lp_set_cmdline("log level", debuglevel)) {
		TALLOC_FREE(frame);
		return W_ERROR_V(WERR_GEN_FAILURE);
	}
	TALLOC_FREE(frame);
	return NET_API_STATUS_SUCCESS;
}

/****************************************************************
****************************************************************/

NET_API_STATUS libnetapi_set_logfile(struct libnetapi_ctx *ctx,
				     const char *logfile)
{
	TALLOC_CTX *frame = talloc_stackframe();
	ctx->logfile = talloc_strdup(ctx, logfile);

	if (!lp_set_cmdline("log file", logfile)) {
		TALLOC_FREE(frame);
		return W_ERROR_V(WERR_GEN_FAILURE);
	}
	debug_set_logfile(logfile);
	setup_logging("libnetapi", DEBUG_FILE);
	TALLOC_FREE(frame);
	return NET_API_STATUS_SUCCESS;
}

/****************************************************************
****************************************************************/

NET_API_STATUS libnetapi_get_debuglevel(struct libnetapi_ctx *ctx,
					char **debuglevel)
{
	*debuglevel = ctx->debuglevel;
	return NET_API_STATUS_SUCCESS;
}

/****************************************************************
****************************************************************/

/**
 * @brief Get the username of the libnet context
 *
 * @param[in]  ctx      The netapi context
 *
 * @param[in]  username A pointer to hold the username.
 *
 * @return 0 on success, an werror code otherwise.
 */
NET_API_STATUS libnetapi_get_username(struct libnetapi_ctx *ctx,
				      const char **username)
{
	if (ctx == NULL) {
		return W_ERROR_V(WERR_INVALID_PARAMETER);
	}

	if (username != NULL) {
		*username = cli_credentials_get_username(ctx->creds);
	}

	return NET_API_STATUS_SUCCESS;
}

/**
 * @brief Get the password of the libnet context
 *
 * @param[in]  ctx      The netapi context
 *
 * @param[in]  password A pointer to hold the password.
 *
 * @return 0 on success, an werror code otherwise.
 */
NET_API_STATUS libnetapi_get_password(struct libnetapi_ctx *ctx,
				      const char **password)
{
	if (ctx == NULL) {
		return W_ERROR_V(WERR_INVALID_PARAMETER);
	}

	if (password != NULL) {
		*password = cli_credentials_get_password(ctx->creds);
	}

	return NET_API_STATUS_SUCCESS;
}

NET_API_STATUS libnetapi_set_username(struct libnetapi_ctx *ctx,
				      const char *username)
{
	if (ctx == NULL || username == NULL) {
		return W_ERROR_V(WERR_INVALID_PARAMETER);
	}

	cli_credentials_parse_string(ctx->creds, username, CRED_SPECIFIED);

	return NET_API_STATUS_SUCCESS;
}

NET_API_STATUS libnetapi_set_password(struct libnetapi_ctx *ctx,
				      const char *password)
{
	bool ok;

	if (ctx == NULL || password == NULL) {
		return W_ERROR_V(WERR_INVALID_PARAMETER);
	}

	ok = cli_credentials_set_password(ctx->creds, password, CRED_SPECIFIED);
	if (!ok) {
		return W_ERROR_V(WERR_INTERNAL_ERROR);
	}

	return NET_API_STATUS_SUCCESS;
}

NET_API_STATUS libnetapi_set_workgroup(struct libnetapi_ctx *ctx,
				       const char *workgroup)
{
	bool ok;

	ok = cli_credentials_set_domain(ctx->creds, workgroup, CRED_SPECIFIED);
	if (!ok) {
		return W_ERROR_V(WERR_INTERNAL_ERROR);
	}

	return NET_API_STATUS_SUCCESS;
}

/**
 * @brief Set the cli_credentials to be used in the netapi context
 *
 * @param[in]  ctx    The netapi context
 *
 * @param[in]  creds  The cli_credentials which should be used by netapi.
 *
 * @return 0 on success, an werror code otherwise.
 */
NET_API_STATUS libnetapi_set_creds(struct libnetapi_ctx *ctx,
				   struct cli_credentials *creds)
{
	if (ctx == NULL || creds == NULL) {
		return W_ERROR_V(WERR_INVALID_PARAMETER);
	}

	ctx->creds = creds;

	return NET_API_STATUS_SUCCESS;
}

/****************************************************************
****************************************************************/

NET_API_STATUS libnetapi_set_use_kerberos(struct libnetapi_ctx *ctx)
{
	cli_credentials_set_kerberos_state(ctx->creds,
					   CRED_USE_KERBEROS_REQUIRED,
					   CRED_SPECIFIED);

	return NET_API_STATUS_SUCCESS;
}

/****************************************************************
****************************************************************/

NET_API_STATUS libnetapi_get_use_kerberos(struct libnetapi_ctx *ctx,
					  int *use_kerberos)
{
	enum credentials_use_kerberos creds_use_kerberos;

	*use_kerberos = 0;

	creds_use_kerberos = cli_credentials_get_kerberos_state(ctx->creds);
	if (creds_use_kerberos > CRED_USE_KERBEROS_DESIRED) {
		*use_kerberos = 1;
	}

	return NET_API_STATUS_SUCCESS;
}

/****************************************************************
****************************************************************/

NET_API_STATUS libnetapi_set_use_ccache(struct libnetapi_ctx *ctx)
{
	uint32_t gensec_features;

	gensec_features = cli_credentials_get_gensec_features(ctx->creds);
	gensec_features |= GENSEC_FEATURE_NTLM_CCACHE;
	cli_credentials_set_gensec_features(ctx->creds,
					    gensec_features,
					    CRED_SPECIFIED);

	return NET_API_STATUS_SUCCESS;
}

/****************************************************************
Return a libnetapi error as a string, caller must free with NetApiBufferFree
****************************************************************/

char *libnetapi_errstr(NET_API_STATUS status)
{
	TALLOC_CTX *frame = talloc_stackframe();
	char *ret;
	if (status & 0xc0000000) {
		ret = talloc_strdup(NULL, 
				     get_friendly_nt_error_msg(NT_STATUS(status)));
	} else {
		ret = talloc_strdup(NULL,
				    get_friendly_werror_msg(W_ERROR(status)));
	}
	TALLOC_FREE(frame);
	return ret;
}

/****************************************************************
****************************************************************/

NET_API_STATUS libnetapi_set_error_string(struct libnetapi_ctx *ctx,
					  const char *format, ...)
{
	va_list args;

	TALLOC_FREE(ctx->error_string);

	va_start(args, format);
	ctx->error_string = talloc_vasprintf(ctx, format, args);
	va_end(args);

	if (!ctx->error_string) {
		return W_ERROR_V(WERR_NOT_ENOUGH_MEMORY);
	}
	return NET_API_STATUS_SUCCESS;
}

/****************************************************************
Return a libnetapi_errstr(), caller must free with NetApiBufferFree
****************************************************************/

char *libnetapi_get_error_string(struct libnetapi_ctx *ctx,
				       NET_API_STATUS status_in)
{
	NET_API_STATUS status;
	struct libnetapi_ctx *tmp_ctx = ctx;

	if (!tmp_ctx) {
		status = libnetapi_getctx(&tmp_ctx);
		if (status != 0) {
			return NULL;
		}
	}

	if (tmp_ctx->error_string) {
		return talloc_strdup(NULL, tmp_ctx->error_string);
	}

	return libnetapi_errstr(status_in);
}

/****************************************************************
****************************************************************/

NET_API_STATUS NetApiBufferAllocate(uint32_t byte_count,
				    void **buffer)
{
	void *buf = NULL;

	if (!buffer) {
		return W_ERROR_V(WERR_INSUFFICIENT_BUFFER);
	}

	if (byte_count == 0) {
		goto done;
	}

	buf = talloc_size(NULL, byte_count);
	if (!buf) {
		return W_ERROR_V(WERR_NOT_ENOUGH_MEMORY);
	}

 done:
	*buffer = buf;

	return NET_API_STATUS_SUCCESS;
}

/****************************************************************
****************************************************************/

NET_API_STATUS NetApiBufferFree(void *buffer)
{
	if (!buffer) {
		return W_ERROR_V(WERR_INSUFFICIENT_BUFFER);
	}

	talloc_free(buffer);

	return NET_API_STATUS_SUCCESS;
}
