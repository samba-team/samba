#include "includes.h"
#include "version.h"
#include "libcli/libcli.h"
#include "lib/events/events.h"
#include "libcli/resolve/resolve.h"
#include "param/param.h"
#include "libcli/raw/raw_proto.h"
#include "libcli/http/http.h"
#include "credentials.h"
#include "util/tevent_ntstatus.h"
#include "lib/tls/tls.h"
#include "lib/cmdline/cmdline.h"


struct http_client_info {
	struct http_conn *http_conn;
	uint16_t server_port;
	const char *server_addr;
	struct tstream_tls_params *tls_params;
	struct cli_credentials *creds;
	struct loadparm_context *lp_ctx;
	const char *uri;
};

static bool send_http_request(TALLOC_CTX *mem_ctx,
	struct tevent_context *ev_ctx,
	struct http_client_info* es,
	size_t response_size,
	NTSTATUS *pstatus)
{
	struct http_request *http_req = NULL;
	struct tevent_req *req = NULL;
	char *uri = NULL;
	struct http_request *http_response = NULL;
	NTSTATUS status;

	http_req = talloc_zero(mem_ctx, struct http_request);
	if (!http_req) {
		DBG_ERR("no memory\n");
		return false;
	}

	uri = talloc_strdup(mem_ctx, es->uri);

	http_req->type = HTTP_REQ_POST;
	http_req->uri = uri;
	http_req->body = data_blob_null;
	http_req->major = '1';
	http_req->minor = '1';

	http_add_header(mem_ctx, &http_req->headers,
			"User-Agent", "Samba/http_test");
	http_add_header(mem_ctx, &http_req->headers,
			"Accept", "*/*");

	req = http_send_auth_request_send(mem_ctx,
				ev_ctx,
				es->http_conn,
				http_req,
				es->creds,
				es->lp_ctx,
				HTTP_AUTH_BASIC);
	if (!tevent_req_set_endtime(req, ev_ctx, timeval_current_ofs(10, 0))) {
		DBG_ERR("Failed to set timeout\n");
		return false;
	}

	if (!tevent_req_poll_ntstatus(req, ev_ctx, pstatus)) {
		DBG_ERR("Failed to connect: %s\n", nt_errstr(*pstatus));
		return false;
	}

	status = http_send_auth_request_recv(req);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Auth request failed: %s\n", nt_errstr(status));
		return false;
	}

	req = http_read_response_send(mem_ctx,
				ev_ctx,
				es->http_conn,
				response_size);
	if (!req) {
		DBG_ERR("no memory\n");
		return false;
	}

	if (!tevent_req_set_endtime(req, ev_ctx, timeval_current_ofs(10, 0))) {
		DBG_ERR("Failed to set timeout\n");
		return false;
	}

	if (!tevent_req_poll_ntstatus(req, ev_ctx, pstatus)) {
		DBG_ERR("Failed to read_resonse: %s\n", nt_errstr(*pstatus));
		return false;
	}

	*pstatus = http_read_response_recv(req, mem_ctx, &http_response);

	if (!NT_STATUS_IS_OK(*pstatus)) {
		DBG_ERR("Failed to receive response: %s\n", nt_errstr(*pstatus));
		return false;
	}
	/* following are not 'hard' errors */
	if (http_response->response_code != 200) {
		fprintf(stdout, "HTTP server response: %u\n",
			http_response->response_code);
		fflush(stdout);
		return false;

	}
	if (http_response->body.length == 0) {
		fprintf(stdout, "unexpected 0 len response\n");
		fflush(stdout);
		return false;
	}
	DBG_ERR("response: len (%d)\n%s\n",
		  (int)http_response->body.length,
		  talloc_strndup(mem_ctx,
				 (char *)http_response->body.data,
				 http_response->body.length));
	fprintf(stdout,"%s", talloc_strndup(mem_ctx,
					    (char *)http_response->body.data,
					    http_response->body.length));
	fflush(stdout);
	return true;
}

int main(int argc, const char *argv[])

{
	TALLOC_CTX *mem_ctx;
	struct tevent_context *ev_ctx;
	int retries = 4;
	int count = 0;
	struct http_client_info *http_info = NULL;
	bool use_tls = false;
	int res;
	NTSTATUS status;
	struct tevent_req *req = NULL;
	bool connected = false;
	poptContext pc;
	const char **const_argv = discard_const_p(const char *, argv);
	int opt;
	bool ok;
	const char *ca_file = NULL;
	int port = 0;
	size_t response_size = 8192000;
	struct cli_credentials *cli_creds;

	struct poptOption long_options[] = {
		POPT_AUTOHELP

		{
			.longName   = "usetls",
			.shortName  = 't',
			.argInfo    = POPT_ARG_NONE,
			.arg        = NULL,
			.val        = 't',
			.descrip    = "Use tls",
			.argDescrip = "enable tls",
		},
		{
			.longName   = "ip-address",
			.shortName  = 'I',
			.argInfo    = POPT_ARG_STRING,
			.arg        = NULL,
			.val        = 'I',
			.descrip    = "Use this IP to connect to",
			.argDescrip = "IP",
		},
		{
			.longName   = "port",
			.shortName  = 'p',
			.argInfo    = POPT_ARG_INT,
			.arg        = &port,
			.val        = 'p',
			.descrip    = "port to connect to",
			.argDescrip = "port",
		},
		{
			.longName   = "cacart",
			.shortName  = 'c',
			.argInfo    = POPT_ARG_STRING,
			.arg        = NULL,
			.val        = 'c',
			.descrip    = "CA certificate to verify peer against",
			.argDescrip = "ca cert",
		},
		{
			.longName   = "uri",
			.shortName  = 'u',
			.argInfo    = POPT_ARG_STRING,
			.arg        = NULL,
			.val        = 'u',
			.descrip    = "uri to send as part of http request",
			.argDescrip = "uri",
		},
		{
			.longName   = "rsize",
			.argInfo    = POPT_ARG_LONG,
			.arg        = &response_size,
			.descrip    = "response size",
		},
		POPT_COMMON_SAMBA
		POPT_COMMON_CREDENTIALS
		POPT_TABLEEND
	};

	mem_ctx = talloc_init("http_test");

	if (!mem_ctx) {
		DBG_ERR("Not enough memory\n");
		res = -1;
		goto done;
	}

	http_info = talloc_zero(mem_ctx, struct http_client_info);

	if (http_info == NULL) {
		DBG_ERR("Not enough memory\n");
		res = -1;
		goto done;
	}

	ok = samba_cmdline_init(mem_ctx,
				SAMBA_CMDLINE_CONFIG_CLIENT,
				false /* require_smbconf */);
	if (!ok) {
		DBG_ERR("Failed to init cmdline parser!\n");
		res = -1;
		goto done;
	}

	pc = samba_popt_get_context(getprogname(),
				    argc,
				    const_argv,
				    long_options,
				    0);
	if (pc == NULL) {
		DBG_ERR("Failed to setup popt context!\n");
		res = -1;
		goto done;
	}

	/* some defaults */

	http_info->server_addr = "localhost";
	http_info->uri = "/_search?pretty";

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
			case 't':
				use_tls = true;
				break;
			case  'c': {
				ca_file = talloc_strdup(mem_ctx,
							poptGetOptArg(pc));
				if (ca_file == NULL) {
					DBG_ERR("Not enough memory\n");
					res = -1;
					goto done;
				}
				break;
			}
			case 'I': {
				http_info->server_addr = talloc_strdup(mem_ctx,
							poptGetOptArg(pc));
				if (http_info->server_addr == NULL) {
					DBG_ERR("Not enough memory\n");
					res = -1;
					goto done;
				}
				break;
			}
			case 'u': {
				http_info->uri = talloc_strdup(mem_ctx,
							poptGetOptArg(pc));
				if (http_info->uri == NULL) {
					DBG_ERR("Not enough memory\n");
					res = -1;
					goto done;
				}
				break;
			}
		}
	}

	if (use_tls && ca_file == NULL) {
		DBG_ERR("No cacert\n");
		res = -1;
		poptPrintUsage(pc, stderr, 0);
		goto done;
	}

	if (!port) {
		port = 8080;
	}
	http_info->server_port = port;

	ev_ctx = s4_event_context_init(mem_ctx);
	if (!ev_ctx) {
		DBG_ERR("Not enough memory\n");
		res = -1;
		goto done;
	}


	cli_creds = samba_cmdline_get_creds();
	if (!cli_credentials_is_anonymous(cli_creds)) {
		http_info->creds = cli_credentials_init(mem_ctx);
		cli_credentials_set_username(
			http_info->creds,
			cli_credentials_get_username(cli_creds),
			CRED_SPECIFIED);
		cli_credentials_set_password(http_info->creds,
			cli_credentials_get_password(cli_creds),
			CRED_SPECIFIED);
	} else {
		DBG_DEBUG("Anonymous creds!!!\n");
		http_info->creds = cli_creds;
	}
	if (http_info->creds == NULL) {
		DBG_ERR("Failed to create creds\n");
		res = -1;
		goto done;
	}
	http_info->lp_ctx = samba_cmdline_get_lp_ctx();

	DBG_ERR("retries = %d/%d, Using server %s, port %d, using tls %s\n",
		count, retries,
		http_info->server_addr,
		http_info->server_port,
		use_tls ? "true" : "false");

	while (count < retries) {
		int error;
		DBG_ERR("Connecting to HTTP [%s] port [%"PRIu16"]%s\n",
			http_info->server_addr, http_info->server_port,
			use_tls ? " with tls" : " without tls");
		if (use_tls) {
			bool system_cas = false;
			const char * const *ca_dirs = NULL;
			const char *crl_file = NULL;
			const char *tls_priority = "NORMAL:-VERS-SSL3.0";
			enum tls_verify_peer_state verify_peer =
				TLS_VERIFY_PEER_CA_ONLY;

			status = tstream_tls_params_client(mem_ctx,
						   system_cas,
						   ca_dirs,
						   ca_file,
						   crl_file,
						   tls_priority,
						   verify_peer,
						   http_info->server_addr,
						   &http_info->tls_params);
			if (!NT_STATUS_IS_OK(status)) {
				DBG_ERR("Failed tstream_tls_params_client - %s\n",
					nt_errstr(status));
				res = -1;
				goto done;
			}
		}

		req = http_connect_send(mem_ctx,
					ev_ctx,
					http_info->server_addr,
					http_info->server_port,
					http_info->creds,
					http_info->tls_params);
		if (!tevent_req_poll_ntstatus(req, ev_ctx, &status)) {
			res = -1;
			goto done;
		}

		error = http_connect_recv(req,
					mem_ctx,
					&http_info->http_conn);
		if (error != 0) {
			count++;
			DBG_ERR("HTTP connection failed retry %d/%d: %s\n", count, retries, strerror(error));
		} else {
			DBG_ERR("HTTP connection succeeded\n");
			connected = true;
			break;
		}
	}

	if (!connected) {
		DBG_ERR("Leaving early\n");
		res = -1;
		goto done;
	}

	if (!send_http_request(mem_ctx, ev_ctx, http_info, response_size, &status)) {
		DBG_ERR("Failure\n");
		res = -1;
		goto done;
	}
	res = 0;
done:
	TALLOC_FREE(mem_ctx);
	return res;
}
