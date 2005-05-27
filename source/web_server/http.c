/* 
   Unix SMB/CIFS implementation.

   http handling code

   Copyright (C) Andrew Tridgell 2005
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "smbd/service_task.h"
#include "web_server/web_server.h"
#include "smbd/service_stream.h"
#include "lib/events/events.h"
#include "system/filesys.h"
#include "system/iconv.h"
#include "system/time.h"
#include "web_server/esp/esp.h"
#include "dlinklist.h"

#define SWAT_SESSION_KEY "_swat_session_"

/*
  context for long term storage in the web server, to support session[]
  and application[] data. Stored in task->private.
*/
struct esp_data {
	struct session_data {
		struct session_data *next, *prev;
		struct esp_data *edata;
		const char *id;
		struct MprVar *data;
		struct timed_event *te;
		int lifetime;
	} *sessions;
	struct MprVar *application_data;
};

/* state of the esp subsystem for a specific request */
struct esp_state {
	struct websrv_context *web;
	struct EspRequest *req;
	struct MprVar variables[ESP_OBJ_MAX];
	struct session_data *session;
};

/* destroy a esp session */
static int esp_destructor(void *ptr)
{
	struct esp_state *esp = talloc_get_type(ptr, struct esp_state);

	if (esp->req) {
		espDestroyRequest(esp->req);
	}
	return 0;
}

/*
  output the http headers
*/
static void http_output_headers(struct websrv_context *web)
{
	int i;
	char *s;
	DATA_BLOB b;
	const char *response_string = "Unknown Code";
	const struct {
		unsigned code;
		const char *response_string;
	} codes[] = {
		{ 200, "OK" },
		{ 301, "Moved" },
		{ 302, "Found" },
		{ 303, "Method" },
		{ 304, "Not Modified" },
		{ 400, "Bad request" },
		{ 401, "Unauthorized" },
		{ 403, "Forbidden" },
		{ 404, "Not Found" },
		{ 500, "Internal Server Error" },
		{ 501, "Not implemented" }
	};
	for (i=0;i<ARRAY_SIZE(codes);i++) {
		if (codes[i].code == web->output.response_code) {
			response_string = codes[i].response_string;
		}
	}

	if (web->output.headers == NULL) return;
	s = talloc_asprintf(web, "HTTP/1.0 %u %s\r\n", 
			    web->output.response_code, response_string);
	if (s == NULL) return;
	for (i=0;web->output.headers[i];i++) {
		s = talloc_asprintf_append(s, "%s\r\n", web->output.headers[i]);
	}
	s = talloc_asprintf_append(s, "\r\n");
	if (s == NULL) return;

	b = web->output.content;
	web->output.content.data = s;
	web->output.content.length = strlen(s);
	data_blob_append(web, &web->output.content, b.data, b.length);
	data_blob_free(&b);
}

/*
  return the local path for a URL
*/
static const char *http_local_path(struct websrv_context *web, const char *url)
{
	int i;
	char *path;

	/* check that the url is OK */
	if (url[0] != '/') return NULL;

	for (i=0;url[i];i++) {
		if ((!isalnum(url[i]) && !strchr("./", url[i])) ||
		    (url[i] == '.' && strchr("/.", url[i+1]))) {
			return NULL;
		}
	}

	path = talloc_asprintf(web, "%s/%s", lp_swat_directory(), url+1);
	if (path == NULL) return NULL;

	if (directory_exist(path)) {
		path = talloc_asprintf_append(path, "/index.esp");
	}
	return path;
}

/*
  called when esp wants to read a file to support include() calls
*/
static int http_readFile(EspHandle handle, char **buf, int *len, const char *path)
{
	struct websrv_context *web = talloc_get_type(handle, struct websrv_context);
	int fd = -1;
	struct stat st;
	*buf = NULL;

	path = http_local_path(web, path);
	if (path == NULL) goto failed;

	fd = open(path, O_RDONLY);
	if (fd == -1 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) goto failed;

	*buf = talloc_size(handle, st.st_size+1);
	if (*buf == NULL) goto failed;

	if (read(fd, *buf, st.st_size) != st.st_size) goto failed;

	(*buf)[st.st_size] = 0;

	close(fd);
	*len = st.st_size;
	return 0;

failed:
	if (fd != -1) close(fd);
	talloc_free(*buf);
	*buf = NULL;
	return -1;
}

/*
  called when esp wants to find the real path of a file
*/
static int http_mapToStorage(EspHandle handle, char *path, int len, const char *uri, int flags)
{
	if (uri == NULL || strlen(uri) >= len) return -1;
	strncpy(path, uri, len);
	return 0;
}

/*
  called when esp wants to output something
*/
static int http_writeBlock(EspHandle handle, char *buf, int size)
{
	struct websrv_context *web = talloc_get_type(handle, struct websrv_context);
	NTSTATUS status;
	status = data_blob_append(web, &web->output.content, buf, size);
	if (!NT_STATUS_IS_OK(status)) return -1;
	return size;
}


/*
  set a http header
*/
static void http_setHeader(EspHandle handle, const char *value, bool allowMultiple)
{
	struct websrv_context *web = talloc_get_type(handle, struct websrv_context);
	char *p = strchr(value, ':');

	if (p && !allowMultiple && web->output.headers) {
		int i;
		for (i=0;web->output.headers[i];i++) {
			if (strncmp(web->output.headers[i], value, (p+1)-value) == 0) {
				web->output.headers[i] = talloc_strdup(web, value);
				return;
			}
		}
	}

	web->output.headers = str_list_add(web->output.headers, value);
	talloc_steal(web, web->output.headers);
}

/*
  set a http response code
*/
static void http_setResponseCode(EspHandle handle, int code)
{
	struct websrv_context *web = talloc_get_type(handle, struct websrv_context);
	web->output.response_code = code;
}

/*
  redirect to another web page
 */
static void http_redirect(EspHandle handle, int code, char *url)
{
	struct websrv_context *web = talloc_get_type(handle, struct websrv_context);
	const char *host = web->input.host;
	
	/* form the full url, unless it already looks like a url */
	if (strchr(url, ':') == NULL) {
		if (host == NULL) {
			host = talloc_asprintf(web, "%s:%u",
					       socket_get_my_addr(web->conn->socket, web),
					       socket_get_my_port(web->conn->socket));
		}
		if (host == NULL) goto internal_error;
		if (url[0] != '/') {
			char *p = strrchr(web->input.url, '/');
			if (p == web->input.url) {
				url = talloc_asprintf(web, "http://%s/%s", host, url);
			} else {
				int dirlen = p - web->input.url;
				url = talloc_asprintf(web, "http://%s%*.*s/%s",
						      host, 
						      dirlen, dirlen, web->input.url,
						      url);
			}
			if (url == NULL) goto internal_error;
		}
	}

	http_setHeader(handle, talloc_asprintf(web, "Location: %s", url), 0);

	/* make sure we give a valid redirect code */
	if (code >= 300 && code < 400) {
		http_setResponseCode(handle, code);
	} else {
		http_setResponseCode(handle, 302);
	}
	return;

internal_error:
	http_error(web, 500, "Internal server error");
}


/*
  setup a cookie
*/
static void http_setCookie(EspHandle handle, const char *name, const char *value, 
			   int lifetime, const char *path, bool secure)
{
	struct websrv_context *web = talloc_get_type(handle, struct websrv_context);
	char *buf;
	
	if (lifetime > 0) {
		buf = talloc_asprintf(web, "Set-Cookie: %s=%s; path=%s; Expires=%s; %s",
				      name, value, path?path:"/", 
				      http_timestring(web, time(NULL)+lifetime),
				      secure?"secure":"");
	} else {
		buf = talloc_asprintf(web, "Set-Cookie: %s=%s; path=%s; %s",
				      name, value, path?path:"/", 
				      secure?"secure":"");
	}
	http_setHeader(handle, "Cache-control: no-cache=\"set-cookie\"", 0);
	http_setHeader(handle, buf, 0);
	talloc_free(buf);
}

/*
  return the session id
*/
static const char *http_getSessionId(EspHandle handle)
{
	struct websrv_context *web = talloc_get_type(handle, struct websrv_context);
	return web->session->id;
}

/*
  setup a session
*/
static void http_createSession(EspHandle handle, int timeout)
{
	struct websrv_context *web = talloc_get_type(handle, struct websrv_context);
	if (web->session) {
		web->session->lifetime = timeout;
		http_setCookie(web, SWAT_SESSION_KEY, web->session->id, 
			       web->session->lifetime, "/", 0);
	}
}

/*
  destroy a session
*/
static void http_destroySession(EspHandle handle)
{
	struct websrv_context *web = talloc_get_type(handle, struct websrv_context);
	talloc_free(web->session);
	web->session = NULL;
}


/*
  setup for a raw http level error
*/
void http_error(struct websrv_context *web, int code, const char *info)
{
	char *s;
	s = talloc_asprintf(web,"<HTML><HEAD><TITLE>Error %u</TITLE></HEAD><BODY><H1>Error %u</H1>%s<p></BODY></HTML>\r\n\r\n", 
			    code, code, info);
	if (s == NULL) {
		stream_terminate_connection(web->conn, "http_error: out of memory");
		return;
	}
	http_writeBlock(web, s, strlen(s));
	http_setResponseCode(web, code);
	http_output_headers(web);
	EVENT_FD_NOT_READABLE(web->conn->event.fde);
	EVENT_FD_WRITEABLE(web->conn->event.fde);
}

/*
  map a unix error code to a http error
*/
void http_error_unix(struct websrv_context *web, const char *info)
{
	int code = 500;
	switch (errno) {
	case ENOENT:
	case EISDIR:
		code = 404;
		break;
	case EACCES:
		code = 403;
		break;
	}
	info = talloc_asprintf(web, "%s<p>%s<p>\n", info, strerror(errno));
	http_error(web, code, info);
}


/*
  a simple file request
*/
static void http_simple_request(struct websrv_context *web)
{
	const char *url = web->input.url;
	const char *path;
	struct stat st;

	path = http_local_path(web, url);
	if (path == NULL) goto invalid;

	/* looks ok */
	web->output.fd = open(path, O_RDONLY);
	if (web->output.fd == -1) {
		http_error_unix(web, path);
		return;
	}

	if (fstat(web->output.fd, &st) != 0 || !S_ISREG(st.st_mode)) {
		close(web->output.fd);
		goto invalid;
	}

	http_output_headers(web);
	EVENT_FD_WRITEABLE(web->conn->event.fde);
	return;

invalid:
	http_error(web, 400, "Malformed URL");
}

/*
  setup the standard ESP arrays
*/
static void http_setup_arrays(struct esp_state *esp)
{
	struct websrv_context *web = esp->web;
	struct EspRequest *req = esp->req;
	char *p;

#define SETVAR(type, name, value) do { \
		const char *v = value; \
		if (v) espSetStringVar(req, type, name, v); \
} while (0)

	SETVAR(ESP_REQUEST_OBJ, "CONTENT_LENGTH", 
	       talloc_asprintf(esp, "%u", web->input.content_length));
	SETVAR(ESP_REQUEST_OBJ, "QUERY_STRING", web->input.query_string);
	SETVAR(ESP_REQUEST_OBJ, "REQUEST_METHOD", web->input.post_request?"POST":"GET");
	SETVAR(ESP_REQUEST_OBJ, "REQUEST_URI", web->input.url);
	p = strrchr(web->input.url, '/');
	SETVAR(ESP_REQUEST_OBJ, "SCRIPT_NAME", p+1);
	p = socket_get_peer_name(web->conn->socket, esp);
	SETVAR(ESP_REQUEST_OBJ, "REMOTE_HOST", p);
	SETVAR(ESP_REQUEST_OBJ, "REMOTE_ADDR", p);
	SETVAR(ESP_REQUEST_OBJ, "REMOTE_USER", "");
	SETVAR(ESP_REQUEST_OBJ, "CONTENT_TYPE", web->input.content_type);
	if (web->session) {
		SETVAR(ESP_REQUEST_OBJ, "SESSION_ID", web->session->id);
	}

	SETVAR(ESP_HEADERS_OBJ, "HTT_REFERER", web->input.referer);
	SETVAR(ESP_HEADERS_OBJ, "HOST", web->input.host);
	SETVAR(ESP_HEADERS_OBJ, "ACCEPT_ENCODING", web->input.accept_encoding);
	SETVAR(ESP_HEADERS_OBJ, "ACCEPT_LANGUAGE", web->input.accept_language);
	SETVAR(ESP_HEADERS_OBJ, "ACCEPT_CHARSET", web->input.accept_charset);
	SETVAR(ESP_HEADERS_OBJ, "COOKIE", web->input.cookie);
	SETVAR(ESP_HEADERS_OBJ, "USER_AGENT", web->input.user_agent);

	SETVAR(ESP_SERVER_OBJ, "SERVER_ADDR", socket_get_my_addr(web->conn->socket, esp));
	SETVAR(ESP_SERVER_OBJ, "SERVER_NAME", socket_get_my_addr(web->conn->socket, esp));
	SETVAR(ESP_SERVER_OBJ, "SERVER_HOST", socket_get_my_addr(web->conn->socket, esp));
	SETVAR(ESP_SERVER_OBJ, "DOCUMENT_ROOT", lp_swat_directory());
	SETVAR(ESP_SERVER_OBJ, "SERVER_PORT", 
	       talloc_asprintf(esp, "%u", socket_get_my_port(web->conn->socket)));
	SETVAR(ESP_SERVER_OBJ, "SERVER_PROTOCOL", "http");
	SETVAR(ESP_SERVER_OBJ, "SERVER_SOFTWARE", "SWAT");
	SETVAR(ESP_SERVER_OBJ, "GATEWAY_INTERFACE", "CGI/1.1");
	SETVAR(ESP_REQUEST_OBJ, "SCRIPT_FILENAME", web->input.url);
}


/*
  process a esp request
*/
static void esp_request(struct esp_state *esp)
{
	struct websrv_context *web = esp->web;
	const char *url = web->input.url;
	size_t size;
	int res;
	char *emsg = NULL, *buf;

	http_setup_arrays(esp);

	if (http_readFile(web, &buf, &size, url) != 0) {
		http_error_unix(web, url);
		return;
	}

	res = espProcessRequest(esp->req, url, buf, &emsg);
	if (res != 0 && emsg) {
		http_writeBlock(web, emsg, strlen(emsg));
	}
	talloc_free(buf);
	http_output_headers(web);
	EVENT_FD_WRITEABLE(web->conn->event.fde);
}


/* 
   handling of + and % escapes in http variables 
*/
static const char *http_unescape(TALLOC_CTX *mem_ctx, const char *p)
{
	char *s0 = talloc_strdup(mem_ctx, p);
	char *s = s0;
	if (s == NULL) return NULL;

	while (*s) {
		unsigned v;
		if (*s == '+') *s = ' ';
		if (*s == '%' && sscanf(s+1, "%02x", &v) == 1) {
			*s = (char)v;
			memmove(s+1, s+3, strlen(s+3)+1);
		}
		s++;
	}

	return s0;
}

/*
  set a form or GET variable
*/
static void esp_putvar(struct esp_state *esp, const char *var, const char *value)
{
	espSetStringVar(esp->req, ESP_FORM_OBJ, 
			http_unescape(esp, var),
			http_unescape(esp, value));
}


/*
  parse the variables in a POST style request
*/
static NTSTATUS http_parse_post(struct esp_state *esp)
{
	DATA_BLOB b = esp->web->input.partial;

	while (b.length) {
		char *p, *line;
		size_t len;

		p = memchr(b.data, '&', b.length);
		if (p == NULL) {
			len = b.length;
		} else {
			len = p - (char *)b.data;
		}
		line = talloc_strndup(esp, b.data, len);
		NT_STATUS_HAVE_NO_MEMORY(line);
				     
		p = strchr(line,'=');
		if (p) {
			*p = 0;
			esp_putvar(esp, line, p+1);
		}
		talloc_free(line);
		b.length -= len;
		b.data += len;
		if (b.length > 0) {
			b.length--;
			b.data++;
		}
	}

	return NT_STATUS_OK;
}

/*
  parse the variables in a GET style request
*/
static NTSTATUS http_parse_get(struct esp_state *esp)
{
	struct websrv_context *web = esp->web;
	char *p, *s, *tok;
	char *pp;

	p = strchr(web->input.url, '?');
	web->input.query_string = p+1;
	*p = 0;

	s = talloc_strdup(esp, esp->web->input.query_string);
	NT_STATUS_HAVE_NO_MEMORY(s);

	for (tok=strtok_r(s,"&;", &pp);tok;tok=strtok_r(NULL,"&;", &pp)) {
		p = strchr(tok,'=');
		if (p) {
			*p = 0;
			esp_putvar(esp, tok, p+1);
		}
	}
	return NT_STATUS_OK;
}

/*
  called when a session times out
*/
static void session_timeout(struct event_context *ev, struct timed_event *te, 
			    struct timeval t, void *private)
{
	struct session_data *s = talloc_get_type(private, struct session_data);
	talloc_free(s);
}

/*
  destroy a session
 */
static int session_destructor(void *ptr)
{
	struct session_data *s = talloc_get_type(ptr, struct session_data);
	DLIST_REMOVE(s->edata->sessions, s);
	return 0;
}

/*
  setup the session for this request
*/
static void http_setup_session(struct esp_state *esp)
{
	const char *session_key = SWAT_SESSION_KEY;
	char *p;
	const char *cookie = esp->web->input.cookie;
	const char *key = NULL;
	struct esp_data *edata = talloc_get_type(esp->web->task->private, struct esp_data);
	struct session_data *s;

	/* look for our session key */
	if (cookie && (p = strstr(cookie, session_key)) && 
	    p[strlen(session_key)] == '=') {
		p += strlen(session_key)+1;
		key = talloc_strndup(esp, p, strcspn(p, ";"));
	}

	if (key == NULL) {
		key = generate_random_str_list(esp, 64, "0123456789");
	}

	/* try to find this session in the existing session list */
	for (s=edata->sessions;s;s=s->next) {
		if (strcmp(key, s->id) == 0) break;
	}

	if (s == NULL) {
		/* create a new session */
		s = talloc_zero(edata, struct session_data);
		s->id = talloc_steal(s, key);
		s->data = NULL;
		s->te = NULL;
		s->edata = edata;
		s->lifetime = lp_parm_int(-1, "http", "sessiontimeout", 300);
		DLIST_ADD(edata->sessions, s);
		talloc_set_destructor(s, session_destructor);
	}

	http_setCookie(esp->web, session_key, key, s->lifetime, "/", 0);

	if (s->data) {
		mprCopyVar(&esp->variables[ESP_SESSION_OBJ], s->data, MPR_DEEP_COPY);
	}

	esp->web->session = s;
}


/* callbacks for esp processing */
static const struct Esp esp_control = {
	.maxScriptSize   = 60000,
	.writeBlock      = http_writeBlock,
	.setHeader       = http_setHeader,
	.redirect        = http_redirect,
	.setResponseCode = http_setResponseCode,
	.readFile        = http_readFile,
	.mapToStorage    = http_mapToStorage,
	.setCookie       = http_setCookie,
	.createSession   = http_createSession,
	.destroySession  = http_destroySession,
	.getSessionId    = http_getSessionId
};

/*
  process a complete http request
*/
void http_process_input(struct websrv_context *web)
{
	NTSTATUS status;
	struct esp_state *esp;
	struct esp_data *edata = talloc_get_type(web->task->private, struct esp_data);
	char *p;
	int i;
	const char *file_type = NULL;
	BOOL esp_enable = False;
	const struct {
		const char *extension;
		const char *mime_type;
		BOOL esp_enable;
	} mime_types[] = {
		{"gif",  "image/gif"},
		{"png",  "image/png"},
		{"jpg",  "image/jpeg"},
		{"txt",  "text/plain"},
		{"ico",  "image/x-icon"},
		{"esp",  "text/html", True}
	};

	esp = talloc_zero(web, struct esp_state);
	if (esp == NULL) goto internal_error;

	esp->web = web;

	mprSetCtx(esp);

	if (espOpen(&esp_control) != 0) goto internal_error;

	for (i=0;i<ARRAY_SIZE(esp->variables);i++) {
		esp->variables[i] = mprCreateUndefinedVar();
	}
	esp->variables[ESP_HEADERS_OBJ]     = mprCreateObjVar("headers", ESP_HASH_SIZE);
	esp->variables[ESP_FORM_OBJ]        = mprCreateObjVar("form", ESP_HASH_SIZE);
	esp->variables[ESP_APPLICATION_OBJ] = mprCreateObjVar("application", ESP_HASH_SIZE);
	esp->variables[ESP_COOKIES_OBJ]     = mprCreateObjVar("cookies", ESP_HASH_SIZE);
	esp->variables[ESP_FILES_OBJ]       = mprCreateObjVar("files", ESP_HASH_SIZE);
	esp->variables[ESP_REQUEST_OBJ]     = mprCreateObjVar("request", ESP_HASH_SIZE);
	esp->variables[ESP_SERVER_OBJ]      = mprCreateObjVar("server", ESP_HASH_SIZE);
	esp->variables[ESP_SESSION_OBJ]     = mprCreateObjVar("session", ESP_HASH_SIZE);

	if (edata->application_data) {
		mprCopyVar(&esp->variables[ESP_APPLICATION_OBJ], 
			   edata->application_data, MPR_DEEP_COPY);
	}

	http_setup_session(esp);

	talloc_set_destructor(esp, esp_destructor);

	esp->req = espCreateRequest(web, web->input.url, esp->variables);
	if (esp->req == NULL) goto internal_error;

	if (web->input.url == NULL) {
		http_error(web, 400, "You must specify a GET or POST request");
		return;
	}
	
	/* parse any form or get variables */
	if (web->input.post_request) {
		status = http_parse_post(esp);
		if (!NT_STATUS_IS_OK(status)) {
			http_error(web, 400, "Malformed POST data");
			return;
		}
	} else if (strchr(web->input.url, '?')) {
		status = http_parse_get(esp);
		if (!NT_STATUS_IS_OK(status)) {
			http_error(web, 400, "Malformed GET data");
			return;
		}
	}

	/* work out the mime type */
	p = strrchr(web->input.url, '.');
	for (i=0;p && i<ARRAY_SIZE(mime_types);i++) {
		if (strcmp(mime_types[i].extension, p+1) == 0) {
			file_type = mime_types[i].mime_type;
			esp_enable = mime_types[i].esp_enable;
		}
	}
	if (file_type == NULL) {
		file_type = "text/html";
	}

	/* setup basic headers */
	http_setResponseCode(web, 200);
	http_setHeader(web, talloc_asprintf(esp, "Date: %s", 
					    http_timestring(esp, time(NULL))), 0);
	http_setHeader(web, "Server: Samba", 0);
	http_setHeader(web, "Connection: close", 0);
	http_setHeader(web, talloc_asprintf(esp, "Content-Type: %s", file_type), 0);

	if (esp_enable) {
		esp_request(esp);
	} else {
		http_simple_request(web);
	}

	/* copy any application data to long term storage in edata */
	talloc_free(edata->application_data);
	edata->application_data = talloc_zero(edata, struct MprVar);
	mprSetCtx(edata->application_data);
	mprCopyVar(edata->application_data, &esp->variables[ESP_APPLICATION_OBJ], MPR_DEEP_COPY);

	/* copy any session data */
	if (web->session) {
		talloc_free(web->session->data);
		web->session->data = talloc_zero(web->session, struct MprVar);
		mprSetCtx(web->session->data);
		if (esp->variables[ESP_SESSION_OBJ].properties == NULL ||
		    esp->variables[ESP_SESSION_OBJ].properties[0].numItems == 0) {
			talloc_free(web->session);
			web->session = NULL;
		} else {
			mprCopyVar(web->session->data, &esp->variables[ESP_SESSION_OBJ], 
				   MPR_DEEP_COPY);
			/* setup the timeout for the session data */
			talloc_free(web->session->te);
			web->session->te = event_add_timed(web->conn->event.ctx, web->session, 
							   timeval_current_ofs(web->session->lifetime, 0), 
							   session_timeout, web->session);
		}
	}

	talloc_free(esp);
	return;
	
internal_error:
	talloc_free(esp);
	http_error(web, 500, "Internal server error");
}


/*
  parse one line of header input
*/
NTSTATUS http_parse_header(struct websrv_context *web, const char *line)
{
	if (line[0] == 0) {
		web->input.end_of_headers = True;
	} else if (strncasecmp(line,"GET ", 4)==0) {
		web->input.url = talloc_strndup(web, &line[4], strcspn(&line[4], " \t"));
	} else if (strncasecmp(line,"POST ", 5)==0) {
		web->input.post_request = True;
		web->input.url = talloc_strndup(web, &line[5], strcspn(&line[5], " \t"));
	} else if (strchr(line, ':') == NULL) {
		http_error(web, 400, "This server only accepts GET and POST requests");
		return NT_STATUS_INVALID_PARAMETER;
	} else if (strncasecmp(line,"Content-Length: ", 16)==0) {
		web->input.content_length = strtoul(&line[16], NULL, 10);
	} else {
#define PULL_HEADER(v, s) do { \
	if (strncmp(line, s, strlen(s)) == 0) { \
		web->input.v = talloc_strdup(web, &line[strlen(s)]); \
		return NT_STATUS_OK; \
	} \
} while (0)
		PULL_HEADER(content_type, "Content-Type: ");
		PULL_HEADER(user_agent, "User-Agent: ");
		PULL_HEADER(referer, "Referer: ");
		PULL_HEADER(host, "Host: ");
		PULL_HEADER(accept_encoding, "Accept-Encoding: ");
		PULL_HEADER(accept_language, "Accept-Language: ");
		PULL_HEADER(accept_charset, "Accept-Charset: ");
		PULL_HEADER(cookie, "Cookie: ");
	}

	/* ignore all other headers for now */
	return NT_STATUS_OK;
}


/*
  setup the esp processor - called at task initialisation
*/
NTSTATUS http_setup_esp(struct task_server *task)
{
	struct esp_data *edata;

	edata = talloc(task, struct esp_data);
	NT_STATUS_HAVE_NO_MEMORY(edata);

	task->private = edata;
	edata->sessions = NULL;
	edata->application_data = NULL;

	return NT_STATUS_OK;
}
