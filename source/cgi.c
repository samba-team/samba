/* 
   some simple CGI helper routines
   Copyright (C) Andrew Tridgell 1997-1998
   
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


#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <pwd.h>

#define MAX_VARIABLES 10000

#ifdef DEBUG_COMMENTS
extern void print_title(char *fmt, ...);
#endif

struct var {
	char *name;
	char *value;
};

static struct var variables[MAX_VARIABLES];
static int num_variables;
static int content_length;
static int request_post;
static int request_get;
static char *query_string;

static void unescape(char *buf)
{
	char *p=buf;

	while ((p=strchr(p,'+')))
		*p = ' ';

	p = buf;

	while (p && *p && (p=strchr(p,'%'))) {
		int c1 = p[1];
		int c2 = p[2];

		if (c1 >= '0' && c1 <= '9')
			c1 = c1 - '0';
		else if (c1 >= 'A' && c1 <= 'F')
			c1 = 10 + c1 - 'A';
		else if (c1 >= 'a' && c1 <= 'f')
			c1 = 10 + c1 - 'a';
		else {p++; continue;}

		if (c2 >= '0' && c2 <= '9')
			c2 = c2 - '0';
		else if (c2 >= 'A' && c2 <= 'F')
			c2 = 10 + c2 - 'A';
		else if (c2 >= 'a' && c2 <= 'f')
			c2 = 10 + c2 - 'a';
		else {p++; continue;}
			
		*p = (c1<<4) | c2;

		memcpy(p+1, p+3, strlen(p+3)+1);
		p++;
	}
}


static char *grab_line(FILE *f, int *cl)
{
	char *ret;
	int i = 0;
	int len = 1024;

	ret = (char *)malloc(len);
	if (!ret) return NULL;
	

	while ((*cl)) {
		int c = fgetc(f);
		(*cl)--;

		if (c == EOF) {
			(*cl) = 0;
			break;
		}
		
		if (c == '\r') continue;

		if (strchr("\n&", c)) break;

		ret[i++] = c;

		if (i == len-1) {
			char *ret2;
			ret2 = (char *)realloc(ret, len*2);
			if (!ret2) return ret;
			len *= 2;
			ret = ret2;
		}
	}
	

	ret[i] = 0;
	return ret;
}

/***************************************************************************
  load all the variables passed to the CGI program. May have multiple variables
  with the same name and the same or different values. Takes a file parameter
  for simulating CGI invocation eg loading saved preferences.
  ***************************************************************************/
void cgi_load_variables(FILE *f1)
{
	FILE *f = f1;
	static char *line;
	char *p, *s, *tok;
	int len;

#ifdef DEBUG_COMMENTS
	char dummy[100]="";
	print_title(dummy);
	printf("<!== Start dump in cgi_load_variables() %s ==>\n",__FILE__);
#endif

	if (!f1) {
		f = stdin;
		if (!content_length) {
			p = getenv("CONTENT_LENGTH");
			len = p?atoi(p):0;
		} else {
			len = content_length;
		}
	} else {
		fseek(f, 0, SEEK_END);
		len = ftell(f);
		fseek(f, 0, SEEK_SET);
	}


	if (len > 0 && 
	    (f1 || request_post ||
	     ((s=getenv("REQUEST_METHOD")) && 
	      strcasecmp(s,"POST")==0))) {
		while (len && (line=grab_line(f, &len))) {
			p = strchr(line,'=');
			if (!p) continue;
			
			*p = 0;
			
			variables[num_variables].name = strdup(line);
			variables[num_variables].value = strdup(p+1);

			free(line);
			
			if (!variables[num_variables].name || 
			    !variables[num_variables].value)
				continue;

			unescape(variables[num_variables].value);
			unescape(variables[num_variables].name);

#ifdef DEBUG_COMMENTS
			printf("<!== POST var %s has value \"%s\"  ==>\n",
			       variables[num_variables].name,
			       variables[num_variables].value);
#endif
			
			num_variables++;
			if (num_variables == MAX_VARIABLES) break;
		}
	}

	if (f1) {
#ifdef DEBUG_COMMENTS
	        printf("<!== End dump in cgi_load_variables() ==>\n"); 
#endif
		return;
	}

	fclose(stdin);

	if ((s=query_string) || (s=getenv("QUERY_STRING"))) {
		for (tok=strtok(s,"&;");tok;tok=strtok(NULL,"&;")) {
			p = strchr(tok,'=');
			if (!p) continue;
			
			*p = 0;
			
			variables[num_variables].name = strdup(tok);
			variables[num_variables].value = strdup(p+1);

			if (!variables[num_variables].name || 
			    !variables[num_variables].value)
				continue;

			unescape(variables[num_variables].value);
			unescape(variables[num_variables].name);

#ifdef DEBUG_COMMENTS
                        printf("<!== Commandline var %s has value \"%s\"  ==>\n",
                               variables[num_variables].name,
                               variables[num_variables].value);
#endif						
			num_variables++;
			if (num_variables == MAX_VARIABLES) break;
		}

	}
#ifdef DEBUG_COMMENTS
        printf("<!== End dump in cgi_load_variables() ==>\n");   
#endif
}


/***************************************************************************
  find a variable passed via CGI
  Doesn't quite do what you think in the case of POST text variables, because
  if they exist they might have a value of "" or even " ", depending on the 
  browser. Also doesn't allow for variables[] containing multiple variables
  with the same name and the same or different values.
  ***************************************************************************/
char *cgi_variable(char *name)
{
	int i;

	for (i=0;i<num_variables;i++)
		if (strcmp(variables[i].name, name) == 0)
			return variables[i].value;
	return NULL;
}

/***************************************************************************
return a particular cgi variable
  ***************************************************************************/
char *cgi_vnum(int i, char **name)
{
	if (i < 0 || i >= num_variables) return NULL;
	*name = variables[i].name;
	return variables[i].value;
}

/***************************************************************************
  return the value of a CGI boolean variable.
  ***************************************************************************/
int cgi_boolean(char *name, int def)
{
	char *p = cgi_variable(name);

	if (!p) return def;

	return strcmp(p, "1") == 0;
}

/***************************************************************************
like strdup() but quotes < > and &
  ***************************************************************************/
char *quotedup(char *s)
{
	int i, n=0;
	int len;
	char *ret;
	char *d;

	if (!s) return strdup("");

	len = strlen(s);

	for (i=0;i<len;i++)
		if (s[i] == '<' || s[i] == '>' || s[i] == '&')
			n++;

	ret = malloc(len + n*6 + 1);

	if (!ret) return NULL;

	d = ret;

	for (i=0;i<len;i++) {
		switch (s[i]) {
		case '<':
			safe_strcpy(d, "&lt;",len + n*6 - (d - ret));
			d += 4;
			break;

		case '>':
			safe_strcpy(d, "&gt;",len + n*6 - (d - ret));
			d += 4;
			break;

		case '&':
			safe_strcpy(d, "&amp;",len + n*6 - (d - ret));
			d += 5;
			break;

		default:
			*d++ = s[i];
		}
	}

	*d = 0;

	return ret;
}


/***************************************************************************
like strdup() but quotes a wide range of characters
  ***************************************************************************/
char *urlquote(char *s)
{
	int i, n=0;
	int len;
	char *ret;
	char *d;
	char *qlist = "\"\n\r'&<> \t+;";

	if (!s) return strdup("");

	len = strlen(s);

	for (i=0;i<len;i++)
		if (strchr(qlist, s[i])) n++;

	ret = malloc(len + n*2 + 1);

	if (!ret) return NULL;

	d = ret;

	for (i=0;i<len;i++) {
		if (strchr(qlist,s[i])) {
			slprintf(d, len + n*2 - (d - ret), "%%%02X", (int)s[i]);
			d += 3;
		} else {
			*d++ = s[i];
		}
	}

	*d = 0;

	return ret;
}


/***************************************************************************
like strdup() but quotes " characters
  ***************************************************************************/
char *quotequotes(char *s)
{
	int i, n=0;
	int len;
	char *ret;
	char *d;

	if (!s) return strdup("");

	len = strlen(s);

	for (i=0;i<len;i++)
		if (s[i] == '"')
			n++;

	ret = malloc(len + n*6 + 1);

	if (!ret) return NULL;

	d = ret;

	for (i=0;i<len;i++) {
		switch (s[i]) {
		case '"':
			safe_strcpy(d, "&quot;", len + n*6 - (d - ret));
			d += 6;
			break;

		default:
			*d++ = s[i];
		}
	}

	*d = 0;

	return ret;
}


/***************************************************************************
quote spaces in a buffer
  ***************************************************************************/
void quote_spaces(char *buf)
{
	while (*buf) {
		if (*buf == ' ') *buf = '+';
		buf++;
	}
}



/***************************************************************************
tell a browser about a fatal error in the http processing
  ***************************************************************************/
static void cgi_setup_error(char *err, char *header, char *info)
{
	printf("HTTP/1.1 %s\r\n%sConnection: close\r\nContent-Type: text/html\r\n\r\n<HTML><HEAD><TITLE>%s</TITLE></HEAD><BODY><H1>%s</H1>%s<p></BODY></HTML>\r\n", err, header, err, err, info);
	exit(0);
}


/***************************************************************************
decode a base64 string in-place - simple and slow algorithm
  ***************************************************************************/
static void base64_decode(char *s)
{
	char *b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	int bit_offset, byte_offset, idx, i;
	unsigned char *d = (unsigned char *)s;
	char *p;

	i=0;

	while (*s && (p=strchr(b64,*s))) {
		idx = (int)(p - b64);
		byte_offset = (i*6)/8;
		bit_offset = (i*6)%8;
		d[byte_offset] &= ~((1<<(8-bit_offset))-1);
		if (bit_offset < 3) {
			d[byte_offset] |= (idx << (2-bit_offset));
		} else {
			d[byte_offset] |= (idx >> (bit_offset-2));
			d[byte_offset+1] = 0;
			d[byte_offset+1] |= (idx << (8-(bit_offset-2))) & 0xFF;
		}
		s++; i++;
	}
}


/***************************************************************************
handle a http authentication line
  ***************************************************************************/
static int cgi_handle_authorization(char *line)
{
	char *p, *user, *pass;
	struct passwd *pwd;
	int ret=0;

	if (strncasecmp(line,"Basic ", 6)) {
		cgi_setup_error("401 Bad Authorization", "", 
				"Only basic authorization is understood");
	}
	line += 6;
	while (line[0] == ' ') line++;
	base64_decode(line);
	if (!(p=strchr(line,':'))) {
		cgi_setup_error("401 Bad Authorization", "", 
				"username/password must be supplied");
	}
	*p = 0;
	user = line;
	pass = p+1;

	/* currently only allow connections as root */
	if (strcasecmp(user,"root")) {
		cgi_setup_error("401 Bad Authorization", "", 
				"incorrect username/password");
	}
	
	pwd = getpwnam(user);

	if (!strcmp((char *)crypt(pass, pwd->pw_passwd),pwd->pw_passwd)) {
		ret = 1;
	}

	memset(pass, 0, strlen(pass));

	return ret;
}


/***************************************************************************
handle a file download
  ***************************************************************************/
static void cgi_download(char *file)
{
	struct stat st;
	char buf[1024];
	int fd, l, i;
	char *p;

	/* sanitise the filename */
	for (i=0;file[i];i++) {
		if (!isalnum(file[i]) && !strchr("/.-_", file[i])) {
			cgi_setup_error("404 File Not Found","",
					"Illegal character in filename");
		}
	}

	if (strstr(file,"..")) {
		cgi_setup_error("404 File Not Found","",
				"Relative paths not allowed");
	}

	if (!file_exist(file, &st)) {
		cgi_setup_error("404 File Not Found","",
				"The requested file was not found");
	}
	fd = open(file,O_RDONLY);
	if (fd == -1) {
		cgi_setup_error("404 File Not Found","",
				"The requested file was not found");
	}
	printf("HTTP/1.1 200 OK\r\n");
	if ((p=strrchr(file,'.'))) {
		if (strcmp(p,".gif")==0 || strcmp(p,".jpg")==0) {
			printf("Content-Type: image/gif\r\n");
		} else {
			printf("Content-Type: text/html\r\n");
		}
	}
	printf("Content-Length: %d\r\n\r\n", (int)st.st_size);
	while ((l=read(fd,buf,sizeof(buf)))>0) {
		fwrite(buf, 1, l, stdout);
	}
	close(fd);
	exit(0);
}


/***************************************************************************
setup the cgi framework, handling the possability that this program is either
run as a true cgi program by a web browser or is itself a mini web server
  ***************************************************************************/
void cgi_setup(char *rootdir)
{
	int authenticated = 0;
	char line[1024];
	char *url=NULL;
	char *p;

	if (chdir(rootdir)) {
		cgi_setup_error("400 Server Error", "",
				"chdir failed - the server is not configured correctly");
	}

	if (getenv("CONTENT_LENGTH") || getenv("REQUEST_METHOD")) {
		/* assume we are running under a real web server */
		return;
	}

	/* we are a mini-web server. We need to read the request from stdin
	   and handle authentication etc */
	while (fgets(line, sizeof(line)-1, stdin)) {
		if (line[0] == '\r' || line[0] == '\n') break;
		if (strncasecmp(line,"GET ", 4)==0) {
			request_get = 1;
			url = strdup(&line[4]);
		} else if (strncasecmp(line,"POST ", 5)==0) {
			request_post = 1;
			url = strdup(&line[5]);
		} else if (strncasecmp(line,"PUT ", 4)==0) {
			cgi_setup_error("400 Bad Request", "",
					"This server does not accept PUT requests");
		} else if (strncasecmp(line,"Authorization: ", 15)==0) {
			authenticated = cgi_handle_authorization(&line[15]);
		} else if (strncasecmp(line,"Content-Length: ", 16)==0) {
			content_length = atoi(&line[16]);
		}
		/* ignore all other requests! */
	}

	if (!authenticated) {
		cgi_setup_error("401 Authorization Required", 
				"WWW-Authenticate: Basic realm=\"root\"\r\n",
				"You must be authenticated to use this service");
	}

	if (!url) {
		cgi_setup_error("400 Bad Request", "",
				"You must specify a GET or POST request");
	}

	/* trim the URL */
	if ((p = strchr(url,' ')) || (p=strchr(url,'\t'))) {
		*p = 0;
	}
	while (*url && strchr("\r\n",url[strlen(url)-1])) {
		url[strlen(url)-1] = 0;
	}

	/* anything following a ? in the URL is part of the query string */
	if ((p=strchr(url,'?'))) {
		query_string = p+1;
		*p = 0;
	}

	if (strcmp(url,"/")) {
		cgi_download(url+1);
	}

	printf("HTTP/1.1 200 OK\r\nConnection: close\r\n");
	
}


