/*
 * Copyright (c) 1997, 1998, 1999 Kungliga Tekniska Högskolan
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
 *      This product includes software developed by Kungliga Tekniska 
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

#include "rsh_locl.h"
RCSID("$Id$");

enum auth_method auth_method;
int do_encrypt;
int do_forward;
int do_forwardable;
krb5_context context;
krb5_keyblock *keyblock;
krb5_crypto crypto;
des_key_schedule schedule;
des_cblock iv;


/*
 *
 */

static int input = 1;		/* Read from stdin */

static int
loop (int s, int errsock)
{
    fd_set real_readset;
    int count = 2;

    FD_ZERO(&real_readset);
    FD_SET(s, &real_readset);
    FD_SET(errsock, &real_readset);
    if(input) {
	FD_SET(STDIN_FILENO, &real_readset);
    }

    for (;;) {
	int ret;
	fd_set readset;
	char buf[RSH_BUFSIZ];

	readset = real_readset;
	ret = select (max(s, errsock) + 1, &readset, NULL, NULL, NULL);
	if (ret < 0) {
	    if (errno == EINTR)
		continue;
	    else
		err (1, "select");
	}
	if (FD_ISSET(s, &readset)) {
	    ret = do_read (s, buf, sizeof(buf));
	    if (ret < 0)
		err (1, "read");
	    else if (ret == 0) {
		close (s);
		FD_CLR(s, &real_readset);
		if (--count == 0)
		    return 0;
	    } else
		net_write (STDOUT_FILENO, buf, ret);
	}
	if (FD_ISSET(errsock, &readset)) {
	    ret = do_read (errsock, buf, sizeof(buf));
	    if (ret < 0)
		err (1, "read");
	    else if (ret == 0) {
		close (errsock);
		FD_CLR(errsock, &real_readset);
		if (--count == 0)
		    return 0;
	    } else
		net_write (STDERR_FILENO, buf, ret);
	}
	if (FD_ISSET(STDIN_FILENO, &readset)) {
	    ret = read (STDIN_FILENO, buf, sizeof(buf));
	    if (ret < 0)
		err (1, "read");
	    else if (ret == 0) {
		close (STDIN_FILENO);
		FD_CLR(STDIN_FILENO, &real_readset);
	    } else
		do_write (s, buf, ret);
	}
    }
}

#ifdef KRB4
static void
send_krb4_auth(int s,
	       struct sockaddr_in thisaddr,
	       struct sockaddr_in thataddr,
	       char *hostname,
	       char *remote_user,
	       char *local_user,
	       size_t cmd_len,
	       char *cmd)
{
    KTEXT_ST text;
    CREDENTIALS cred;
    MSG_DAT msg;
    int status;
    size_t len;

    status = krb_sendauth (do_encrypt ? KOPT_DO_MUTUAL : 0,
			   s, &text, "rcmd",
			   hostname, krb_realmofhost (hostname),
			   getpid(), &msg, &cred, schedule,
			   &thisaddr, &thataddr, KCMD_VERSION);
    if (status != KSUCCESS)
	errx (1, "%s: %s", hostname, krb_get_err_text(status));
    memcpy (iv, cred.session, sizeof(iv));

    len = strlen(remote_user) + 1;
    if (net_write (s, remote_user, len) != len)
	err (1, "write");
    if (net_write (s, cmd, cmd_len) != cmd_len)
	err (1, "write");
}
#endif /* KRB4 */

/*
 * Send forward information on `s' for host `hostname', them being
 * forwardable themselves if `forwardable'
 */

static int
krb5_forward_cred (krb5_auth_context auth_context,
		   int s,
		   const char *hostname,
		   int forwardable)
{
    krb5_error_code ret;
    krb5_ccache     ccache;
    krb5_creds      creds;
    krb5_kdc_flags  flags;
    krb5_data       out_data;
    krb5_principal  principal;

    memset (&creds, 0, sizeof(creds));

    ret = krb5_cc_default (context, &ccache);
    if (ret) {
	warnx ("could not forward creds: krb5_cc_default: %s",
	       krb5_get_err_text (context, ret));
	return 1;
    }

    ret = krb5_cc_get_principal (context, ccache, &principal);
    if (ret) {
	warnx ("could not forward creds: krb5_cc_get_principal: %s",
	       krb5_get_err_text (context, ret));
	return 1;
    }

    creds.client = principal;
    
    ret = krb5_build_principal (context,
				&creds.server,
				strlen(principal->realm),
				principal->realm,
				"krbtgt",
				principal->realm,
				NULL);

    if (ret) {
	warnx ("could not forward creds: krb5_build_principal: %s",
	       krb5_get_err_text (context, ret));
	return 1;
    }

    creds.times.endtime = 0;

    flags.i = 0;
    flags.b.forwarded   = 1;
    flags.b.forwardable = forwardable;

    ret = krb5_get_forwarded_creds (context,
				    auth_context,
				    ccache,
				    flags.i,
				    hostname,
				    &creds,
				    &out_data);
    if (ret) {
	warnx ("could not forward creds: krb5_get_forwarded_creds: %s",
	       krb5_get_err_text (context, ret));
	return 1;
    }

    ret = krb5_write_message (context,
			      (void *)&s,
			      &out_data);
    krb5_data_free (&out_data);

    if (ret)
	warnx ("could not forward creds: krb5_write_message: %s",
	       krb5_get_err_text (context, ret));
    return 0;
}

static void
send_krb5_auth(int s,
	       struct sockaddr_in thisaddr,
	       struct sockaddr_in thataddr,
	       char *hostname,
	       char *remote_user,
	       char *local_user,
	       size_t cmd_len,
	       char *cmd)
{
    krb5_principal server;
    krb5_data cksum_data;
    krb5_ccache ccache;
    int status;
    size_t len;
    krb5_auth_context auth_context = NULL;

    krb5_init_context(&context);

    krb5_cc_default (context, &ccache);

    status = krb5_sname_to_principal(context,
				     hostname,
				     "host",
				     KRB5_NT_SRV_HST,
				     &server);
    if (status)
	errx (1, "%s: %s", hostname, krb5_get_err_text(context, status));

    cksum_data.length = asprintf ((char **)&cksum_data.data,
				  "%u:%s%s%s",
				  ntohs(thataddr.sin_port),
				  do_encrypt ? "-x " : "",
				  cmd,
				  remote_user);

    status = krb5_sendauth (context,
			    &auth_context,
			    &s,
			    KCMD_VERSION,
			    NULL,
			    server,
			    do_encrypt ? AP_OPTS_MUTUAL_REQUIRED : 0,
			    &cksum_data,
			    NULL,
			    ccache,
			    NULL,
			    NULL,
			    NULL);
    if (status)
	errx (1, "%s: %s", hostname, krb5_get_err_text(context, status));

    status = krb5_auth_con_getkey (context, auth_context, &keyblock);
    if (status)
      errx (1, "krb5_auth_con_getkey: %s",
	    krb5_get_err_text(context, status));

    krb5_crypto_init(context, keyblock, 0, &crypto);
    if(status)
	errx (1, "krb5_crypto_init: %s",
	      krb5_get_err_text(context, status));

    len = strlen(remote_user) + 1;
    if (net_write (s, remote_user, len) != len)
	err (1, "write");
    if (do_encrypt && net_write (s, "-x ", 3) != 3)
	err (1, "write");
    if (net_write (s, cmd, cmd_len) != cmd_len)
	err (1, "write");
    len = strlen(local_user) + 1;
    if (net_write (s, local_user, len) != len)
	err (1, "write");

    if (!do_forward
	|| krb5_forward_cred (auth_context, s, hostname, do_forwardable)) {
	/* Empty forwarding info */

	u_char zero[4] = {0, 0, 0, 0};
	write (s, &zero, 4);
    }
    krb5_auth_con_free (context, auth_context);

}

static void
send_broken_auth(int s,
		 struct sockaddr_in thisaddr,
		 struct sockaddr_in thataddr,
		 char *hostname,
		 char *remote_user,
		 char *local_user,
		 size_t cmd_len,
		 char *cmd)
{
    size_t len;

    len = strlen(local_user) + 1;
    if (net_write (s, local_user, len) != len)
	err (1, "write");
    len = strlen(remote_user) + 1;
    if (net_write (s, remote_user, len) != len)
	err (1, "write");
    if (net_write (s, cmd, cmd_len) != cmd_len)
	err (1, "write");
}

static int
proto (int s, int errsock,
       char *hostname, char *local_user, char *remote_user,
       char *cmd, size_t cmd_len)
{
    struct sockaddr_in erraddr;
    int errsock2;
    char buf[BUFSIZ];
    char *p;
    size_t len;
    char reply;
    struct sockaddr_in thisaddr, thataddr;
    int addrlen;
    int ret;

    addrlen = sizeof(thisaddr);
    if (getsockname (s, (struct sockaddr *)&thisaddr, &addrlen) < 0
	|| addrlen != sizeof(thisaddr)) {
	err (1, "getsockname(%s)", hostname);
    }
    addrlen = sizeof(thataddr);
    if (getpeername (s, (struct sockaddr *)&thataddr, &addrlen) < 0
	|| addrlen != sizeof(thataddr)) {
	err (1, "getpeername(%s)", hostname);
    }

    addrlen = sizeof(erraddr);
    if (getsockname (errsock, (struct sockaddr *)&erraddr, &addrlen) < 0)
	err (1, "getsockname");

    if (listen (errsock, 1) < 0)
	err (1, "listen");

    p = buf;
    snprintf (p, sizeof(buf), "%u", ntohs(erraddr.sin_port));
    len = strlen(buf) + 1;
    if(net_write (s, buf, len) != len)
	err (1, "write");

    errsock2 = accept (errsock, NULL, NULL);
    if (errsock2 < 0)
	err (1, "accept");
    close (errsock);

#ifdef KRB4
    if (auth_method == AUTH_KRB4)
	send_krb4_auth (s, thisaddr, thataddr,
			hostname, remote_user, local_user,
			cmd_len, cmd);
    else
#endif /* KRB4 */
    if(auth_method == AUTH_KRB5)
	send_krb5_auth (s, thisaddr, thataddr,
			hostname, remote_user, local_user,
			cmd_len, cmd);
    else
    if(auth_method == AUTH_BROKEN)
	send_broken_auth (s, thisaddr, thataddr,
			  hostname, remote_user, local_user,
			  cmd_len, cmd);
    else
	abort ();

    if (net_read (s, &reply, 1) != 1)
	err (1, "read");
    if (reply != 0) {

	warnx ("Error from rshd at %s:", hostname);

	while ((ret = read (s, buf, sizeof(buf))) > 0)
	    write (STDOUT_FILENO, buf, ret);
	return 1;
    }

    return loop (s, errsock2);
}

static size_t
construct_command (char **res, int argc, char **argv)
{
    int i;
    size_t len = 0;
    char *tmp;

    for (i = 0; i < argc; ++i)
	len += strlen(argv[i]) + 1;
    tmp = malloc (len);
    if (tmp == NULL)
	errx (1, "malloc %u failed", len);

    *tmp = '\0';
    for (i = 0; i < argc - 1; ++i) {
	strcat (tmp, argv[i]);
	strcat (tmp, " ");
    }
    strcat (tmp, argv[argc-1]);
    *res = tmp;
    return len;
}

static int
doit_broken (int argc,
	     char **argv,
	     int optind,
	     char *host,
	     char *remote_user,
	     char *local_user,
	     int port,
	     int priv_socket1,
	     int priv_socket2,
	     char *cmd,
	     size_t cmd_len)
{
    struct hostent *hostent;
    struct sockaddr_in addr;

    if (priv_socket1 < 0 || priv_socket2 < 0)
	errx (1, "unable to bind reserved port: is rsh setuid root?");

    hostent = roken_gethostbyname (host);
    if (hostent == NULL)
	errx (1, "gethostbyname '%s' failed: %s",
	      host, hstrerror(h_errno));

    memset (&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = port;
    addr.sin_addr   = *((struct in_addr *)hostent->h_addr_list[0]);

    if (connect(priv_socket1, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
	struct in_addr **h;

	if (hostent->h_addr_list[1] == NULL)
	    return 1;

	close(priv_socket1);
	close(priv_socket2);

	for(h = (struct in_addr **)hostent->h_addr_list;
	    *h != NULL;
	    ++h) {
	    pid_t pid;

	    pid = fork();
	    if (pid < 0)
		err (1, "fork");
	    else if(pid == 0) {
		char **new_argv;
		int i = 0;

		new_argv = malloc((argc + 2) * sizeof(*new_argv));
		if (new_argv == NULL)
		    errx (1, "malloc: out of memory");
		new_argv[i] = argv[i];
		++i;
		if (optind == i)
		    new_argv[i++] = inet_ntoa(**h);
		new_argv[i++] = "-K";
		for(; i <= argc; ++i)
		    new_argv[i] = argv[i - 1];
		if (optind > 1)
		    new_argv[optind + 1] = inet_ntoa(**h);
		new_argv[argc + 1] = NULL;
		execv(PATH_RSH, new_argv);
		err(1, "execv(%s)", PATH_RSH);
	    } else {
		int status;

		while(waitpid(pid, &status, 0) < 0)
		    ;
		if(WIFEXITED(status) && WEXITSTATUS(status) == 0)
		    return 0;
	    }
	}
	return 1;
    } else {
	return proto (priv_socket1, priv_socket2,
		      argv[optind],
		      local_user, remote_user,
		      cmd, cmd_len);
    }
}

static int
doit (char *hostname,
      char *remote_user,
      char *local_user,
      int port,
      char *cmd,
      size_t cmd_len)
{
    struct hostent *hostent;
    struct in_addr **h;

    hostent = roken_gethostbyname (hostname);
    if (hostent == NULL)
	errx (1, "gethostbyname '%s' failed: %s",
	      hostname,
	      hstrerror(h_errno));
    for (h = (struct in_addr **)hostent->h_addr_list;
	*h != NULL;
	 ++h) {
	int s;
	struct sockaddr_in addr;
	int errsock;
	struct sockaddr_in erraddr;

	memset (&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port   = port;
	addr.sin_addr   = **h;

	s = socket (AF_INET, SOCK_STREAM, 0);
	if (s < 0)
	    err (1, "socket");
	if (connect (s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
	    warn ("connect(%s)", hostname);
	    close (s);
	    continue;
	}
	errsock = socket (AF_INET, SOCK_STREAM, 0);
	if (errsock < 0)
	    err (1, "socket");
	memset (&erraddr, 0, sizeof(erraddr));
	erraddr.sin_family = AF_INET;
	erraddr.sin_addr.s_addr = INADDR_ANY;
	if (bind (errsock, (struct sockaddr *)&erraddr, sizeof(erraddr)) < 0)
	    err (1, "bind");
    
	return proto (s, errsock,
		      hostname,
		      local_user, remote_user,
		      cmd, cmd_len);
    }
    return 1;
}

#ifdef KRB4
static int use_v4 = 0;
#endif
static int use_v5 = 0;
static int use_only_broken = 0;
static int use_broken = 1;
static char *port_str;
static char *user;
static int do_version;
static int do_help;

struct getargs args[] = {
#ifdef KRB4
    { "krb4",	'4', arg_flag,		&use_v4,	"Use Kerberos V4",
      NULL },
#endif
    { "krb5",	'5', arg_flag,		&use_v5,	"Use Kerberos V5",
      NULL },
    { "broken", 'K', arg_flag,		&use_only_broken, "Use priv port",
      NULL },
    { "input",	'n', arg_negative_flag,	&input,		"Close stdin",
      NULL },
    { "encrypt", 'x', arg_flag,		&do_encrypt,	"Encrypt connection",
      NULL },
    { "forward", 'f', arg_flag,		&do_forward,	"Forward credentials",
      NULL },
    { "forwardable", 'F', arg_flag,	&do_forwardable,
      "Forward forwardable credentials", NULL },
    { "port",	'p', arg_string,	&port_str,	"Use this port",
      "number-or-service" },
    { "user",	'l', arg_string,	&user,		"Run as this user",
      NULL },
    { "version", 0,  arg_flag,		&do_version,	"Print version",
      NULL },
    { "help",	 0,  arg_flag,		&do_help,	NULL,
      NULL }
};

static void
usage (int ret)
{
    arg_printusage (args,
		    sizeof(args) / sizeof(args[0]),
		    NULL,
		    "host command");
    exit (ret);
}

/*
 * main
 */

int
main(int argc, char **argv)
{
    int priv_port1, priv_port2;
    int priv_socket1, priv_socket2;
    int port = 0;
    int optind = 0;
    int ret = 1;
    char *cmd;
    size_t cmd_len;
    struct passwd *pwd;
    char *local_user;
    char *host = NULL;
    int host_index = -1;

    priv_port1 = priv_port2 = IPPORT_RESERVED-1;
    priv_socket1 = rresvport(&priv_port1);
    priv_socket2 = rresvport(&priv_port2);
    setuid(getuid());
    
    set_progname (argv[0]);

    if (argc >= 2 && argv[1][0] != '-') {
	host = argv[host_index = 1];
	optind = 1;
    }

    if (getarg (args, sizeof(args) / sizeof(args[0]), argc, argv,
		&optind))
	usage (1);

    if (do_forwardable)
	do_forward = 1;

    /* default to v5 */
#ifdef KRB4
    if(use_v4 == 0 && use_v5 == 0)
#endif
	use_v5 = 1;

    if (use_only_broken) {
#ifdef KRB4
	use_v4 = 0;
#endif
	use_v5 = 0;
    }

    if (do_help)
	usage (0);

    if (do_version) {
	print_version (NULL);
	return 0;
    }
	
    if (host == NULL) {
	if (argc - optind < 2)
	    usage (1);
	else
	    host = argv[host_index = optind++];
    }

    if (port_str) {
	struct servent *s = roken_getservbyname (port_str, "tcp");

	if (s)
	    port = s->s_port;
	else {
	    char *ptr;

	    port = strtol (port_str, &ptr, 10);
	    if (port == 0 && ptr == port_str)
		errx (1, "Bad port `%s'", port_str);
	    port = htons(port);
	}
    }

    pwd = getpwuid (getuid());
    if (pwd == NULL)
	errx (1, "who are you?");
    local_user = pwd->pw_name;

    if (user == NULL)
	user = local_user;

    cmd_len = construct_command(&cmd, argc - optind, argv + optind);

    /*
     * Try all different authentication methods
     */

    if (ret && use_v5) {
	int tmp_port;

	if (port)
	    tmp_port = port;
	else
	    tmp_port = krb5_getportbyname (context, "kshell", "tcp", 544);

	auth_method = AUTH_KRB5;
	ret = doit (host, user, local_user, tmp_port, cmd, cmd_len);
    }
#ifdef KRB4
    if (ret && use_v4) {
	int tmp_port;

	if (port)
	    tmp_port = port;
	else if (do_encrypt)
	    tmp_port = krb5_getportbyname (context, "ekshell", "tcp", 545);
	else
	    tmp_port = krb5_getportbyname (context, "kshell", "tcp", 544);

	auth_method = AUTH_KRB4;
	ret = doit (host, user, local_user, tmp_port, cmd, cmd_len);
    }
#endif
    if (ret && use_broken) {
	int tmp_port;

	if(port)
	    tmp_port = port;
	else
	    tmp_port = krb5_getportbyname(context, "shell", "tcp", 514);
	auth_method = AUTH_BROKEN;
	ret = doit_broken (argc, argv, host_index, host,
			   user, local_user,
			   tmp_port,
			   priv_socket1,
			   priv_socket2,
			   cmd, cmd_len);
    }
    return ret;
}
