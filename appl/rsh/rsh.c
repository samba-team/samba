#include "rsh_locl.h"
RCSID("$Id$");

enum auth_method auth_method;
int do_encrypt;
krb5_context context;
krb5_keyblock *keyblock;
des_key_schedule schedule;
des_cblock iv;


/*
 *
 */

static int no_input;

static void
usage (void)
{
    errx (1, "Usage: %s [-45nx] [-p port] [-l user] host command", __progname);
}

static int
loop (int s, int errsock)
{
    struct fd_set real_readset;
    int count = 2;

    FD_ZERO(&real_readset);
    FD_SET(s, &real_readset);
    FD_SET(errsock, &real_readset);
    if(!no_input) {
	FD_SET(STDIN_FILENO, &real_readset);
    }

    for (;;) {
	int ret;
	struct fd_set readset;
	char buf[RSH_BUFSIZ];

	readset = real_readset;
	ret = select (max(s, errsock) + 1, &readset, NULL, NULL, NULL);
	if (ret < 0)
	    if (errno == EINTR)
		continue;
	    else
		err (1, "select");
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
		krb_net_write (STDOUT_FILENO, buf, ret);
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
		krb_net_write (STDERR_FILENO, buf, ret);
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

static void
send_krb4_auth(int s, struct sockaddr_in thisaddr,
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
    if (krb_net_write (s, remote_user, len) != len)
	err (1, "write");
    if (krb_net_write (s, cmd, cmd_len) != cmd_len)
	err (1, "write");
}

static void
send_krb5_auth(int s, struct sockaddr_in thisaddr,
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
    des_cblock key;
    int status;
    size_t len;
    krb5_auth_context auth_context = NULL;

    krb5_init_context(&context);

    krb5_cc_default (context, &ccache);

    status = krb5_sname_to_principal(context,
				     hostname,
				     "host",
				     KRB5_NT_SRV_INST,
				     &server);
    if (status)
	errx (1, "%s: %s", hostname, krb5_get_err_text(context, status));

    cksum_data.length = asprintf ((char **)&cksum_data.data,
				  "%u:%s%s%s",
				  ntohs(thataddr.sin_port),
				  do_encrypt ? "-x " : "",
				  cmd,
				  local_user);

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

    len = strlen(local_user) + 1;
    if (krb_net_write (s, local_user, len) != len)
	err (1, "write");
    if (do_encrypt && krb_net_write (s, "-x ", 3) != 3)
	err (1, "write");
    if (krb_net_write (s, cmd, cmd_len) != cmd_len)
	err (1, "write");
    len = strlen(remote_user) + 1;
    if (krb_net_write (s, remote_user, len) != len)
	err (1, "write");

    {
	/* Empty forwarding info */

	u_int32_t zero = 0;
	write (s, &zero, 4);
    }

}

static int
proto (int s, char *hostname, char *local_user, char *remote_user,
       char *cmd, size_t cmd_len)
{
    struct sockaddr_in erraddr;
    int errsock, errsock2;
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

    errsock = socket (AF_INET, SOCK_STREAM, 0);
    if (errsock < 0)
	err (1, "socket");
    memset (&erraddr, 0, sizeof(erraddr));
    erraddr.sin_family = AF_INET;
    erraddr.sin_addr.s_addr = INADDR_ANY;
    if (bind (errsock, (struct sockaddr *)&erraddr, sizeof(erraddr)) < 0)
	err (1, "bind");
    
    addrlen = sizeof(erraddr);
    if (getsockname (errsock, (struct sockaddr *)&erraddr, &addrlen) < 0)
	err (1, "getsockname");

    if (listen (errsock, 1) < 0)
	err (1, "listen");

    p = buf;
    snprintf (p, sizeof(buf), "%u", ntohs(erraddr.sin_port));
    len = strlen(buf) + 1;
    if(krb_net_write (s, buf, len) != len)
	err (1, "write");

    errsock2 = accept (errsock, NULL, NULL);
    if (errsock2 < 0)
	err (1, "accept");
    close (errsock);

    if (auth_method == AUTH_KRB4)
	send_krb4_auth (s, thisaddr, thataddr,
			hostname, remote_user, local_user,
			cmd_len, cmd);
    else if(auth_method == AUTH_KRB5)
	send_krb5_auth (s, thisaddr, thataddr,
			hostname, remote_user, local_user,
			cmd_len, cmd);
    else
	abort ();

    free (cmd);

    if (krb_net_read (s, &reply, 1) != 1)
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
doit (char *hostname, char *remote_user, int port, int argc, char **argv)
{
    struct hostent *hostent;
    struct in_addr **h;
    struct passwd *pwd;
    char *cmd;
    size_t cmd_len;

    pwd = getpwuid (getuid());
    if (pwd == NULL)
	errx (1, "who are you?");

    cmd_len = construct_command(&cmd, argc, argv);

    hostent = gethostbyname (hostname);
    if (hostent == NULL)
	errx (1, "gethostbyname '%s' failed: %s",
	      hostname,
	      hstrerror(h_errno));
    for (h = (struct in_addr **)hostent->h_addr_list;
	*h != NULL;
	 ++h) {
	struct sockaddr_in addr;
	int s;

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
	return proto (s, hostname, pwd->pw_name,
		      remote_user ? remote_user : pwd->pw_name,
		      cmd, cmd_len);
    }
    return 1;
}

/*
 * rsh host command
 */

int
main(int argc, char **argv)
{
    int c;
    char *remote_user = NULL;
    int port = 0;

    set_progname (argv[0]);

    if (argc < 3)
	usage ();
    auth_method = AUTH_KRB5;
    while ((c = getopt(argc, argv, "45l:nxp:")) != EOF) {
	switch (c) {
	case '4':
	    auth_method = AUTH_KRB4;
	    break;
	case '5':
	    auth_method = AUTH_KRB5;
	    break;
	case 'l':
	    remote_user = optarg;
	    break;
	case 'n':
	    no_input = 1;
	    break;
	case 'x':
	    do_encrypt = 1;
	    break;
	case 'p': {
	    struct servent *s = getservbyname (optarg, "tcp");

	    if (s)
		port = s->s_port;
	    else {
		char *ptr;

		port = strtol (optarg, &ptr, 10);
		if (port == 0 && ptr == optarg)
		    errx (1, "Bad port `%s'", optarg);
		port = htons(port);
	    }
	    break;
	}
	default:
	    usage ();
	    break;
	}
    }

    if (port == 0)
	if (do_encrypt && auth_method == AUTH_KRB4)
	    port = k_getportbyname ("ekshell", "tcp", htons(545));
	else
	    port = k_getportbyname ("kshell", "tcp", htons(544));

    return doit (argv[optind], remote_user, port,
		 argc - optind - 1, argv + optind + 1);
}
