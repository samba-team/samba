#include "rsh_locl.h"
RCSID("$Id$");

static enum auth_method auth_method;

/*
 *
 */

#define RSH_BUFSIZ 10240

static krb5_context context;
static krb5_auth_context auth_context;
static krb5_keyblock keyblock;
static des_key_schedule schedule;
static des_cblock iv;

static int no_input, do_encrypt;

static void
usage (void)
{
    errx (1, "Usage: %s [-45nx] [-l user] host command", __progname);
}

static ssize_t
do_read (int fd,
	 void *buf,
	 size_t sz)
{
    int ret;

    if (do_encrypt) {
	if (auth_method == AUTH_KRB4) {
	    return des_enc_read (fd, buf, sz, schedule, &iv);
	} else if(auth_method == AUTH_KRB5) {
	    u_int32_t len, outer_len;
	    int status;
	    krb5_data data;

	    ret = krb5_net_read (context, fd, &len, 4);
	    if (ret != 4)
		return ret;
	    len = ntohl(len);
	    outer_len = len + 12;
	    outer_len = (outer_len + 7) & ~7;
	    if (outer_len > sz)
		abort ();
	    ret = krb5_net_read (context, fd, buf, outer_len);
	    if (ret != outer_len)
		return ret;
	    status = krb5_decrypt(context, buf, outer_len,
				  &keyblock, &data);
	    if (status != KSUCCESS)
		errx ("%s", krb5_get_err_text (context, status));
	    memcpy (buf, data.data, len);
	    free (data.data);
	    return len;
	} else {
	    abort ();
	}
    } else
	return read (fd, buf, sz);
}

static ssize_t
do_write (int fd, void *buf, size_t sz)
{
    int ret;

    if (do_encrypt) {
	if(auth_method == AUTH_KRB4) {
	    return des_enc_write (fd, buf, sz, schedule, &iv);
	} else if(auth_method == AUTH_KRB5) {
	    krb5_error_code status;
	    krb5_data data;
	    u_int32_t len;
	    int ret;

	    status = krb5_encrypt (context,
				   buf,
				   sz,
				   &keyblock,
				   &data);
	    if (status != KSUCCESS)
		errx (1, "%s", krb5_get_err_text(context, status));
	    len = htonl(sz);
	    ret = krb5_net_write (context, fd, &len, 4);
	    if (ret != 4)
		return ret;
	    ret = krb5_net_write (context, fd, data.data, data.length);
	    if (ret != data.length)
		return ret;
	    free (data.data);
	    return sz;
	} else {
	    abort();
	}
    } else
	return write (fd, buf, sz);
}

static int
loop (int s, int errsock)
{
    struct fd_set real_readset;
    int count = 0;

    FD_ZERO(&real_readset);
    FD_SET(s, &real_readset);
    FD_SET(errsock, &real_readset);
    if(!no_input)
	FD_SET(STDIN_FILENO, &real_readset);

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
		if (++count == 2)
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
		if (++count == 2)
		    return 0;
	    } else
		krb_net_write (STDERR_FILENO, buf, ret);
	}
	if (FD_ISSET(STDIN_FILENO, &readset)) {
	    ret = read (STDIN_FILENO, buf, sizeof(buf));
	    if (ret < 0)
		err (1, "read");
	    else if (ret == 0)
		return 0;
	    else
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
	errx ("%s: %s", hostname, krb_get_err_text(status));
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
    char *buf;
    int status;
    size_t len;

    krb5_init_context(&context);

    krb5_cc_default (context, &ccache);

    status = krb5_sname_to_principal(context,
				     hostname,
				     "host",
				     KRB5_NT_SRV_INST,
				     &server);
    if (status)
	errx ("%s: %s", hostname, krb5_get_err_text(context, status));

    len = 6 + 3 + cmd_len + strlen(local_user);
    buf = malloc (len);
    snprintf (buf, len, "%u:%s%s%s", ntohs(thataddr.sin_port),
	      do_encrypt ? "-x " : "",
	      cmd, local_user);

    cksum_data.data   = buf;
    cksum_data.length = strlen (buf);

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
	errx ("%s: %s", hostname, krb5_get_err_text(context, status));

    keyblock = auth_context->key;

    len = strlen(local_user) + 1;
    if (krb_net_write (s, local_user, len) != len)
	err (1, "write");
    if (do_encrypt && krb_net_write (s, "-x ", 3) != 3)
	err (1, "write");
    if (krb_net_write (s, cmd, cmd_len) != cmd_len)
	err (1, "write");
    free (cmd);
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
doit (char *hostname, char *remote_user, int argc, char **argv)
{
    struct hostent *hostent;
    struct in_addr **h;
    struct passwd *pwd;
    char *cmd;
    size_t cmd_len;
    int port;

    pwd = getpwuid (getuid());
    if (pwd == NULL)
	errx (1, "who are you?");

    cmd_len = construct_command(&cmd, argc, argv);

    if (do_encrypt)
	port = k_getportbyname ("ekshell", "tcp", htons(545));
    else
	port = k_getportbyname ("kshell", "tcp", htons(544));

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

    set_progname (argv[0]);

    if (argc < 3)
	usage ();
    auth_method = AUTH_KRB5;
    while ((c = getopt(argc, argv, "45l:nx")) != EOF) {
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
	default:
	    usage ();
	    break;
	}
    }
    return doit (argv[optind], remote_user,
		 argc - optind - 1, argv + optind + 1);
}
