#include "rsh_locl.h"
RCSID("$Id$");

static enum auth_method auth_method;

static krb5_context context;
static krb5_auth_context auth_context;
static krb5_keyblock keyblock;
static des_key_schedule schedule;
static des_cblock iv;

static int do_encrypt;

static void
syslog_and_die (int prio, const char *m, ...)
{
    va_list args;

    va_start(args, m);
    vsyslog (prio, m, args);
    va_end(args);
    exit (1);
}

static void
fatal (int sock, const char *m, ...)
{
    va_list args;
    char buf[BUFSIZ];
    size_t len;

    *buf = 1;
    va_start(args, m);
    len = vsnprintf (buf + 1, sizeof(buf) - 1, m, args);
    va_end(args);
    syslog (LOG_ERR, buf + 1);
    krb_net_write (sock, buf, len + 1);
    exit (1);
}

static void
read_str (int s, char *str, size_t sz, char *expl)
{
    while (sz > 0) {
	if (krb_net_read (s, str, 1) != 1)
	    syslog_and_die (LOG_ERR, "read: %m");
	if (*str == '\0')
	    return;
	--sz;
	++str;
    }
    fatal (s, "%s too long", expl);
}

static int
recv_krb4_auth (int s, u_char *buf,
		struct sockaddr_in thisaddr,
		struct sockaddr_in thataddr,
		char *client_username,
		char *server_username,
		char *cmd)
{
    int status;
    int32_t options;
    KTEXT_ST ticket;
    AUTH_DAT nauth;
    char instance[INST_SZ + 1];
    char version[KRB_SENDAUTH_VLEN + 1];

    if (memcmp (buf, KRB_SENDAUTH_VERS, 4) != 0)
	return -1;
    if (krb_net_read (s, buf + 4, KRB_SENDAUTH_VLEN - 4) !=
	KRB_SENDAUTH_VLEN - 4)
	syslog_and_die (LOG_ERR, "reading auth info: %m");
    if (memcmp (buf, KRB_SENDAUTH_VERS, KRB_SENDAUTH_VLEN) != 0)
	syslog_and_die(LOG_ERR,
		       "unrecognized auth protocol: %.8s", buf);

    options = KOPT_IGNORE_PROTOCOL;
    if (do_encrypt)
	options |= KOPT_DO_MUTUAL;
    k_getsockinst (s, instance, sizeof(instance));
    status = krb_recvauth (options,
			   s,
			   &ticket,
			   "rcmd",
			   instance,
			   &thataddr,
			   &thisaddr,
			   &auth,
			   "",
			   schedule,
			   version);
    if (status != KSUCCESS)
	syslog_and_die (LOG_ERR, "recvauth: %s", krb_get_err_text(status));
    if (strncmp (version, KCMD_VERSION, KRB_SENDAUTH_VLEN) != 0)
	syslog_and_die (LOG_ERR, "bad version: %s", version);

    read_str (s, server_username, USERNAME_SZ, "remote username");
    if (kuserok (&auth, server_username) != 0)
	fatal (s, "Permission denied");
    read_str (s, cmd, COMMAND_SZ, "command");
    return 0;
}

static int
recv_krb5_auth (int s, u_char *buf,
		struct sockaddr_in thisaddr,
		struct sockaddr_in thataddr,
		char *client_username,
		char *server_username,
		char *cmd)
{
    u_int32_t len;
    krb5_auth_context *auth_context = NULL;
    krb5_ticket *ticket;
    krb5_error_code status;

    if (memcmp (buf, "\x00\x00\x00\x13", 4) != 0)
	return -1;
    len = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | (buf[3]);
	
    if (krb_net_read(s, buf, len) != len)
	syslog_and_die (LOG_ERR, "reading auth info: %m");
    if (len != sizeof(KRB5_SENDAUTH_VERSION)
	|| memcmp (buf, KRB5_SENDAUTH_VERSION, len) != 0)
	syslog_and_die (LOG_ERR, "bad sendauth version: %.8s", buf);
    
    krb5_init_context (&context);

    status = krb5_recvauth(context,
			   &auth_context,
			   &s,
			   KCMD_VERSION,
			   server,
			   KRB5_RECVAUTH_IGNORE_VERSION,
			   NULL,
			   &ticket);
    if (status)
	syslog_and_die (LOG_ERR, "krb5_recvauth: %s",
			krb5_get_err_text(context, status));
    keyblock = auth_context->key;

    read_str (s, client_username, USERNAME_SZ, "local username");
    read_str (s, cmd, COMMAND_SZ, "command");
    read_str (s, server_username, USERNAME_SZ, "remote username");

    /* discard forwarding information */
    krb_net_read (s, buf, 4);

    if(!krb5_kuserok (context,
		     ticket->enc_part2.client,
		     server_username))
	fatal (s, "Permission denied");

    if (strncmp (cmd, "-x ", 3) == 0) {
	do_encrypt = 1;
	memmove (cmd + 3, cmd, strlen(cmd) - 3);
    }
    return 0;
}

static int
doit (int s)
{
    u_char buf[BUFSIZ];
    char *p;
    struct sockaddr_in thisaddr, thataddr, erraddr;
    int addrlen;
    int port;
    int errsock = -1;
    char client_user[16], server_user[16];
    char cmd[COMMAND_SZ];

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

    p = buf;
    port = 0;
    for(;;) {
	if (krb_net_read (s, p, 1) != 1)
	    syslog_and_die (LOG_ERR, "reading port number: %m");
	if (*p == '\0')
	    break;
	else if (isdigit(*p))
	    port = port * 10 + *p - '0';
	else
	    syslog_and_die (LOG_ERR, "non-digit in port number: %c", *p);
    }
    if (port) {
	erraddr = thataddr;
	errsock = socket (AF_INET, SOCK_STREAM, 0);
	if (errsock < 0)
	    syslog_and_die (LOG_ERR, "socket: %m");
	if (connect (errsock, (struct sockaddr *)&erradr, sizeof(erraddr)) < 0)
	    syslog_and_die (LOG_ERR, "connect: %m");
    }
    
    if (krb_net_read (s, buf, 4) != 4)
	syslog_and_die (LOG_ERR, "reading auth info: %m");
    
    if (recv_krb4_auth (s, buf, thisaddr, thataddr,
			client_user,
			server_user,
			cmd) == 0)
	auth_method = AUTH_KRB4;
    else if(recv_krb5_auth (s, buf, thisaddr, thataddr,
			    client_user,
			    server_user,
			    cmd) == 0)
	auth_method = AUTH_KRB5;
    else
	syslog_and_die (LOG_ERR,
			"unrecognized auth protocol: %x %x %x %x",
			buf[0], buf[1], buf[2], buf[3]);



    
}

int
main(int argc, char **argv)
{
    int c;
    int inetd = 0;

    set_progname (argv[0]);
    openlog ("rshd", LOG_ODELAY, LOG_AUTH);

    while ((c = getopt(argc, argv, "ix")) != EOF) {
	switch (c) {
	case 'i' :
	    inetd = 1;
	    break;
	case 'x' :
	    do_encrypt = 1;
	    break;
	default :
	    usage ();
	}
    }
    return doit (STDIN_FILENO);
}
