#include "test_locl.h"
RCSID("$Id$");

static void
usage (void)
{
    errx (1, "Usage: %s [-p port] [-s service]", __progname);
}

static int
proto (int sock, const char *service)
{
    struct sockaddr_in remote, local;
    int addrlen;
    krb5_address remote_addr, local_addr;
    krb5_context context;
    krb5_ccache ccache;
    krb5_auth_context auth_context;
    krb5_error_code status;
    krb5_principal server;
    krb5_ticket *ticket;
    char *name;
    char hostname[MAXHOSTNAMELEN];
    krb5_data packet;
    krb5_data data;
    u_int32_t len, net_len;

    addrlen = sizeof(local);
    if (getsockname (sock, (struct sockaddr *)&local, &addrlen) < 0
	|| addrlen != sizeof(local))
	err (1, "getsockname)");

    addrlen = sizeof(remote);
    if (getpeername (sock, (struct sockaddr *)&remote, &addrlen) < 0
	|| addrlen != sizeof(remote))
	err (1, "getpeername");

    status = krb5_init_context(&context);
    if (status)
	errx (1, "krb5_init_context: %s",
	      krb5_get_err_text(context, status));

    status = krb5_auth_con_init (context, &auth_context);
    if (status)
	errx (1, "krb5_auth_con_init: %s",
	      krb5_get_err_text(context, status));

    local_addr.addr_type = AF_INET;
    local_addr.address.length = sizeof(local.sin_addr);
    local_addr.address.data   = &local.sin_addr;

    remote_addr.addr_type = AF_INET;
    remote_addr.address.length = sizeof(remote.sin_addr);
    remote_addr.address.data   = &remote.sin_addr;

    status = krb5_auth_con_setaddrs (context,
				     auth_context,
				     &local_addr,
				     &remote_addr);
    if (status)
	errx (1, "krb5_auth_con_setaddr: %s",
	      krb5_get_err_text(context, status));

    if(gethostname (hostname, sizeof(hostname)) < 0)
	err (1, "gethostname");

    status = krb5_sname_to_principal (context,
				      hostname,
				      service,
				      KRB5_NT_SRV_HST,
				      &server);
    if (status)
	errx (1, "krb5_sname_to_principal: %s",
	      krb5_get_err_text(context, status));

    status = krb5_recvauth (context,
			    &auth_context,
			    &sock,
			    VERSION,
			    server,
			    0,
			    NULL,
			    &ticket);
    if (status)
	errx (1, "krb5_recvauth: %s",
	      krb5_get_err_text(context, status));

    status = krb5_unparse_name (context,
				ticket->enc_part2.client,
				&name);
    if (status)
	errx (1, "krb5_unparse_name: %s",
	      krb5_get_err_text(context, status));

    printf ("User is `%s'\n", name);
    free (name);

    krb5_data_zero (&data);
    krb5_data_zero (&packet);

    if (krb5_net_read (context, sock, &net_len, 4) != 4)
	err (1, "krb5_net_read");

    len = ntohl(net_len);

    krb5_data_alloc (&packet, len);

    if (krb5_net_read (context, sock, packet.data, len) != len)
	err (1, "krb5_net_read");
    
    status = krb5_rd_safe (context,
			   auth_context,
			   &packet,
			   &data,
			   NULL);
    if (status)
	errx (1, "krb5_rd_safe: %s",
	      krb5_get_err_text(context, status));

    printf ("safe packet: %.*s\n", data.length, data.data);

    if (krb5_net_read (context, sock, &net_len, 4) != 4)
	err (1, "krb5_net_read");

    len = ntohl(net_len);

    krb5_data_alloc (&packet, len);

    if (krb5_net_read (context, sock, packet.data, len) != len)
	err (1, "krb5_net_read");
    
    status = krb5_rd_priv (context,
			   auth_context,
			   &packet,
			   &data,
			   NULL);
    if (status)
	errx (1, "krb5_rd_priv: %s",
	      krb5_get_err_text(context, status));

    printf ("priv packet: %.*s\n", data.length, data.data);

    return 0;
}

static int
doit (int port, const char *service)
{
    int sock, sock2;
    struct sockaddr_in my_addr;
    int one = 1;

    sock = socket (AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
	err (1, "socket");

    memset (&my_addr, 0, sizeof(my_addr));
    my_addr.sin_family      = AF_INET;
    my_addr.sin_port        = port;
    my_addr.sin_addr.s_addr = INADDR_ANY;

    if (setsockopt (sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0)
	warn ("setsockopt SO_REUSEADDR");

    if (bind (sock, (struct sockaddr *)&my_addr, sizeof(my_addr)) < 0)
	err (1, "bind");

    if (listen (sock, 1) < 0)
	err (1, "listen");

    sock2 = accept (sock, NULL, NULL);
    if (sock2 < 0)
	err (1, "accept");

    return proto (sock2, service);
}

int
main(int argc, char **argv)
{
    int c;
    int port = 0;
    char *service = SERVICE;

    set_progname (argv[0]);

    while ((c = getopt (argc, argv, "p:s:")) != EOF) {
	switch (c) {
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
	case 's':
	    service = optarg;
	    break;
	default:
	    usage ();
	    break;
	}
    }
    argc -= optind;
    argv += optind;

    if (argc != 0)
	usage ();

    if (port == 0)
	port = krb5_getportbyname (PORT, "tcp", htons(4711));

    return doit (port, service);
}
