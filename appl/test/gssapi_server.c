#include "test_locl.h"
#include <gssapi.h>
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
    gss_ctx_id_t context_hdl = GSS_C_NO_CONTEXT;
    gss_buffer_t input_token, output_token;
    gss_buffer_desc real_input_token, real_output_token;
    OM_uint32 maj_stat, min_stat;
    gss_name_t client_name;
    u_int32_t len, net_len;
    char *name;

    krb5_context context;
    krb5_principal server;
    krb5_error_code status;

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

    input_token = &real_input_token;
    output_token = &real_output_token;

    do {
	if (read(sock, &net_len, 4) != 4)
	    err (1, "read");
	len = ntohl(net_len);
	input_token->length = len;
	input_token->value  = malloc(len);
	if (read (sock, input_token->value, len) != len)
	    err (1, "read");
	maj_stat =
	    gss_accept_sec_context (&min_stat,
				    &context_hdl,
				    GSS_C_NO_CREDENTIAL,
				    input_token,
				    GSS_C_NO_CHANNEL_BINDINGS,
				    &client_name,
				    NULL,
				    output_token,
				    NULL,
				    NULL,
				    NULL);
	if(GSS_ERROR(maj_stat))
	    abort ();
	if (output_token->length != 0) {
	    len = output_token->length;

	    net_len = htonl(len);

	    if (write (sock, &net_len, 4) != 4)
		err (1, "write");
	    if (write (sock, output_token->value, len) != len)
		err (1, "write");

	    gss_release_buffer (&min_stat,
				output_token);
	}
	if (GSS_ERROR(maj_stat)) {
	    if (context_hdl != GSS_C_NO_CONTEXT)
		gss_delete_sec_context (&min_stat,
					&context_hdl,
					GSS_C_NO_BUFFER);
	    break;
	}
    } while(maj_stat & GSS_S_CONTINUE_NEEDED);

    status = krb5_unparse_name (context,
				client_name,
				&name);
    if (status)
	errx (1, "krb5_unparse_name: %s",
	      krb5_get_err_text(context, status));

    printf ("User is `%s'\n", name);
    free (name);

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
