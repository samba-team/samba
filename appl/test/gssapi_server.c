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
    gss_buffer_desc name_token;

    addrlen = sizeof(local);
    if (getsockname (sock, (struct sockaddr *)&local, &addrlen) < 0
	|| addrlen != sizeof(local))
	err (1, "getsockname)");

    addrlen = sizeof(remote);
    if (getpeername (sock, (struct sockaddr *)&remote, &addrlen) < 0
	|| addrlen != sizeof(remote))
	err (1, "getpeername");

    input_token = &real_input_token;
    output_token = &real_output_token;

    do {
	read_token (sock, input_token);
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
	if (output_token->length != 0)
	    write_token (sock, output_token);
	if (GSS_ERROR(maj_stat)) {
	    if (context_hdl != GSS_C_NO_CONTEXT)
		gss_delete_sec_context (&min_stat,
					&context_hdl,
					GSS_C_NO_BUFFER);
	    break;
	}
    } while(maj_stat & GSS_S_CONTINUE_NEEDED);

    maj_stat = gss_display_name (&min_stat,
				 client_name,
				 &name_token,
				 NULL);
    if (GSS_ERROR(maj_stat))
	abort ();

    printf ("User is `%.*s'\n", name_token.length, name_token.value);

    /* gss_verify_mic */

    read_token (sock, input_token);
    read_token (sock, output_token);

    maj_stat = gss_verify_mic (&min_stat,
			       context_hdl,
			       input_token,
			       output_token,
			       NULL);
    if (GSS_ERROR(maj_stat))
	abort ();

    printf ("gss_verify_mic: %.*s\n", input_token->length, input_token->value);

    /* gss_unwrap */

    read_token (sock, input_token);

    maj_stat = gss_unwrap (&min_stat,
			   context_hdl,
			   input_token,
			   output_token,
			   NULL,
			   NULL);
    if(GSS_ERROR(maj_stat))
	abort ();

    printf ("gss_unwrap: %.*s\n", output_token->length, output_token->value);

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
