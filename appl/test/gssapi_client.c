#include "test_locl.h"
#include <gssapi.h>
RCSID("$Id$");

static void
usage (void)
{
    errx (1, "Usage: %s [-p port] [-s service] host", __progname);
}

static int
proto (int sock, const char *hostname, const char *service)
{
    struct sockaddr_in remote, local;
    int addrlen;

    int context_established = 0;
    gss_ctx_id_t context_hdl = GSS_C_NO_CONTEXT;
    gss_buffer_t input_token, output_token;
    gss_buffer_desc real_input_token, real_output_token;
    OM_uint32 maj_stat, min_stat;
    u_int32_t len, net_len;

    krb5_context context;
    krb5_principal server;
    krb5_error_code status;

    status = krb5_init_context(&context);
    if (status)
	errx (1, "krb5_init_context: %s",
	      krb5_get_err_text(context, status));

    status = krb5_sname_to_principal (context,
				      hostname,
				      service,
				      KRB5_NT_SRV_INST,
				      &server);
    if (status)
	errx (1, "krb5_sname_to_principal: %s",
	      krb5_get_err_text(context, status));

    addrlen = sizeof(local);
    if (getsockname (sock, (struct sockaddr *)&local, &addrlen) < 0
	|| addrlen != sizeof(local))
	err (1, "getsockname(%s)", hostname);

    addrlen = sizeof(remote);
    if (getpeername (sock, (struct sockaddr *)&remote, &addrlen) < 0
	|| addrlen != sizeof(remote))
	err (1, "getpeername(%s)", hostname);

    input_token = &real_input_token;
    output_token = &real_output_token;

    input_token->length = 0;
    output_token->length = 0;

    while(!context_established) {
	maj_stat =
	    gss_init_sec_context(&min_stat,
				 GSS_C_NO_CREDENTIAL,
				 &context_hdl,
				 server,
				 GSS_C_NO_OID,
				 GSS_C_MUTUAL_FLAG | GSS_C_SEQUENCE_FLAG,
				 0,
				 GSS_C_NO_CHANNEL_BINDINGS,
				 input_token,
				 NULL,
				 output_token,
				 NULL,
				 NULL);
	if (GSS_ERROR(maj_stat))
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
	if (maj_stat & GSS_S_CONTINUE_NEEDED) {
	    if (read(sock, &net_len, 4) != 4)
		err (1, "read");
	    len = ntohl(net_len);
	    input_token->length = len;
	    input_token->value  = malloc(len);
	    if (read (sock, input_token->value, len) != len)
		err (1, "read");
	} else {
	    context_established = 1;
	}

    }
    return 0;
}

static int
doit (const char *hostname, int port, const char *service)
{
    struct in_addr **h;
    struct hostent *hostent;

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
	return proto (s, hostname, service);
    }
    return 1;
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

    if (argc != 1)
	usage ();

    if (port == 0)
	port = krb5_getportbyname (PORT, "tcp", htons(4711));

    return doit (*argv, port, service);
}
