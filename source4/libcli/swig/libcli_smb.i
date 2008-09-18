%module libcli_smb

%import "../../../lib/talloc/talloc.i"
%import "../../lib/events/events.i"

%{
#include "includes.h"
#include "lib/events/events.h"
#include "libcli/raw/libcliraw.h"
%}

struct smbcli_socket *smbcli_sock_connect_byname(const char *host, const char **ports,
						 TALLOC_CTX *mem_ctx,
                         struct resolve_context *resolve_ctx,
						 struct event_context *event_ctx);

void smbcli_sock_dead(struct smbcli_socket *sock);
