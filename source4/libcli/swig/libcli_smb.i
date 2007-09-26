%module libcli_smb

%{
#include "includes.h"
#include "lib/talloc/talloc.h"
#include "lib/events/events.h"
#include "libcli/raw/libcliraw.h"
%}

TALLOC_CTX *talloc_init(char *name);
int talloc_free(TALLOC_CTX *ptr);
struct event_context *event_context_init(TALLOC_CTX *mem_ctx);

struct smbcli_socket *smbcli_sock_connect_byname(const char *host, int port,
						 TALLOC_CTX *mem_ctx,
						 struct event_context *event_ctx);

void smbcli_sock_dead(struct smbcli_socket *sock);
