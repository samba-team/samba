
/* The following definitions come from librpc/ndr/util.c  */

enum ndr_err_code ndr_push_server_id(struct ndr_push *ndr, int ndr_flags, const struct server_id *r);
enum ndr_err_code ndr_pull_server_id(struct ndr_pull *ndr, int ndr_flags, struct server_id *r);
void ndr_print_server_id(struct ndr_print *ndr, const char *name, const struct server_id *r);
_PUBLIC_ void ndr_print_sockaddr_storage(struct ndr_print *ndr, const char *name, const struct sockaddr_storage *ss);
