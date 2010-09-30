_PUBLIC_ void ndr_print_dns_string(struct ndr_print *ndr, const char *name, const char *s);
_PUBLIC_ enum ndr_err_code ndr_pull_dns_string(struct ndr_pull *ndr, int ndr_flags, const char **s);
_PUBLIC_ enum ndr_err_code ndr_push_dns_string(struct ndr_push *ndr, int ndr_flags, const char *s);
_PUBLIC_ enum ndr_err_code ndr_push_dns_res_rec(struct ndr_push *ndr, int ndr_flags, const struct dns_res_rec *r);
_PUBLIC_ enum ndr_err_code ndr_pull_dns_res_rec(struct ndr_pull *ndr, int ndr_flags, struct dns_res_rec *r);
