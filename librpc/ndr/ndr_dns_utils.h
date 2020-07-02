
enum ndr_err_code ndr_push_dns_string_list(struct ndr_push *ndr,
					   struct ndr_token_list *string_list,
					   int ndr_flags,
					   const char *s,
					   bool is_nbt);
