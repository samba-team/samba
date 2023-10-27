
enum ndr_err_code ndr_push_dns_string_list(struct ndr_push *ndr,
					   struct ndr_token_list *string_list,
					   ndr_flags_type ndr_flags,
					   const char *s,
					   bool is_nbt);
