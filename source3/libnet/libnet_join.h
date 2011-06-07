/* The following definitions come from libnet/libnet_join.c  */

NTSTATUS libnet_join_ok(const char *netbios_domain_name,
			const char *machine_name,
			const char *dc_name);
WERROR libnet_init_JoinCtx(TALLOC_CTX *mem_ctx,
			   struct libnet_JoinCtx **r);
WERROR libnet_init_UnjoinCtx(TALLOC_CTX *mem_ctx,
			     struct libnet_UnjoinCtx **r);
WERROR libnet_Join(TALLOC_CTX *mem_ctx,
		   struct libnet_JoinCtx *r);
WERROR libnet_Unjoin(TALLOC_CTX *mem_ctx,
		     struct libnet_UnjoinCtx *r);
