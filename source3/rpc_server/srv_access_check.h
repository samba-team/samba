/* The following definitions come from rpc_server/srv_access_check.c */

NTSTATUS access_check_object( struct security_descriptor *psd, struct security_token *token,
			      enum sec_privilege needed_priv_1, enum sec_privilege needed_priv_2,
			      uint32 rights_mask,
			      uint32 des_access, uint32 *acc_granted,
			      const char *debug );
void map_max_allowed_access(const struct security_token *nt_token,
			    const struct security_unix_token *unix_token,
			    uint32_t *pacc_requested);
