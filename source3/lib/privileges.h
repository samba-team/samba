#include "../libcli/security/privileges.h"

/* The following definitions come from lib/privileges.c  */

bool get_privileges_for_sids(uint64_t *privileges, struct dom_sid *slist, int scount);
NTSTATUS get_privileges_for_sid_as_set(TALLOC_CTX *mem_ctx, PRIVILEGE_SET **privileges, struct dom_sid *sid);
NTSTATUS privilege_enumerate_accounts(struct dom_sid **sids, int *num_sids);
NTSTATUS privilege_enum_sids(enum sec_privilege privilege, TALLOC_CTX *mem_ctx,
			     struct dom_sid **sids, int *num_sids);
bool grant_privilege_set(const struct dom_sid *sid, struct lsa_PrivilegeSet *set);
bool grant_privilege_by_name( const struct dom_sid *sid, const char *name);
bool revoke_all_privileges( const struct dom_sid *sid );
bool revoke_privilege_set(const struct dom_sid *sid, struct lsa_PrivilegeSet *set);
bool revoke_privilege_by_name(const struct dom_sid *sid, const char *name);
NTSTATUS privilege_create_account(const struct dom_sid *sid );
NTSTATUS privilege_delete_account(const struct dom_sid *sid);
bool is_privileged_sid( const struct dom_sid *sid );
bool grant_all_privileges( const struct dom_sid *sid );
