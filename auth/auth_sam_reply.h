#ifndef __AUTH_AUTH_SAM_REPLY_H__
#define __AUTH_AUTH_SAM_REPLY_H__

#undef _PRINTF_ATTRIBUTE
#define _PRINTF_ATTRIBUTE(a1, a2) PRINTF_ATTRIBUTE(a1, a2)
/* this file contains prototypes for functions that are private
 * to this subsystem or library. These functions should not be
 * used outside this particular subsystem! */


/* The following definitions come from auth/auth_sam_reply.c  */

NTSTATUS auth_convert_user_info_dc_sambaseinfo(TALLOC_CTX *mem_ctx,
					      struct auth_user_info_dc *user_info_dc,
					      struct netr_SamBaseInfo **_sam);
NTSTATUS auth_convert_user_info_dc_saminfo3(TALLOC_CTX *mem_ctx,
					   struct auth_user_info_dc *user_info_dc,
					   struct netr_SamInfo3 **_sam3);

/**
 * Make a user_info_dc struct from the info3 returned by a domain logon
 */
NTSTATUS make_user_info_dc_netlogon_validation(TALLOC_CTX *mem_ctx,
					      const char *account_name,
					      uint16_t validation_level,
					      union netr_Validation *validation,
					      struct auth_user_info_dc **_user_info_dc);

/**
 * Make a user_info_dc struct from the PAC_LOGON_INFO supplied in the krb5 logon
 */
NTSTATUS make_user_info_dc_pac(TALLOC_CTX *mem_ctx,
			      struct PAC_LOGON_INFO *pac_logon_info,
			      struct auth_user_info_dc **_user_info_dc);
#undef _PRINTF_ATTRIBUTE
#define _PRINTF_ATTRIBUTE(a1, a2)

#endif /* __AUTH_AUTH_SAM_REPLY_H__ */
