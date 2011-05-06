struct PAC_LOGON_INFO;

#include "libads/ads_status.h"

/* The following definitions come from libads/kerberos_verify.c  */

NTSTATUS ads_verify_ticket(TALLOC_CTX *mem_ctx,
			   const char *realm,
			   time_t time_offset,
			   const DATA_BLOB *ticket,
			   char **principal,
			   struct PAC_LOGON_INFO **logon_info,
			   DATA_BLOB *ap_rep,
			   DATA_BLOB *session_key,
			   bool use_replay_cache);

/* The following definitions come from libads/kerberos.c  */

int kerberos_kinit_password_ext(const char *principal,
				const char *password,
				int time_offset,
				time_t *expire_time,
				time_t *renew_till_time,
				const char *cache_name,
				bool request_pac,
				bool add_netbios_addr,
				time_t renewable_time,
				NTSTATUS *ntstatus);
int ads_kdestroy(const char *cc_name);
char* kerberos_standard_des_salt( void );
bool kerberos_secrets_store_des_salt( const char* salt );
char* kerberos_secrets_fetch_des_salt( void );
char *kerberos_get_default_realm_from_ccache( void );
char *kerberos_get_realm_from_hostname(const char *hostname);

bool kerberos_secrets_store_salting_principal(const char *service,
					      int enctype,
					      const char *principal);
int kerberos_kinit_password(const char *principal,
			    const char *password,
			    int time_offset,
			    const char *cache_name);
bool create_local_private_krb5_conf_for_domain(const char *realm,
						const char *domain,
						const char *sitename,
						struct sockaddr_storage *pss,
						const char *kdc_name);

/* The following definitions come from libads/authdata.c  */

NTSTATUS kerberos_return_pac(TALLOC_CTX *mem_ctx,
			     const char *name,
			     const char *pass,
			     time_t time_offset,
			     time_t *expire_time,
			     time_t *renew_till_time,
			     const char *cache_name,
			     bool request_pac,
			     bool add_netbios_addr,
			     time_t renewable_time,
			     const char *impersonate_princ_s,
			     struct PAC_LOGON_INFO **logon_info);

/* The following definitions come from libads/krb5_setpw.c  */

ADS_STATUS ads_krb5_set_password(const char *kdc_host, const char *princ,
				 const char *newpw, int time_offset);
ADS_STATUS kerberos_set_password(const char *kpasswd_server,
				 const char *auth_principal, const char *auth_password,
				 const char *target_principal, const char *new_password,
				 int time_offset);
