/*
  header for ads (active directory) library routines

  basically this is a wrapper around ldap
*/

typedef struct {
	void *ld; /* the active ldap structure */
	struct in_addr ldap_ip; /* the ip of the active connection, if any */
	time_t last_attempt; /* last attempt to reconnect */
	int ldap_port;
	
	int is_mine;	/* do I own this structure's memory? */
	
	/* info needed to find the server */
	struct {
		char *realm;
		char *workgroup;
		char *ldap_server;
		char *ldap_uri;
		int foreign; /* set to 1 if connecting to a foreign realm */
	} server;

	/* info needed to authenticate */
	struct {
		char *realm;
		char *password;
		char *user_name;
		char *kdc_server;
		unsigned flags;
		int time_offset;
		time_t expire;
	} auth;

	/* info derived from the servers config */
	struct {
		char *realm;
		char *bind_path;
		char *ldap_server_name;
		time_t current_time;
	} config;
} ADS_STRUCT;

/* there are 5 possible types of errors the ads subsystem can produce */
enum ads_error_type {ENUM_ADS_ERROR_KRB5, ENUM_ADS_ERROR_GSS, 
		     ENUM_ADS_ERROR_LDAP, ENUM_ADS_ERROR_SYSTEM, ENUM_ADS_ERROR_NT};

typedef struct {
	enum ads_error_type error_type;
	union err_state{		
		int rc;
		NTSTATUS nt_status;
	} err;
	/* For error_type = ENUM_ADS_ERROR_GSS minor_status describe GSS API error */
	/* Where rc represents major_status of GSS API error */
	int minor_status;
} ADS_STATUS;

#ifdef HAVE_ADS
typedef LDAPMod **ADS_MODLIST;
#else
typedef void **ADS_MODLIST;
#endif

/* macros to simplify error returning */
#define ADS_ERROR(rc) ADS_ERROR_LDAP(rc)
#define ADS_ERROR_LDAP(rc) ads_build_error(ENUM_ADS_ERROR_LDAP, rc, 0)
#define ADS_ERROR_SYSTEM(rc) ads_build_error(ENUM_ADS_ERROR_SYSTEM, rc?rc:EINVAL, 0)
#define ADS_ERROR_KRB5(rc) ads_build_error(ENUM_ADS_ERROR_KRB5, rc, 0)
#define ADS_ERROR_GSS(rc, minor) ads_build_error(ENUM_ADS_ERROR_GSS, rc, minor)
#define ADS_ERROR_NT(rc) ads_build_nt_error(ENUM_ADS_ERROR_NT,rc)

#define ADS_ERR_OK(status) ((status.error_type == ENUM_ADS_ERROR_NT) ? NT_STATUS_IS_OK(status.err.nt_status):(status.err.rc == 0))
#define ADS_SUCCESS ADS_ERROR(0)

/* time between reconnect attempts */
#define ADS_RECONNECT_TIME 5

/* timeout on searches */
#define ADS_SEARCH_TIMEOUT 10

/* ldap control oids */
#define ADS_PAGE_CTL_OID "1.2.840.113556.1.4.319"
#define ADS_NO_REFERRALS_OID "1.2.840.113556.1.4.1339"
#define ADS_SERVER_SORT_OID "1.2.840.113556.1.4.473"
#define ADS_PERMIT_MODIFY_OID "1.2.840.113556.1.4.1413"

/* UserFlags for userAccountControl */
#define UF_SCRIPT	 			0x00000001
#define UF_ACCOUNTDISABLE			0x00000002
#define UF_UNUSED_1	 			0x00000004
#define UF_HOMEDIR_REQUIRED			0x00000008

#define UF_LOCKOUT	 			0x00000010
#define UF_PASSWD_NOTREQD 			0x00000020
#define UF_PASSWD_CANT_CHANGE 			0x00000040
#define UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED	0x00000080

#define UF_TEMP_DUPLICATE_ACCOUNT       	0x00000100
#define UF_NORMAL_ACCOUNT               	0x00000200
#define UF_UNUSED_2	 			0x00000400
#define UF_INTERDOMAIN_TRUST_ACCOUNT    	0x00000800

#define UF_WORKSTATION_TRUST_ACCOUNT    	0x00001000
#define UF_SERVER_TRUST_ACCOUNT         	0x00002000
#define UF_UNUSED_3	 			0x00004000
#define UF_UNUSED_4	 			0x00008000

#define UF_DONT_EXPIRE_PASSWD			0x00010000
#define UF_MNS_LOGON_ACCOUNT			0x00020000
#define UF_SMARTCARD_REQUIRED			0x00040000
#define UF_TRUSTED_FOR_DELEGATION		0x00080000

#define UF_NOT_DELEGATED			0x00100000
#define UF_USE_DES_KEY_ONLY			0x00200000
#define UF_DONT_REQUIRE_PREAUTH			0x00400000
#define UF_UNUSED_5				0x00800000

#define UF_UNUSED_6				0x01000000
#define UF_UNUSED_7				0x02000000
#define UF_UNUSED_8				0x04000000
#define UF_UNUSED_9				0x08000000

#define UF_UNUSED_10				0x10000000
#define UF_UNUSED_11				0x20000000
#define UF_UNUSED_12				0x40000000
#define UF_UNUSED_13				0x80000000

#define UF_MACHINE_ACCOUNT_MASK (\
		UF_INTERDOMAIN_TRUST_ACCOUNT |\
		UF_WORKSTATION_TRUST_ACCOUNT |\
		UF_SERVER_TRUST_ACCOUNT \
		)

#define UF_ACCOUNT_TYPE_MASK (\
		UF_TEMP_DUPLICATE_ACCOUNT |\
		UF_NORMAL_ACCOUNT |\
		UF_INTERDOMAIN_TRUST_ACCOUNT |\
		UF_WORKSTATION_TRUST_ACCOUNT |\
		UF_SERVER_TRUST_ACCOUNT \
                )

#define UF_SETTABLE_BITS (\
		UF_SCRIPT |\
		UF_ACCOUNTDISABLE |\
		UF_HOMEDIR_REQUIRED  |\
		UF_LOCKOUT |\
		UF_PASSWD_NOTREQD |\
		UF_PASSWD_CANT_CHANGE |\
		UF_ACCOUNT_TYPE_MASK | \
		UF_DONT_EXPIRE_PASSWD | \
		UF_MNS_LOGON_ACCOUNT |\
		UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED |\
		UF_SMARTCARD_REQUIRED |\
		UF_TRUSTED_FOR_DELEGATION |\
		UF_NOT_DELEGATED |\
		UF_USE_DES_KEY_ONLY  |\
		UF_DONT_REQUIRE_PREAUTH \
		)

/* sAMAccountType */
#define ATYPE_NORMAL_ACCOUNT			0x30000000 /* 805306368 */
#define ATYPE_WORKSTATION_TRUST			0x30000001 /* 805306369 */
#define ATYPE_INTERDOMAIN_TRUST			0x30000002 /* 805306370 */ 
#define ATYPE_SECURITY_GLOBAL_GROUP		0x10000000 /* 268435456 */
#define ATYPE_DISTRIBUTION_GLOBAL_GROUP		0x10000001 /* 268435457 */
#define ATYPE_DISTRIBUTION_UNIVERSAL_GROUP 	ATYPE_DISTRIBUTION_GLOBAL_GROUP
#define ATYPE_SECURITY_LOCAL_GROUP		0x20000000 /* 536870912 */
#define ATYPE_DISTRIBUTION_LOCAL_GROUP		0x20000001 /* 536870913 */

#define ATYPE_ACCOUNT		ATYPE_NORMAL_ACCOUNT 		/* 0x30000000 805306368 */
#define ATYPE_GLOBAL_GROUP	ATYPE_SECURITY_GLOBAL_GROUP 	/* 0x10000000 268435456 */
#define ATYPE_LOCAL_GROUP	ATYPE_SECURITY_LOCAL_GROUP 	/* 0x20000000 536870912 */

/* groupType */
#define GTYPE_SECURITY_BUILTIN_LOCAL_GROUP	0x80000005	/* -2147483643 */
#define GTYPE_SECURITY_DOMAIN_LOCAL_GROUP	0x80000004	/* -2147483644 */
#define GTYPE_SECURITY_GLOBAL_GROUP		0x80000002	/* -2147483646 */
#define GTYPE_DISTRIBUTION_GLOBAL_GROUP		0x00000002	/* 2 */
#define GTYPE_DISTRIBUTION_DOMAIN_LOCAL_GROUP	0x00000004	/* 4 */
#define GTYPE_DISTRIBUTION_UNIVERSAL_GROUP	0x00000008	/* 8 */

/* Mailslot or cldap getdcname response flags */
#define ADS_PDC            0x00000001  /* DC is PDC */
#define ADS_GC             0x00000004  /* DC is a GC of forest */
#define ADS_LDAP           0x00000008  /* DC is an LDAP server */
#define ADS_DS             0x00000010  /* DC supports DS */
#define ADS_KDC            0x00000020  /* DC is running KDC */
#define ADS_TIMESERV       0x00000040  /* DC is running time services */
#define ADS_CLOSEST        0x00000080  /* DC is closest to client */
#define ADS_WRITABLE       0x00000100  /* DC has writable DS */
#define ADS_GOOD_TIMESERV  0x00000200  /* DC has hardware clock
	  				 (and running time) */
#define ADS_NDNC           0x00000400  /* DomainName is non-domain NC serviced
	  				 by LDAP server */
#define ADS_PINGS          0x0000FFFF  /* Ping response */
#define ADS_DNS_CONTROLLER 0x20000000  /* DomainControllerName is a DNS name*/
#define ADS_DNS_DOMAIN     0x40000000  /* DomainName is a DNS name */
#define ADS_DNS_FOREST     0x80000000  /* DnsForestName is a DNS name */

/* DomainCntrollerAddressType */
#define ADS_INET_ADDRESS      0x00000001
#define ADS_NETBIOS_ADDRESS   0x00000002


/* ads auth control flags */
#define ADS_AUTH_DISABLE_KERBEROS 0x01
#define ADS_AUTH_NO_BIND          0x02
#define ADS_AUTH_ANON_BIND        0x04
#define ADS_AUTH_SIMPLE_BIND      0x08
#define ADS_AUTH_ALLOW_NTLMSSP    0x10

/* Kerberos environment variable names */
#define KRB5_ENV_CCNAME "KRB5CCNAME"

/* Heimdal uses a slightly different name */
#if defined(HAVE_ENCTYPE_ARCFOUR_HMAC_MD5)
#define ENCTYPE_ARCFOUR_HMAC ENCTYPE_ARCFOUR_HMAC_MD5
#endif

/* The older versions of heimdal that don't have this
   define don't seem to use it anyway.  I'm told they
   always use a subkey */
#ifndef HAVE_AP_OPTS_USE_SUBKEY
#define AP_OPTS_USE_SUBKEY 0
#endif
