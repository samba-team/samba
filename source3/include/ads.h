/*
  header for ads (active directory) library routines

  basically this is a wrapper around ldap
*/

typedef struct {
	void *ld;
	char *realm;
	char *ldap_server;
	char *kdc_server;
	int ldap_port;
	char *bind_path;
	time_t last_attempt;
} ADS_STRUCT;


/* time between reconnect attempts */
#define ADS_RECONNECT_TIME 5

/* timeout on searches */
#define ADS_SEARCH_TIMEOUT 10

#define UF_DONT_EXPIRE_PASSWD           0x10000
#define UF_MNS_LOGON_ACCOUNT            0x20000
#define UF_SMARTCARD_REQUIRED           0x40000
#define UF_TRUSTED_FOR_DELEGATION       0x80000
#define UF_NOT_DELEGATED               0x100000
#define UF_USE_DES_KEY_ONLY            0x200000
#define UF_DONT_REQUIRE_PREAUTH        0x400000

#define UF_TEMP_DUPLICATE_ACCOUNT       0x0100
#define UF_NORMAL_ACCOUNT               0x0200
#define UF_INTERDOMAIN_TRUST_ACCOUNT    0x0800
#define UF_WORKSTATION_TRUST_ACCOUNT    0x1000
#define UF_SERVER_TRUST_ACCOUNT         0x2000

/* account types */
#define ATYPE_GROUP               0x10000000
#define ATYPE_USER                0x30000000
