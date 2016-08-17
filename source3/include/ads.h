#ifndef _INCLUDE_ADS_H_
#define _INCLUDE_ADS_H_
/*
  header for ads (active directory) library routines

  basically this is a wrapper around ldap
*/

#include "libads/ads_status.h"
#include "smb_ldap.h"
#include "librpc/gen_ndr/ads.h"

struct ads_saslwrap;

struct ads_saslwrap_ops {
	const char *name;
	ADS_STATUS (*wrap)(struct ads_saslwrap *, uint8_t *buf, uint32_t len);
	ADS_STATUS (*unwrap)(struct ads_saslwrap *);
	void (*disconnect)(struct ads_saslwrap *);
};

typedef struct ads_struct ADS_STRUCT;

#ifdef HAVE_ADS
typedef LDAPMod **ADS_MODLIST;
#else
typedef void **ADS_MODLIST;
#endif

/* time between reconnect attempts */
#define ADS_RECONNECT_TIME 5

/* ldap control oids */
#define ADS_PAGE_CTL_OID 	"1.2.840.113556.1.4.319"
#define ADS_NO_REFERRALS_OID 	"1.2.840.113556.1.4.1339"
#define ADS_SERVER_SORT_OID 	"1.2.840.113556.1.4.473"
#define ADS_PERMIT_MODIFY_OID 	"1.2.840.113556.1.4.1413"
#define ADS_ASQ_OID		"1.2.840.113556.1.4.1504"
#define ADS_EXTENDED_DN_OID	"1.2.840.113556.1.4.529"
#define ADS_SD_FLAGS_OID	"1.2.840.113556.1.4.801"

/* ldap bitwise searches */
#define ADS_LDAP_MATCHING_RULE_BIT_AND	"1.2.840.113556.1.4.803"
#define ADS_LDAP_MATCHING_RULE_BIT_OR	"1.2.840.113556.1.4.804"

#define ADS_PINGS          0x0000FFFF  /* Ping response */

enum ads_extended_dn_flags {
	ADS_EXTENDED_DN_HEX_STRING	= 0,
	ADS_EXTENDED_DN_STRING		= 1 /* not supported on win2k */
};

/* this is probably not very well suited to pass other controls generically but
 * is good enough for the extended dn control where it is only used for atm */

typedef struct {
	const char *control;
	int val;
	int critical;
} ads_control;

#include "libads/ads_proto.h"

#ifdef HAVE_LDAP
#include "libads/ads_ldap_protos.h"
#endif

#include "libads/kerberos_proto.h"

#define ADS_TALLOC_CONST_FREE(PTR) do { talloc_free(discard_const(PTR)); PTR = NULL; } while (0);

#endif	/* _INCLUDE_ADS_H_ */
