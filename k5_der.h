#include <der.h>
#include <time.h>

/*
 * Message types.
 */

enum {
  KRB_AS_REQ  = 10,
  KRB_AS_REP  = 11,
  KRB_TGS_REQ = 12,
  KRB_TGS_REP = 13,
  KRB_AP_REQ  = 14,
  KRB_AP_REP  = 15,
  KRB_SAFE    = 20,
  KRB_PRIV    = 21,
  KRB_CRED    = 22,
  KRB_ENCASREPPART = 25,
  KRB_ENCKDCREPPART = 26,
  KRB_ERROR   = 30
};

/*
 * Application
 */

enum {
  APPL_TICKET = 1
};

struct HostAddress {
     int addr_type;
     krb5_data addr;
};

typedef struct HostAddress HostAddress;

struct HostAddresses {
     int number;
     HostAddress *addrs;
};

typedef struct HostAddresses HostAddresses;

struct PrincipalName {
     int name_type;
     unsigned num_strings;
     krb5_data *names;
};

enum {
     nt_unknown = 0,
     nt_principal = 1,
     nt_srv_inst = 2,
     nt_srv_hst = 3,
     nt_srv_xhst = 4,
     nt_uid = 5
};

typedef struct PrincipalName PrincipalName;

struct KdcOptions {
     unsigned
	  reserved : 1,
	  forwardable : 1,
	  forwarded : 1,
	  proxiable : 1,
	  proxy : 1,
	  allow_postdate : 1,
	  postdated : 1,
	  unused7 : 1,
	  renewable : 1,
	  unused9 : 1,
	  unused10 : 1,
	  unused11 : 1,
	  renewable_ok : 1,
	  enc_tkt_in_skey : 1,
	  renew : 1,
	  validate : 1;
};

typedef struct KdcOptions KdcOptions;

typedef krb5_data Realm;

typedef int EncryptionType;

struct  Kdc_Req {
     int pvno;
     int msg_type;
     KdcOptions kdc_options;
     PrincipalName *cname;
     Realm realm;
     PrincipalName *sname;
     time_t till;
     unsigned num_etypes;
     EncryptionType *etypes;
     HostAddress *addrs;
     unsigned num_addrs;
};

typedef struct Kdc_Req Kdc_Req;

typedef Kdc_Req As_Req;

struct EncryptedData {
     int etype;
     int *kvno;
     krb5_data cipher;
};

typedef struct EncryptedData EncryptedData;

struct Ticket {
     int tkt_vno;
     Realm realm;
     PrincipalName sname;
     EncryptedData enc_part;
};

typedef struct Ticket Ticket;

struct Kdc_Rep {
     int pvno;
     int msg_type;
     Realm realm;
     PrincipalName cname;
     Ticket ticket;
     EncryptedData enc_part;
};

typedef struct Kdc_Rep Kdc_Rep;

typedef Kdc_Rep As_Rep;

typedef Kdc_Rep Tgs_Rep;

struct EncryptionKey {
     int keytype;
     krb5_data keyvalue;
};

typedef struct EncryptionKey EncryptionKey;

struct LastReq {
     int number;
     struct {
	  int lr_type;
	  time_t lr_value;
     } *values;
};

typedef struct LastReq LastReq;

struct TicketFlags {
     unsigned forwardable:1,
	  forwarded:1,
	  proxiable:1,
	  proxy:1,
	  may_postdate:1,
	  postdated:1,
	  invalid:1,
	  renewable:1,
	  initial:1,
	  pre_authent:1,
	  hw_authent:1;
};

typedef struct TicketFlags TicketFlags;

struct EncKdcRepPart {
     EncryptionKey key;
     LastReq req;
     int nonce;
     time_t *key_expiration;
     TicketFlags flags;
     time_t authtime;
     time_t *starttime;
     time_t endtime;
     time_t *renew_till;
     Realm srealm;
     PrincipalName sname;
     HostAddresses caddr;
};

typedef struct EncKdcRepPart EncKdcRepPart;

typedef EncKdcRepPart EncASRepPart;
typedef EncKdcRepPart EncTGSRepPart;
