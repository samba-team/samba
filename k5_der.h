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

struct  Kdc_Req {
     int pvno;
     int msg_type;
     KdcOptions kdc_options;
     krb5_principal cname;
     krb5_realm realm;
     krb5_principal sname;
     krb5_time till;
     int nonce;
     unsigned num_etypes;
     krb5_enctype *etypes;
     krb5_addresses addrs;
};

typedef struct Kdc_Req Kdc_Req;

typedef Kdc_Req As_Req;

struct EncryptedData {
     int etype;
     int *kvno;
     krb5_data cipher;
};

typedef struct EncryptedData EncryptedData;

struct LastReq {
     int number;
     struct {
	  int lr_type;
	  krb5_time lr_value;
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
     krb5_keyblock key;
     LastReq req;
     int nonce;
     krb5_time *key_expiration;
     TicketFlags flags;
     krb5_time authtime;
     krb5_time *starttime;
     krb5_time endtime;
     krb5_time *renew_till;
     krb5_realm srealm;
     krb5_principal sname;
     krb5_addresses caddr;
};

typedef struct EncKdcRepPart EncKdcRepPart;

typedef EncKdcRepPart EncASRepPart;
typedef EncKdcRepPart EncTGSRepPart;

struct krb5_kdc_rep {
     int pvno;
     int msg_type;
     krb5_realm realm;
     krb5_principal cname;
     krb5_ticket ticket;
     EncryptedData enc_part;
     EncASRepPart enc_part2;
};

typedef krb5_kdc_rep As_Rep;

typedef krb5_kdc_rep Tgs_Rep;

