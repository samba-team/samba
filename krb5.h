#ifndef __KRB5_H__
#define __KRB5_H__

#include <sys/types.h>
#include <stdarg.h>

/* types */
typedef int	int32_t;
typedef short 	int16_t;
typedef char 	int8_t;

typedef int32_t	krb5_int32;
typedef int16_t	krb5_int16;
typedef int8_t	krb5_int8;

typedef unsigned int krb5_uint32;
typedef unsigned short krb5_uint16;
typedef unsigned char krb5_uint8;

typedef int krb5_boolean;

typedef krb5_int32 krb5_error_code;



typedef void *krb5_pointer;
typedef const void *krb5_const_pointer;

typedef struct krb5_data{
  size_t length;
  krb5_pointer data;
} krb5_data;


typedef enum krb5_cksumtype { 
  CKSUMTYPE_NONE		= 0,
  CKSUMTYPE_CRC32		= 1,
  CKSUMTYPE_RSA_MD4		= 2,
  CKSUMTYPE_RSA_MD4_DES		= 3,
  CKSUMTYPE_DES_MAC		= 4,
  CKSUMTYPE_DES_MAC_K		= 5,
  CKSUMTYPE_RSA_MD4_DES_K	= 6,
  CKSUMTYPE_RSA_MD5_DES		= 7,
} krb5_cksumtype;



typedef enum krb5_enctype { 
  ETYPE_NONE		= 0,
  ETYPE_DES_CBC_CRC	= 1,
  ETYPE_DES_CBC_MD4	= 2,
  ETYPE_DES_CBC_MD5	= 3
} krb5_enctype;

typedef enum krb5_preauthtype {
  KRB5_PADATA_NONE		= 0,
  KRB5_PADATA_AP_REQ,
  KRB5_PADATA_TGS_REQ		= 1,
  KRB5_PADATA_PW_SALT		= 3,
  KRB5_PADATA_ENC_TIMESTAMP	= 2,
  KRB5_PADATA_ENC_SECURID
} krb5_preauthtype;


typedef enum krb5_address_type { 
  KRB5_ADDRESS_INET = AF_INET,
} krb5_address_type;

typedef struct krb5_address{
  krb5_address_type type;
  krb5_data address;
} krb5_address;



typedef enum krb5_keytype { KEYTYPE_DES } krb5_keytype;

typedef struct krb5_keyblock{
  krb5_keytype keytype;
  krb5_data contents;
} krb5_keyblock;


typedef struct krb5_context_data{
  krb5_enctype *etypes;
  char *default_realm;
  krb5_config_file *cf;
} krb5_context_data;

typedef krb5_context_data *krb5_context;


typedef time_t krb5_time;

typedef struct krb5_times{
  krb5_time endtime;
  krb5_time starttime;
  krb5_time renew_till;
} krb5_times;

typedef struct krb5_ticket{
  int kvno;
  krb5_principal sprinc;
  krb5_data enc_part;
  krb5_data enc_part2;
  krb5_enctype etype;
}krb5_ticket;



#define KRB5_PARSE_MALFORMED 17
#define KRB5_PROG_ETYPE_NOSUPP 4711

typedef enum k{
  KRB_NT_UNKNOWNN	= 0,
  KRB_NT_PRINCIPAL	= 1.
  KRB_NT_SRV_INST	= 2,
  KRB_NT_SRV_HST	= 3,
  KRB_NT_SRV_XHST	= 4,
  KRB_NT_UID		= 5
};

typedef struct krb5_principal_data{
  int type;
  krb5_data realm;
  krb5_data *comp;
  int ncomp;
}krb5_principal_data;

typedef krb5_principal_data *krb5_principal;
typedef const krb5_principal_data *krb5_const_principal;

typedef struct krb5_creds {
  krb5_principal client;
  krb5_principal server;
  krb5_keyblock session;
  krb5_times times;
  krb5_ticket ticket;

  krb5_ticket second_ticket; /* ? */
  krb5_data authdata; /* ? */
  
} krb5_creds;


typedef struct krb5_authenticator_data{
  int dummy;
} krb5_authenticator_data;

typedef krb5_authenticator_data *krb5_authenticator;

typedef struct krb5_rcache{
  int dummy;
}krb5_rcache;

typedef struct krb5_ccache{
  krb5_data data;
}krb5_ccache;

typedef struct krb5_fcache{
  char *filename;
};

typedef struct krb5_cc_cursor{
  int dummy;
}krb5_cc_cursor;

typedef struct krb5_keytab{
  int dummy;
}krb5_keytab;


typedef struct krb5_auth_context{
  krb5_int32 flags;
  krb5_cksumtype cksumtype;

  krb5_address local_address;
  krb5_address remote_address;
  krb5_keyblock key;
  krb5_keyblock local_subkey;
  krb5_keyblock remote_subkey;

  krb5_int32 local_seqnumber;
  krb5_int32 remote_seqnumber;

  krb5_authenticator authenticator;
  
  krb5_pointer i_vector;
  
  krb5_rcache rcache;
  
}krb5_auth_context;


typedef krb5_uint32 krb5_flags;

typedef struct krb5_kdc_rep{
  int dummy;
}krb5_kdc_rep;


krb5_error_code
krb5_init_context(krb5_context *context);


krb5_error_code
krb5_get_cred_from_kdc(krb5_context,
		       krb5_ccache ccache,
		       krb5_creds *in_cred,
		       krb5_creds **out_cred,
		       krb5_creds **tgts);


krb5_error_code
krb5_get_credentials(krb5_context context,
		     krb5_flags options,
		     krb5_ccache ccache,
		     krb5_creds *in_creds,
		     krb5_creds *out_creds);

typedef krb5_error_code (*krb5_key_proc)(krb5_context context,
					 const krb5_keytype type,
					 krb5_data *salt,
					 krb5_const_pointer keyseed,
					 krb5_keyblock **key);
typedef krb5_error_code (*krb5_decrypt_proc)(krb5_context context,
					     const krb5_keyblock *key,
					     krb5_const_pointer *decrypt_arg,
					     krb5_kdc_rep *dec_rep);

krb5_error_code
krb5_get_in_tkt(krb5_context context,
		krb5_flags options,
		krb5_address *const *addrs,
		const krb5_enctype *etypes,
		const krb5_preauthtype *ptypes,
		krb5_key_proc key_proc,
		krb5_const_pointer keyseed,
		krb5_decrypt_proc decrypt_proc,
		krb5_const_pointer decryptarg,
		krb5_creds *creds,
		krb5_ccache ccache,
		krb5_kdc_rep **ret_as_reply);


krb5_error_code
krb5_mk_req(krb5_context context,
	    krb5_auth_context **auth_context,
	    const krb5_flags ap_req_options,
	    char *service,
	    char *hostname,
	    krb5_data *in_data,
	    krb5_ccache ccache,
	    krb5_data *outbuf);

krb5_error_code
krb5_generate_subkey(krb5_context context,
		     const krb5_keyblock *key,
		     krb5_keyblock **subkey);


krb5_error_code
krb5_rd_req(krb5_context context,
	    krb5_auth_context **auth_context,
	    const krb5_data *inbuf,
	    krb5_const_principal server,
	    krb5_keytab keytab,
	    krb5_flags *ap_req_options,
	    krb5_ticket **ticket);


krb5_error_code
krb5_parse_name(krb5_context context,
		const char *name,
		krb5_principal *principal);

void
krb5_free_principal(krb5_principal principal);

krb5_error_code
krb5_unparse_name(krb5_context context,
		  krb5_principal principal,
		  char **name);

krb5_error_code
krb5_unparse_name_ext(krb5_context context,
		      krb5_const_principal principal,
		      char **name,
		      size_t *size);

krb5_data*
krb5_princ_realm(krb5_context context,
		 krb5_principal principal);

void
krb5_princ_set_realm(krb5_context context,
		     krb5_principal principal,
		     krb5_data *realm);

krb5_error_code
krb5_build_principal(krb5_context context,
		     krb5_principal *principal,
		     int rlen,
		     const char *realm,
		     ...);

krb5_error_code
krb5_build_principal_va(krb5_context context,
			krb5_principal *principal,
			int rlen,
			const char *realm,
			va_list ap);

krb5_error_code
krb5_build_principal_ext(krb5_context context,
			 krb5_principal *principal,
			 int rlen,
			 const char *realm,
			 ...);

krb5_error_code
krb5_copy_principal(krb5_context context,
		    krb5_const_principal inprinc,
		    krb5_principal *outprinc);

krb5_boolean
krb5_principal_compare(krb5_context context,
		       krb5_const_principal princ1,
		       krb5_const_principal princ2);

krb5_boolean
krb5_realm_compare(krb5_context context,
		   krb5_const_principal princ1,
		   krb5_const_principal princ2);
		   
krb5_error_code
krb5_425_conv_principal(krb5_context context,
			const char *name,
			const char *instance,
			const char *realm,
			krb5_principal *princ);

krb5_error_code
krb5_get_krbhst (krb5_context context,
		 const krb5_data *realm,
		 char ***hostlist);

krb5_error_code
krb5_free_krbhst (krb5_context context,
		  char *const *hostlist);


#endif /* __KRB5_H__ */

