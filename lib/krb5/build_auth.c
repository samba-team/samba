#include <krb5_locl.h>
#include <krb5_error.h>
#include <md4.h>

krb5_error_code
krb5_build_authenticator (krb5_context context,
			  krb5_principal client,
			  Checksum *cksum,
			  Authenticator **auth_result,
			  krb5_data *result)
{
  struct timeval tv;
  Authenticator *auth = malloc(sizeof(*auth));
  char buf[1024];
  unsigned char *p;
  int len;
  struct md4 m;
  u_int32_t crc;

  if (auth_result)
    *auth_result = auth;
  auth->authenticator_vno = 5;
  auth->crealm = malloc(client->realm.length + 1);
  strncpy(auth->crealm, client->realm.data, client->realm.length);
  auth->crealm[client->realm.length] = '\0';
  krb5_principal2principalname(&auth->cname, client);

  gettimeofday(&tv, NULL);
  auth->cusec = tv.tv_usec;
  auth->ctime = tv.tv_sec;
  auth->subkey = NULL;
  auth->seq_number = NULL;
  auth->authorization_data = NULL;
  auth->cksum = cksum;

  memset (buf, 0, sizeof(buf));
  len = encode_Authenticator(buf + sizeof(buf) - 9,
			     sizeof(buf) - 8 - 12,
			     auth);
  p = buf + sizeof(buf) - 8 - len;
  
  p -= 12;
  len += 12;
  len = (len + 7) & ~7;
  crc_init_table ();
  crc = crc_update(p, len, 0);
  memcpy(p + 8, &crc, 4);
  result->length = len;
  result->data = malloc(len);
  memcpy(result->data, p, len);
  return 0;
}
