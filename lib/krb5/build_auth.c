#include <krb5_locl.h>
#include <krb5_error.h>

krb5_error_code
krb5_build_authenticator (krb5_context context,
			  krb5_auth_context auth_context,
			  krb5_creds *cred,
			  Checksum *cksum,
			  Authenticator **auth_result,
			  krb5_data *result)
{
  struct timeval tv;
  Authenticator *auth = malloc(sizeof(*auth));
  char buf[1024];
  int len;
  krb5_error_code ret;

  auth->authenticator_vno = 5;
  auth->crealm = malloc(cred->client->realm.length + 1);
  strncpy(auth->crealm, cred->client->realm.data, cred->client->realm.length);
  auth->crealm[cred->client->realm.length] = '\0';
  krb5_principal2principalname(&auth->cname, cred->client);

  gettimeofday(&tv, NULL);
  auth->cusec = tv.tv_usec;
  auth->ctime = tv.tv_sec;
  auth->subkey = NULL;
  auth->seq_number = NULL;
  auth->authorization_data = NULL;
  auth->cksum = cksum;

  /* XXX - Copy more to auth_context? */

  if (auth_context) {
    auth_context->authenticator->cusec = tv.tv_usec;
    auth_context->authenticator->ctime = tv.tv_sec;
  }

  memset (buf, 0, sizeof(buf));
  len = encode_Authenticator (buf + sizeof(buf) - 1, sizeof(buf), auth);

  ret = krb5_encrypt (context, buf + sizeof(buf) - len, len, &cred->session, result);

  if (auth_result)
    *auth_result = auth;
  else
    free (auth);
  return ret;
}
#if 0

  /*
  len = encode_Authenticator(buf + sizeof(buf) - 9,
			     sizeof(buf) - 8 - 12,
			     auth);

			     */
  

  p = buf + sizeof(buf) - 8 - len;
  
  p -= 12;
  len += 12;
  len = (len + 7) & ~7;
  crc_init_table ();
  crc = crc_update(p, len, 0);
#if 0
  memcpy(p + 8, &crc, 4);
#endif
  p[8]  = crc & 0xff;
  p[9]  = (crc >> 8)  & 0xff;
  p[10] = (crc >> 16) & 0xff;
  p[11] = (crc >> 24) & 0xff;
  result->length = len;
  result->data = malloc(len);
  memcpy(result->data, p, len);

}

#endif
