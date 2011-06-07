/* The following definitions come from rpc_client/init_netlogon.c  */

void init_netr_CryptPassword(const char *pwd,
			     unsigned char session_key[16],
			     struct netr_CryptPassword *pwd_buf);
