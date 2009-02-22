
int ECDSA_verify(int, const unsigned char *, unsigned int,
		 unsigned char *, unsigned int, EC_KEY *);
	     
int ECDSA_sign(int, const unsigned char *, unsigned int,
	       unsigned char *, unsigned int *, EC_KEY *);

int ECDSA_size(EC_KEY *);

