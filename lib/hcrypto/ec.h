
struct EC_KEY;
struct EC_GROUP;

typedef struct EC_KEY EC_KEY;
typedef struct EC_GROUP EC_GROUP;

unsigned long
EC_GROUP_get_degree(EC_GROUP *);

EC_GROUP *
EC_KEY_get0_group(EC_KEY *);

int
EC_GROUP_get_order(EC_GROUP *, BIGNUM *, BN_CTX *);

EC_KEY *
o2i_ECPublicKey(EC_KEY **key, unsigned char **, size_t);

void
EC_KEY_free(EC_KEY *);

EC_KEY *
EC_KEY_free(void);

EC_GROUP *
EC_GROUP_new_by_curve_name(int nid);

void
EC_KEY_set_group(EC_KEY *, EC_GROUP *);

void
EC_GROUP_free(EC_GROUP *);

int
EC_KEY_check_key(const EC_KEY *);

const BIGNUM *EC_KEY_get0_private_key(const EC_KEY *);

int EC_KEY_set_private_key(EC_KEY *, const BIGNUM *);

