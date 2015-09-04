#ifndef LIB_CRYPTO_AES_TEST_H
#define LIB_CRYPTO_AES_TEST_H

struct aes_mode_testvector {
	DATA_BLOB K;
	DATA_BLOB N;
	DATA_BLOB A;
	DATA_BLOB P;
	DATA_BLOB C;
	DATA_BLOB T;
	const char *mode;
	bool aes_cmac_128;
	bool aes_ccm_128;
	bool aes_gcm_128;
	const char *location;
};

#define AES_MODE_TESTVECTOR(_mode, _k, _n, _a, _p, _c, _t) \
	{ \
		.K = strhex_to_data_blob(tctx, _k), \
		.N = strhex_to_data_blob(tctx, _n), \
		.A = strhex_to_data_blob(tctx, _a), \
		.P = strhex_to_data_blob(tctx, _p), \
		.C = strhex_to_data_blob(tctx, _c), \
		.T = strhex_to_data_blob(tctx, _t), \
		._mode = true, \
		.mode = #_mode, \
		.location = __location__, \
	}

#define aes_mode_testvector_debug(tv, P, C, T) \
	_aes_mode_testvector_debug(tv, P, C, T, __location__)
static inline void _aes_mode_testvector_debug(const struct aes_mode_testvector *tv,
					      const DATA_BLOB *P,
					      const DATA_BLOB *C,
					      const DATA_BLOB *T,
					      const char *location)
{
	printf("location: %s\n", location);
	printf("TEST: %s\n", tv->location);
	printf("MODE: %s\n", tv->mode);
	printf("K\n");
	dump_data(0, tv->K.data, tv->K.length);
	printf("N\n");
	dump_data(0, tv->N.data, tv->N.length);
	printf("A\n");
	dump_data(0, tv->A.data, tv->A.length);
	printf("P\n");
	dump_data(0, tv->P.data, tv->P.length);
	if (P) {
		printf("PV\n");
		dump_data(0, P->data, P->length);
	}
	printf("C\n");
	dump_data(0, tv->C.data, tv->C.length);
	if (C) {
		printf("CV\n");
		dump_data(0, C->data, C->length);
	}
	printf("T\n");
	dump_data(0, tv->T.data, tv->T.length);
	if (T) {
		printf("TV\n");
		dump_data(0, T->data, T->length);
	}
}
#endif /* LIB_CRYPTO_AES_TEST_H */
