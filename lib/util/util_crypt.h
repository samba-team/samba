
int talloc_crypt_blob(TALLOC_CTX *mem_ctx,
		      const char *phrase,
		      const char *cmd,
		      DATA_BLOB *blob);

char *talloc_crypt_errstring(TALLOC_CTX *mem_ctx, int error);
