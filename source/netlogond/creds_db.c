#include "includes.h"

extern int DEBUGLEVEL;

static TDB_CONTEXT *db = NULL;

static char *make_creds_key(const char *domain, const char* wks, int *klen)
{
	char *k;
	int domlen = strlen(domain);
	int wkslen = strlen(wks);

	(*klen) = domlen + wkslen + 1;
	k = malloc((*klen) * sizeof(char));

	if (k != NULL)
	{
		safe_strcpy(k         , domain, domlen);
		safe_strcpy(k+domlen+1, wks   , wkslen);
		strlower(k);
		strlower(k+domlen+1);

		DEBUG(10,("make_creds_key: dom %s wks %s\n", domain, wks));
		dump_data(10, k, (*klen));
	}

	return k;
}

BOOL cred_get(const char *domain, const char* wks, struct dcinfo *dc)
{
	int klen;
	char *k;
	TDB_DATA key, data;

	DEBUG(10,("cred_get:\n"));

	k = make_creds_key(domain, wks, &klen);

	if (k == NULL) return False;

	key.dptr  = k;
	key.dsize = klen+1;

	data = tdb_fetch(db, key);

	free(k);

	if (data.dptr == NULL)
	{
		DEBUG(10,("cred_get: NULL data\n"));
		return False;
	}
	if (data.dsize != sizeof(*dc)+1)
	{
		DEBUG(10,("cred_get: data size mismatch\n"));
		free(data.dptr);
		return False;
	}

	memcpy(dc, data.dptr, sizeof(*dc));
	free(data.dptr);

	dump_data(100, (char*)dc, sizeof(*dc));
	return True;
}

BOOL cred_store(const char *domain, const char* wks, struct dcinfo *dc)
{
	int klen;
	char *k;
	TDB_DATA key, data;
	BOOL ret;

	DEBUG(10,("cred_store:\n"));

	k = make_creds_key(domain, wks, &klen);

	if (k == NULL) return False;

	key.dptr  = k;
	key.dsize = klen+1;

	data.dptr  = (char*)dc;
	data.dsize = sizeof(*dc)+1;

	ret = tdb_store(db, key, data, TDB_REPLACE) == 0;

	free(k);

	dump_data(100, (char*)dc, sizeof(*dc));

	return ret;
}

BOOL cred_init_db(void)
{
	db = tdb_open(lock_path("netlogoncreds.tdb"), 0, TDB_CLEAR_IF_FIRST, 
		      O_RDWR | O_CREAT | O_TRUNC, 0600);

	if (db == NULL)
	{
		DEBUG(0,("cred_init_db: failed\n"));
		return False;
	}
	
	DEBUG(10,("cred_init_db: opened\n"));

	return True;
}
