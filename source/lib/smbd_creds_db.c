#include "includes.h"

extern int DEBUGLEVEL;

static TDB_CONTEXT *db = NULL;

static char *make_creds_key(uint32 pid, uint16 vuid, int *klen)
{
	char *k;

	(*klen) = sizeof(pid) + sizeof(vuid);
	k = malloc((*klen) * sizeof(char));

	if (k != NULL)
	{
		*((uint32*)k) = pid;
		*((uint16*)(k+sizeof(pid)) = pid;

		DEBUG(10,("make_creds_key: pid: %x vuid %x\n",
		           pid, vuid));
		dump_data(10, k, (*klen));
	}

	return k;
}

BOOL smbd_cred_get(uint32 pid, uint16 vuid, struct smbd_creds *dc)
{
	int klen;
	char *k;
	TDB_DATA key, data;

	DEBUG(10,("smbd_cred_get:\n"));

	k = make_creds_key(pid, vuid, &klen);

	if (k == NULL) return False;

	key.dptr  = k;
	key.dsize = klen;

	data = tdb_fetch(db, key);

	free(k);

	if (data.dptr == NULL)
	{
		DEBUG(10,("smbd_cred_get: NULL data\n"));
		return False;
	}
	if (data.dsize != sizeof(*dc))
	{
		DEBUG(10,("smbd_cred_get: data size mismatch\n"));
		free(data.dptr);
		return False;
	}

	memcpy(dc, data.dptr, sizeof(*dc));
	free(data.dptr);

	dump_data(100, (char*)dc, sizeof(*dc));
	return True;
}

BOOL smbd_cred_store(uint32 pid, uint16 vuid, struct smbd_creds *dc)
{
	int klen;
	char *k;
	TDB_DATA key, data;
	BOOL ret;

	DEBUG(10,("smbd_cred_store:\n"));

	k = make_creds_key(pid, vuid, &klen);

	if (k == NULL) return False;

	key.dptr  = k;
	key.dsize = klen;

	data.dptr  = (char*)dc;
	data.dsize = sizeof(*dc);

	ret = (tdb_store(db, key, data, TDB_REPLACE) == 0);

	free(k);

	dump_data(100, (char*)dc, sizeof(*dc));

	return ret;
}

BOOL smbd_cred_init_db(void)
{
	db = tdb_open(lock_path("smbdcreds.tdb"), 0, 0, 
		      O_RDWR | O_CREAT, 0600);

	if (db == NULL)
	{
		DEBUG(0,("smbd_cred_init_db: failed\n"));
		return False;
	}
	
	DEBUG(10,("smbd_cred_init_db: opened\n"));

	return True;
}

