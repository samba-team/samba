/* 
   Unix SMB/CIFS implementation.
   Name mangling with persistent tdb
   Copyright (C) Simo Sorce 2001
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

/****************************************************************************
  Rewritten from scrach in 2001 by Simo Sorce <idra@samba.org>
 ****************************************************************************/

#include "includes.h"


/* -------------------------------------------------------------------------- **
 * External Variables...
 */

extern int case_default;    /* Are conforming 8.3 names all upper or lower?   */
extern BOOL case_mangle;    /* If true, all chars in 8.3 should be same case. */

char magic_char = '~';

/* -------------------------------------------------------------------- */

#define MANGLE_TDB_VERSION		"20010927"
#define MANGLE_TDB_FILE_NAME		"mangle.tdb"
#define MANGLED_PREFIX			"MANGLED_"
#define LONG_PREFIX			"LONG_"
#define COUNTER_PREFIX			"COUNTER_"
#define	MANGLE_COUNTER_MAX		99
#define MANGLE_SUFFIX_SIZE		3 /* "~XX" */


static TDB_CONTEXT	*mangle_tdb;

BOOL init_mangle_tdb(void)
{
	char *tdbfile;
	
	tdbfile = lock_path(MANGLE_TDB_FILE_NAME); /* this return a static pstring do not try to free it */

	/* Open tdb */
	if (!(mangle_tdb = tdb_open_log(tdbfile, 0, TDB_DEFAULT, O_RDWR | O_CREAT, 0600)))
	{
		DEBUG(0, ("Unable to open Mangle TDB\n"));
		return False;
	}

	return True;
}

/* trasform a unicode string into a dos charset string */
static int ucs2_to_dos(char *dest, const smb_ucs2_t *src, int dest_len)
{
	int src_len, ret;

	if (dest_len == -1) {
		dest_len = sizeof(pstring);
	}

	src_len = strlen_w(src)* sizeof(smb_ucs2_t);
	
	ret = convert_string(CH_UCS2, CH_DOS, src, src_len, dest, dest_len);
	if (dest_len) dest[MIN(ret, dest_len-1)] = 0;

	return ret;
}

/* trasform in a string that contain only valid chars for win filenames,
 not including a '.' */
static void strvalid(smb_ucs2_t *src)
{
	if (!src || !*src) return;

	while (*src) {
		if (!isvalid83_w(*src) || *src == UCS2_CHAR('.')) *src = UCS2_CHAR('_');
		src++;
	}
}


/* return False if something fail and
 * return 2 alloced unicode strings that contain prefix and extension
 */
static NTSTATUS mangle_get_prefix(const smb_ucs2_t *ucs2_string, smb_ucs2_t **prefix, smb_ucs2_t **extension)
{
	size_t ext_len;
	smb_ucs2_t *p;

	*extension = 0;
	*prefix = strdup_w(ucs2_string);
	if (!*prefix)
	{
		DEBUG(0,("mangle_get_prefix: out of memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}
	if ((p = strrchr_w(*prefix, UCS2_CHAR('.'))))
	{
		ext_len = strlen_w(p+1);
		if ((ext_len > 0) && (ext_len < 4) && (p != *prefix) &&
		    (NT_STATUS_IS_OK(has_valid_chars(p+1)))) /* check extension */
		{
			*p = 0;
			*extension = strdup_w(p+1);
			if (!*extension)
			{
				DEBUG(0,("mangle_get_prefix: out of memory!\n"));
				SAFE_FREE(*prefix);
				return NT_STATUS_NO_MEMORY;
			}
		}
	}
	return NT_STATUS_OK;
}


/* mangled must contain only the file name, not a path.
   and MUST be ZERO terminated */
smb_ucs2_t *unmangle(const smb_ucs2_t *mangled)
{
	TDB_DATA data, key;
	fstring keystr;
	fstring mufname;
	smb_ucs2_t *pref, *ext, *retstr;
	size_t long_len, ext_len, muf_len;

	if (strlen_w(mangled) > 12) return NULL;
	if (!strchr_w(mangled, UCS2_CHAR('~'))) return NULL;

	/* if it is a path refuse to proceed */
	if (strchr_w(mangled, UCS2_CHAR('/'))) {
		DEBUG(10, ("unmangle: cannot unmangle a path\n"));
		return NULL;
	}

	if (NT_STATUS_IS_ERR(mangle_get_prefix(mangled, &pref, &ext)))
		return NULL;

	/* mangled names are stored lowercase only */	
	strlower_w(pref);
	/* set search key */
	muf_len = ucs2_to_dos(mufname, pref, sizeof(mufname));
	SAFE_FREE(pref);
	if (!muf_len) return NULL;
	
	slprintf(keystr, sizeof(keystr) - 1, "%s%s", MANGLED_PREFIX, mufname);
	key.dptr = keystr;
	key.dsize = strlen (keystr) + 1;
	
	/* get the record */
	data = tdb_fetch(mangle_tdb, key);
	
	if (!data.dptr) /* not found */
	{
		DEBUG(5,("unmangle: failed retrieve from db %s\n", tdb_errorstr(mangle_tdb)));
		retstr = NULL;
		goto done;
	}

	if (ext)
	{
		long_len = (data.dsize / 2) - 1;
		ext_len = strlen_w(ext);
		retstr = (smb_ucs2_t *)malloc((long_len + ext_len + 2)*sizeof(smb_ucs2_t));
		if (!retstr)
		{
			DEBUG(0, ("unamngle: out of memory!\n"));
			goto done;
		}
		strncpy_w(retstr, (smb_ucs2_t *)data.dptr, long_len);
		retstr[long_len] = UCS2_CHAR('.');
		retstr[long_len + 1] = 0;
		strncat_w(retstr, ext, ext_len);
	}
	else
	{
		retstr = strdup_w((smb_ucs2_t *)data.dptr);
		if (!retstr)
		{
			DEBUG(0, ("unamngle: out of memory!\n"));
			goto done;
		}

	}

done:
	SAFE_FREE(data.dptr);
	SAFE_FREE(pref);
	SAFE_FREE(ext);

	return retstr;
}

/* unmangled must contain only the file name, not a path.
   and MUST be ZERO terminated.
   return a new allocated string if the name is yet valid 8.3
   or is mangled successfully.
   return null on error.
 */

smb_ucs2_t *mangle(const smb_ucs2_t *unmangled)
{
	TDB_DATA data, key, klock;
	pstring keystr;
	pstring longname;
	fstring keylock;
	fstring mufname;
	fstring prefix;
	BOOL tclock = False;
	char suffix[7];
	smb_ucs2_t *mangled = NULL;
	smb_ucs2_t *umpref, *ext, *p = NULL;
	size_t pref_len, ext_len, ud83_len;

	/* if it is a path refuse to proceed */
	if (strchr_w(unmangled, UCS2_CHAR('/'))) {
		DEBUG(10, ("mangle: cannot mangle a path\n"));
		return NULL;
	}

	/* if it is a valid 8_3 do not mangle again */
	if (NT_STATUS_IS_OK(is_8_3_w(unmangled)))
		return NULL;

	if (NT_STATUS_IS_ERR(mangle_get_prefix(unmangled, &umpref, &ext)))
		return NULL;

	/* test if the same is yet mangled */

	/* set search key */
	pull_ucs2(NULL, longname, umpref, sizeof(longname), 0, STR_TERMINATE);
	slprintf(keystr, sizeof(keystr)-1, "%s%s", LONG_PREFIX, longname);
	key.dptr = keystr;
	key.dsize = strlen(keystr) + 1;

	/* get the record */
	data = tdb_fetch (mangle_tdb, key);
	if (!data.dptr) /* not found */
	{
		smb_ucs2_t temp[9];
		size_t c, pos;

		if (tdb_error(mangle_tdb) != TDB_ERR_NOEXIST)
		{
			DEBUG(0, ("mangle: database retrieval error: %s\n",
					tdb_errorstr(mangle_tdb)));
			goto done;
		}

		/* if not find the first free possibile mangled name */

		pos = strlen_w(umpref);
		if ((8 - MANGLE_SUFFIX_SIZE) < pos)
			pos = 8 - MANGLE_SUFFIX_SIZE;
		pos++;
		do
		{
			pos--;
			if (pos == 0)
			{
				DEBUG(0, ("mangle: unable to mangle file name!\n"));
				goto done;
			}
			strncpy_w(temp, umpref, pos);
			temp[pos] = 0;
			strlower_w(temp);

			/* convert any invalid char into '_' */
			strvalid(temp);
			ud83_len = ucs2_to_dos(prefix, temp, sizeof(prefix));
			if (!ud83_len) goto done;
		}
		while (ud83_len > 8 - MANGLE_SUFFIX_SIZE);

		slprintf(keylock, sizeof(keylock)-1, "%s%s", COUNTER_PREFIX, prefix);
		klock.dptr = keylock;
		klock.dsize = strlen(keylock) + 1;

		c = 0;
		data.dptr = (char *)&c;
		data.dsize = sizeof(uint32);
		/* try to insert a new counter prefix, if it exist the call will
		   fail (correct) otherwise it will create a new entry with counter set
		   to 0
		 */
		if(tdb_store(mangle_tdb, klock, data, TDB_INSERT) != TDB_SUCCESS)
		{
			if (tdb_error(mangle_tdb) != TDB_ERR_EXISTS)
			{
				DEBUG(0, ("mangle: database store error: %s\n",
					tdb_errorstr(mangle_tdb)));
				goto done;
			}
		}

		/* lock the mangle counter for this prefix */		
		if (tdb_chainlock(mangle_tdb, klock))
		{
			DEBUG(0,("mangle: failed to lock database\n!"));
			goto done;
		}
		tclock = True;

		data = tdb_fetch(mangle_tdb, klock);
		if (!data.dptr)
		{
			DEBUG(0, ("mangle: database retrieval error: %s\n",
					tdb_errorstr(mangle_tdb)));
			goto done;
		}
		c = *((uint32 *)data.dptr);
		c++;
		
		if (c > MANGLE_COUNTER_MAX)
		{
			DEBUG(0, ("mangle: error, counter overflow!\n"));
			goto done;
		}
			
		temp[pos] = UCS2_CHAR('~');
		temp[pos+1] = 0;
		snprintf(suffix, 7, "%.6d", c);
		strncat_wa(temp, &suffix[7 - MANGLE_SUFFIX_SIZE], MANGLE_SUFFIX_SIZE);

		ud83_len = ucs2_to_dos(mufname, temp, sizeof(mufname));
		if (!ud83_len) goto done;
		if (ud83_len > 8)
		{
			DEBUG(0, ("mangle: darn, logic error aborting!\n"));
			goto done;
		}
			
		/* store the long entry with mangled key */
		slprintf(keystr, sizeof(keystr)-1, "%s%s", MANGLED_PREFIX, mufname);
		key.dptr = keystr;
		key.dsize = strlen (keystr) + 1;
		data.dsize = (strlen_w(umpref) + 1) * sizeof (smb_ucs2_t);
		data.dptr = (void *)umpref;

		if (tdb_store(mangle_tdb, key, data, TDB_INSERT) != TDB_SUCCESS)
		{
			DEBUG(0, ("mangle: database store error: %s\n",
					tdb_errorstr(mangle_tdb)));
			goto done;
		}

		/* store the mangled entry with long key*/
		pull_ucs2(NULL, longname, umpref, sizeof(longname), 0, STR_TERMINATE);
		slprintf(keystr, sizeof(keystr)-1, "%s%s", LONG_PREFIX, longname);
		key.dptr = keystr;
		key.dsize = strlen (keystr) + 1;
		data.dsize = strlen(mufname) + 1;
		data.dptr = mufname;
		if (tdb_store(mangle_tdb, key, data, TDB_INSERT) != TDB_SUCCESS)
		{
			DEBUG(0, ("mangle: database store failed: %s\n",
					tdb_errorstr(mangle_tdb)));

			/* try to delete the mangled key entry to avoid later inconsistency */
			slprintf(keystr, sizeof(keystr)-1, "%s%s", MANGLED_PREFIX, mufname);
			key.dptr = keystr;
			key.dsize = strlen (keystr) + 1;
			if (!tdb_delete(mangle_tdb, key))
			{
				DEBUG(0, ("mangle: severe error, mangled tdb may be inconsistent!\n"));
			}
			goto done;
		}

		p = strdup_w(temp);
		if (!p)
		{
			DEBUG(0,("mangle: out of memory!\n"));
			goto done;
		}
		
		data.dptr = (char *)&c;
		data.dsize = sizeof(uint32);
		/* store the counter */
		if(tdb_store(mangle_tdb, klock, data, TDB_REPLACE) != TDB_SUCCESS)
		{
			DEBUG(0, ("mangle: database store failed: %s\n",
					tdb_errorstr(mangle_tdb)));
			/* try to delete the mangled and long key entry to avoid later inconsistency */
			slprintf(keystr, sizeof(keystr)-1, "%s%s", MANGLED_PREFIX, mufname);
			key.dptr = keystr;
			key.dsize = strlen (keystr) + 1;
			if (!tdb_delete(mangle_tdb, key))
			{
				DEBUG(0, ("mangle: severe error, mangled tdb may be inconsistent!\n"));
			}
			slprintf(keystr, sizeof(keystr)-1, "%s%s", LONG_PREFIX, longname);
			key.dptr = keystr;
			key.dsize = strlen (keystr) + 1;
			if (!tdb_delete(mangle_tdb, key))
			{
				DEBUG(0, ("mangle: severe error, mangled tdb may be inconsistent!\n"));
			}
			goto done;
		}

		tclock = False;
		tdb_chainunlock(mangle_tdb, klock);
	}
	else /* FOUND */
	{
		p = acnv_dosu2(data.dptr);
		if (!p)
		{
			DEBUG(0,("mangle: internal error acnv_dosu2() failed!\n"));
			goto done;
		}
	}
		
	if (ext)
	{
		pref_len = strlen_w(p);
		ext_len = strlen_w(ext);
		mangled = (smb_ucs2_t *)malloc((pref_len + ext_len + 2)*sizeof(smb_ucs2_t));
		if (!mangled)
		{
			DEBUG(0,("mangle: out of memory!\n"));
			goto done;
		}
		strncpy_w (mangled, p, pref_len);
		mangled[pref_len] = UCS2_CHAR('.');
		mangled[pref_len + 1] = 0;
		strncat_w (mangled, ext, ext_len);
	}
	else
	{
		mangled = strdup_w(p);
		if (!mangled)
		{
			DEBUG(0,("mangle: out of memory!\n"));
			goto done;
		}
	}

	/* mangled name are returned in upper or lower case depending on
	   case_default value */
	strnorm_w(mangled);

done:
	if (tclock) tdb_chainunlock(mangle_tdb, klock);
	SAFE_FREE(p);
	SAFE_FREE(umpref);
	SAFE_FREE(ext);

	return mangled;
}


/* non unicode compatibility functions */

char *dos_mangle(const char *dos_unmangled)
{
	smb_ucs2_t *in, *out;
	char *dos_mangled;

	if (!dos_unmangled || !*dos_unmangled) return NULL;

	in = acnv_dosu2(dos_unmangled);
	if (!in)
	{
		DEBUG(0,("dos_mangle: internal error acnv_dosu2() failed!\n"));
		return NULL;
	}

	out = mangle(in);
	if (!out)
	{
		SAFE_FREE(in);
		return NULL;
	}

	dos_mangled = acnv_u2dos(out);
	if (!dos_mangled)
	{
		DEBUG(0,("dos_mangle: internal error acnv_u2dos() failed!\n"));
		goto done;
	}

done:
	SAFE_FREE(in);
	SAFE_FREE(out);
	return dos_mangled;
}

char *dos_unmangle(const char *dos_mangled)
{
	smb_ucs2_t *in, *out;
	char *dos_unmangled;

	if (!dos_mangled || !*dos_mangled) return NULL;

	in = acnv_dosu2(dos_mangled);
	if (!in)
	{
		DEBUG(0,("dos_unmangle: internal error acnv_dosu2() failed!\n"));
		return NULL;
	}

	out = unmangle(in);
	if (!out)
	{
		SAFE_FREE(in);
		return NULL;
	}

	dos_unmangled = acnv_u2dos(out);
	if (!dos_unmangled)
	{
		DEBUG(0,("dos_unmangle: internal error acnv_u2dos failed!\n"));
		goto done;
	}

done:
	SAFE_FREE(in);
	SAFE_FREE(out);
	return dos_unmangled;
}

BOOL is_8_3(const char *fname, BOOL check_case)
{
	const char *f;
	smb_ucs2_t *ucs2name;
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	if (!fname || !*fname) return False;
	if ((f = strrchr(fname, '/')) == NULL) f = fname;
	else f++;

	DEBUG(10,("is_8_3: testing [%s]\n", f));

	if (strlen(f) > 12) return False;
	
	ucs2name = acnv_uxu2(f);
	if (!ucs2name)
	{
		DEBUG(0,("is_8_3: internal error acnv_uxu2() failed!\n"));
		goto done;
	}

	ret = is_8_3_w(ucs2name);

done:
	SAFE_FREE(ucs2name);

	DEBUG(10,("is_8_3: returning -> %s\n", NT_STATUS_IS_OK(ret)?"True":"False"));

	if (NT_STATUS_IS_ERR(ret)) return False;
	else return True;
}

NTSTATUS is_8_3_w(const smb_ucs2_t *fname)
{
	smb_ucs2_t *pref = 0, *ext = 0;
	size_t plen;
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	if (!fname || !*fname) return NT_STATUS_INVALID_PARAMETER;

	DEBUG(10,("is_8_3_w: testing\n")); /* [%s]\n", fname)); */

	if (strlen_w(fname) > 12) return NT_STATUS_UNSUCCESSFUL;
	
	if (strcmp_wa(fname, ".") == 0 || strcmp_wa(fname, "..") == 0)
		return NT_STATUS_OK;

	if (NT_STATUS_IS_ERR(is_valid_name(fname))) goto done;

	if (NT_STATUS_IS_ERR(mangle_get_prefix(fname, &pref, &ext))) goto done;
	plen = strlen_w(pref);

	if (strchr_wa(pref, '.')) goto done;
	if (plen < 1 || plen > 8) goto done;
	if (ext) if (strlen_w(ext) > 3) goto done;

	ret = NT_STATUS_OK;

done:
	SAFE_FREE(pref);
	SAFE_FREE(ext);
	return ret;
}

NTSTATUS has_valid_chars(const smb_ucs2_t *s)
{
	NTSTATUS ret = NT_STATUS_OK;

	if (!s || !*s) return NT_STATUS_INVALID_PARAMETER;

	DEBUG(10,("has_valid_chars: testing\n")); /* [%s]\n", s)); */
	
	/* CHECK: this should not be necessary if the ms wild chars
	   are not valid in valid.dat  --- simo */
	if (ms_has_wild_w(s)) return NT_STATUS_UNSUCCESSFUL;

	while (*s) {
		if(!isvalid83_w(*s)) return NT_STATUS_UNSUCCESSFUL;
		s++;
	}

	return ret;
}

NTSTATUS is_valid_name(const smb_ucs2_t *fname)
{
	smb_ucs2_t *str, *p;
	NTSTATUS ret = NT_STATUS_OK;

	if (!fname || !*fname) return NT_STATUS_INVALID_PARAMETER;

	DEBUG(10,("is_valid_name: testing\n")); /* [%s]\n", s)); */

	if (*fname == UCS2_CHAR('.')) return NT_STATUS_UNSUCCESSFUL;
	
	ret = has_valid_chars(fname);
	if (NT_STATUS_IS_ERR(ret)) return ret;

	str = strdup_w(fname);
	p = strchr_w(str, UCS2_CHAR('.'));
	if (p) *p = 0;
	strupper_w(str);
	p = &(str[1]);

	switch(str[0])
	{
	case UCS2_CHAR('A'):
		if(strcmp_wa(p, "UX") == 0)
			ret = NT_STATUS_UNSUCCESSFUL;
		break;
	case UCS2_CHAR('C'):
		if((strcmp_wa(p, "LOCK$") == 0)
		|| (strcmp_wa(p, "ON") == 0)
		|| (strcmp_wa(p, "OM1") == 0)
		|| (strcmp_wa(p, "OM2") == 0)
		|| (strcmp_wa(p, "OM3") == 0)
		|| (strcmp_wa(p, "OM4") == 0)
		)
			ret = NT_STATUS_UNSUCCESSFUL;
		break;
	case UCS2_CHAR('L'):
		if((strcmp_wa(p, "PT1") == 0)
		|| (strcmp_wa(p, "PT2") == 0)
		|| (strcmp_wa(p, "PT3") == 0)
		)
			ret = NT_STATUS_UNSUCCESSFUL;
		break;
	case UCS2_CHAR('N'):
		if(strcmp_wa(p, "UL") == 0)
			ret = NT_STATUS_UNSUCCESSFUL;
		break;
	case UCS2_CHAR('P'):
		if(strcmp_wa(p, "RN") == 0)
			ret = NT_STATUS_UNSUCCESSFUL;
		break;
	default:
		break;
	}

	SAFE_FREE(str);
	return ret;
}

BOOL is_mangled(const char *s)
{
	smb_ucs2_t *u2, *res;
	BOOL ret = False;
	
	DEBUG(10,("is_mangled: testing [%s]\n", s));
	
	if (!s || !*s) return False;
	if ((strlen(s) > 12) || (!strchr(s, '~'))) return False;
	
	u2 = acnv_dosu2(s);
	if (!u2)
	{
		DEBUG(0,("is_mangled: internal error acnv_dosu2() failed!!\n"));
		return ret;
	}

	res = unmangle(u2);
	if (res) ret = True;
	SAFE_FREE(res);
	SAFE_FREE(u2);
	DEBUG(10,("is_mangled: returning  [%s]\n", ret?"True":"False"));
	return ret;
}

NTSTATUS is_mangled_w(const smb_ucs2_t *s)
{
	smb_ucs2_t *res;
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;
	
	res = unmangle(s);
	if (res) ret = NT_STATUS_OK;
	SAFE_FREE(res);
	return ret;
}

NTSTATUS path_has_mangled(const smb_ucs2_t *s)
{
	smb_ucs2_t *p, *f, *b;
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	if (!s || !*s) return NT_STATUS_INVALID_PARAMETER;

	p = strdup_w(s);
	if (!p) return NT_STATUS_NO_MEMORY;
	trim_string_wa(p, "/", "/");
	f = b = p;
	while (b) {
		b = strchr_w(f, UCS2_CHAR('/'));
		if (b) *b = 0;
		if (NT_STATUS_IS_OK(is_mangled_w(f))) {
			ret = NT_STATUS_OK;
			goto done;
		}
		f = b + 1;
	}
done:
	SAFE_FREE(p);
	return ret;
}

/* backward compatibility functions */

void reset_mangled_cache(void)
{
	DEBUG(10,("reset_mangled_cache: compatibility function, remove me!\n"));
}

BOOL check_mangled_cache(char *s)
{
	smb_ucs2_t *u2, *res;
	BOOL ret = False;

	DEBUG(10,("check_mangled_cache: I'm so ugly, please remove me!\n"));
	DEBUG(10,("check_mangled_cache: testing -> [%s]\n", s));

	if (!s || !*s) return False;

	u2 = acnv_dosu2(s);
	if (!u2)
	{
		DEBUG(0,("check_mangled_cache: out of memory!\n"));
		return ret;
	}

	res = unmangle(u2);
	if (res)
	{
		
		ucs2_to_dos (s, res, PSTRING_LEN);
		/* We MUST change this brainded interface,
		   we do not know how many chars will be used
		   in dos so i guess they will be no more than
		   double the size of the unicode string
		          ---simo */
		DEBUG(10,("check_mangled_cache: returning -> [%s]\n", s));
		ret = True;
	}
	SAFE_FREE(res);
	SAFE_FREE(u2);
	DEBUG(10,("check_mangled_cache: returning -> %s\n", ret?"True":"False"));
	return ret;
}

void mangle_name_83(char *s)
{
	smb_ucs2_t *u2, *res;

	DEBUG(10,("mangle_name_83: I'm so ugly, please remove me!\n"));
	DEBUG(10,("mangle_name_83: testing -> [%s]\n", s));

	if (!s || !*s) return;
	
	u2 = acnv_dosu2(s);
	if (!u2)
	{
		DEBUG(0,("mangle_name_83: internal error acnv_dosu2() failed!\n"));
		return;
	}

	res = mangle(u2);
	if (res) ucs2_to_dos (s, res, 13); /* ugly, but must be done this way */
	DEBUG(10,("mangle_name_83: returning -> [%s]\n", s));
	SAFE_FREE(res);
	SAFE_FREE(u2);
}

BOOL name_map_mangle(char *OutName, BOOL need83, BOOL cache83, int snum)
{
	DEBUG(10,("name_map_mangle: I'm so ugly, please remove me!\n"));

	if (!need83) return True;
	/* if (is_8_3(OutName, True)) return True; */
	/* Warning: we should check for invalid chars in file name and mangle
	   if invalid chars found --simo*/

	mangle_name_83(OutName);
	return True;
}



#if 0 /* TEST_MANGLE_CODE */

#define LONG		"this_is_a_long_file_name"
#define	LONGM		"this_~01"
#define SHORT		"short"
#define	SHORTM		"short~01"
#define EXT1		"ex1"
#define EXT2		"e2"
#define EXT3		"3"
#define EXTFAIL		"longext"
#define EXTNULL		""

static void unmangle_test (char *name, char *ext)
{
	smb_ucs2_t ucs2_name[2048];
	smb_ucs2_t *retstr;
	pstring unix_name;	

	push_ucs2(NULL, ucs2_name, name, sizeof(ucs2_name), STR_TERMINATE);
	if (ext)
	{
		strncat_wa(ucs2_name, ".", 1);
		strncat_wa(ucs2_name, ext, strlen(ext) + 1);
	}
	retstr = unmangle(ucs2_name);
	if(retstr) pull_ucs2(NULL, unix_name, retstr, sizeof(unix_name), 0, STR_TERMINATE);
	else unix_name[0] = 0;
	if (ext) printf ("[%s.%s] ---> [%s]\n", name, ext, unix_name);
	else printf ("[%s] ---> [%s]\n", name, unix_name);
	SAFE_FREE(retstr);
}

static void mangle_test (char *name, char *ext)
{
	smb_ucs2_t ucs2_name[2048];
	smb_ucs2_t *retstr;
	pstring unix_name;	

	push_ucs2(NULL, ucs2_name, name, sizeof(ucs2_name), STR_TERMINATE);
	if (ext)
	{
		strncat_wa(ucs2_name, ".", 1);
		strncat_wa(ucs2_name, ext, strlen(ext) + 1);
	}
	retstr = mangle(ucs2_name);
	if(retstr) pull_ucs2(NULL, unix_name, retstr, sizeof(unix_name), 0, STR_TERMINATE);
	else unix_name[0] = 0;
	if (ext) printf ("[%s.%s] ---> [%s]\n", name, ext, unix_name);
	else printf ("[%s] ---> [%s]\n", name, unix_name);
	SAFE_FREE(retstr);
}

void mangle_test_code(void)
{
	init_mangle_tdb();

	/* unmangle every */
	printf("Unmangle test 1:\n");

	unmangle_test (LONG, NULL);
	unmangle_test (LONG, EXT1);
	unmangle_test (LONG, EXT2);
	unmangle_test (LONG, EXT3);
	unmangle_test (LONG, EXTFAIL);
	unmangle_test (LONG, EXTNULL);

	unmangle_test (LONGM, NULL);
	unmangle_test (LONGM, EXT1);
	unmangle_test (LONGM, EXT2);
	unmangle_test (LONGM, EXT3);
	unmangle_test (LONGM, EXTFAIL);
	unmangle_test (LONGM, EXTNULL);

	unmangle_test (SHORT, NULL);
	unmangle_test (SHORT, EXT1);
	unmangle_test (SHORT, EXT2);
	unmangle_test (SHORT, EXT3);
	unmangle_test (SHORT, EXTFAIL);
	unmangle_test (SHORT, EXTNULL);

	unmangle_test (SHORTM, NULL);
	unmangle_test (SHORTM, EXT1);
	unmangle_test (SHORTM, EXT2);
	unmangle_test (SHORTM, EXT3);
	unmangle_test (SHORTM, EXTFAIL);
	unmangle_test (SHORTM, EXTNULL);

	/* mangle every */
	printf("Mangle test\n");

	mangle_test (LONG, NULL);
	mangle_test (LONG, EXT1);
	mangle_test (LONG, EXT2);
	mangle_test (LONG, EXT3);
	mangle_test (LONG, EXTFAIL);
	mangle_test (LONG, EXTNULL);

	mangle_test (LONGM, NULL);
	mangle_test (LONGM, EXT1);
	mangle_test (LONGM, EXT2);
	mangle_test (LONGM, EXT3);
	mangle_test (LONGM, EXTFAIL);
	mangle_test (LONGM, EXTNULL);

	mangle_test (SHORT, NULL);
	mangle_test (SHORT, EXT1);
	mangle_test (SHORT, EXT2);
	mangle_test (SHORT, EXT3);
	mangle_test (SHORT, EXTFAIL);
	mangle_test (SHORT, EXTNULL);

	mangle_test (SHORTM, NULL);
	mangle_test (SHORTM, EXT1);
	mangle_test (SHORTM, EXT2);
	mangle_test (SHORTM, EXT3);
	mangle_test (SHORTM, EXTFAIL);
	mangle_test (SHORTM, EXTNULL);

	/* unmangle again every */
	printf("Unmangle test 2:\n");

	unmangle_test (LONG, NULL);
	unmangle_test (LONG, EXT1);
	unmangle_test (LONG, EXT2);
	unmangle_test (LONG, EXT3);
	unmangle_test (LONG, EXTFAIL);
	unmangle_test (LONG, EXTNULL);

	unmangle_test (LONGM, NULL);
	unmangle_test (LONGM, EXT1);
	unmangle_test (LONGM, EXT2);
	unmangle_test (LONGM, EXT3);
	unmangle_test (LONGM, EXTFAIL);
	unmangle_test (LONGM, EXTNULL);

	unmangle_test (SHORT, NULL);
	unmangle_test (SHORT, EXT1);
	unmangle_test (SHORT, EXT2);
	unmangle_test (SHORT, EXT3);
	unmangle_test (SHORT, EXTFAIL);
	unmangle_test (SHORT, EXTNULL);

	unmangle_test (SHORTM, NULL);
	unmangle_test (SHORTM, EXT1);
	unmangle_test (SHORTM, EXT2);
	unmangle_test (SHORTM, EXT3);
	unmangle_test (SHORTM, EXTFAIL);
	unmangle_test (SHORTM, EXTNULL);
}

#endif /* TEST_MANGLE_CODE */
