/* 
   Unix SMB/CIFS implementation.

   provide access to data blobs

   Copyright (C) Andrew Tridgell 2005
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "scripting/ejs/smbcalls.h"
#include "lib/appweb/ejs/ejs.h"
#include "librpc/gen_ndr/winreg.h"

/*
  create a data blob object from a ejs array of integers
*/
static int ejs_blobFromArray(MprVarHandle eid, int argc, struct MprVar **argv)
{
	struct MprVar *array, *v;
	unsigned length, i;
	DATA_BLOB blob;

	if (argc != 1) {
		ejsSetErrorMsg(eid, "blobFromArray invalid arguments");
		return -1;		
	}
	array = argv[0];

	v = mprGetProperty(array, "length", NULL);
	if (v == NULL) {
		goto failed;
	}
	length = mprToInt(v);

	blob = data_blob_talloc(mprMemCtx(), NULL, length);
	if (length != 0 && blob.data == NULL) {
		goto failed;
	}

	for (i=0;i<length;i++) {
		struct MprVar *vs;
		char idx[16];
		mprItoa(i, idx, sizeof(idx));		
		vs = mprGetProperty(array, idx, NULL);
		if (vs == NULL) {
			goto failed;
		}
		blob.data[i] = mprVarToNumber(vs);
	}

	mpr_Return(eid, mprDataBlob(blob));
	return 0;

failed:
	mpr_Return(eid, mprCreateUndefinedVar());
	return 0;
}

/*
  create a ejs array of integers from a data blob
*/
static int ejs_blobToArray(MprVarHandle eid, int argc, struct MprVar **argv)
{
	DATA_BLOB *blob;
	struct MprVar array;
	int i;

	if (argc != 1) {
		ejsSetErrorMsg(eid, "blobToArray invalid arguments");
		return -1;		
	}
	blob = mprToDataBlob(argv[0]);
	if (blob == NULL) {
		goto failed;
	}

	array = mprArray("array");
	
	for (i=0;i<blob->length;i++) {
		mprAddArray(&array, i, mprCreateNumberVar(blob->data[i]));
	}
	mpr_Return(eid, array);
	return 0;

failed:
	mpr_Return(eid, mprCreateUndefinedVar());
	return 0;
}


/*
  compare two data blobs
*/
static int ejs_blobCompare(MprVarHandle eid, int argc, struct MprVar **argv)
{
	DATA_BLOB *blob1, *blob2;
	BOOL ret = False;

	if (argc != 2) {
		ejsSetErrorMsg(eid, "blobCompare invalid arguments");
		return -1;		
	}
	
	blob1 = mprToDataBlob(argv[0]);
	blob2 = mprToDataBlob(argv[1]);

	if (blob1 == blob2) {
		ret = True;
		goto done;
	}
	if (blob1 == NULL || blob2 == NULL) {
		ret = False;
		goto done;
	}

	if (blob1->length != blob2->length) {
		ret = False;
		goto done;
	}

	if (memcmp(blob1->data, blob2->data, blob1->length) != 0) {
		ret = False;
		goto done;
	}
	ret = True;

done:
	mpr_Return(eid, mprCreateBoolVar(ret));
	return 0;
}


/*
  convert a blob in winreg format to a mpr variable
  
  usage:
     v = data.regToVar(blob, type);
*/
static int ejs_regToVar(MprVarHandle eid, int argc, struct MprVar **argv)
{
	DATA_BLOB *blob;
	enum winreg_Type type;
	struct MprVar v;

	if (argc != 2) {
		ejsSetErrorMsg(eid, "regToVar invalid arguments");
		return -1;		
	}
	
	blob = mprToDataBlob(argv[0]);
	type = mprToInt(argv[1]);

	if (blob == NULL) {
		ejsSetErrorMsg(eid, "regToVar null data");
		return -1;
	}

	switch (type) {
	case REG_NONE:
		v = mprCreateUndefinedVar();
		break;

	case REG_SZ:
	case REG_EXPAND_SZ: {
		char *s;
		ssize_t len;
		len = convert_string_talloc(mprMemCtx(), CH_UTF16, CH_UNIX, 
					    blob->data, blob->length, (void **)&s);
		if (len == -1) {
			ejsSetErrorMsg(eid, "regToVar invalid REG_SZ string");
			return -1;
		}
		v = mprString(s);
		talloc_free(s);
		break;
	}

	case REG_DWORD: {
		if (blob->length != 4) {
			ejsSetErrorMsg(eid, "regToVar invalid REG_DWORD length %ld", (long)blob->length);
			return -1;
		}
		v = mprCreateNumberVar(IVAL(blob->data, 0));
		break;
	}

	case REG_DWORD_BIG_ENDIAN: {
		if (blob->length != 4) {
			ejsSetErrorMsg(eid, "regToVar invalid REG_DWORD_BIG_ENDIAN length %ld", (long)blob->length);
			return -1;
		}
		v = mprCreateNumberVar(RIVAL(blob->data, 0));
		break;
	}

	case REG_QWORD: {
		if (blob->length != 8) {
			ejsSetErrorMsg(eid, "regToVar invalid REG_QWORD length %ld", (long)blob->length);
			return -1;
		}
		v = mprCreateNumberVar(BVAL(blob->data, 0));
		break;
	}

	case REG_MULTI_SZ: {
		DATA_BLOB b = *blob;
		const char **list = NULL;
		while (b.length > 0) {
			char *s;
			ssize_t len;
			size_t slen = utf16_len_n(b.data, b.length);
			if (slen == 2 && b.length == 2 && SVAL(b.data, 0) == 0) {
				break;
			}
			len = convert_string_talloc(mprMemCtx(), CH_UTF16, CH_UNIX, 
						    b.data, slen, (void **)&s);
			if (len == -1) {
				ejsSetErrorMsg(eid, "regToVar invalid REG_MULTI_SZ string");
				return -1;
			}
			list = str_list_add(list, s);
			talloc_free(s);
			talloc_steal(mprMemCtx(), list);
			b.data += slen;
			b.length -= slen;
		}
		v = mprList("REG_MULTI_SZ", list);
		talloc_free(list);
		break;
	}
		

	case REG_FULL_RESOURCE_DESCRIPTOR:
	case REG_RESOURCE_LIST:
	case REG_BINARY:
	case REG_RESOURCE_REQUIREMENTS_LIST:
	case REG_LINK:
		return ejs_blobToArray(eid, 1, argv);

	default:
		ejsSetErrorMsg(eid, "regToVar invalid type %d", type);
		return -1;		
	}
	
	mpr_Return(eid, v);
	return 0;
}

/*
  initialise datablob ejs subsystem
*/
static int ejs_datablob_init(MprVarHandle eid, int argc, struct MprVar **argv)
{
	struct MprVar *obj = mprInitObject(eid, "datablob", argc, argv);

	mprSetCFunction(obj, "blobFromArray", ejs_blobFromArray);
	mprSetCFunction(obj, "blobToArray", ejs_blobToArray);
	mprSetCFunction(obj, "blobCompare", ejs_blobCompare);
	mprSetCFunction(obj, "regToVar", ejs_regToVar);

	return 0;
}

/*
  setup C functions that be called from ejs
*/
NTSTATUS smb_setup_ejs_datablob(void)
{
	ejsDefineCFunction(-1, "datablob_init", ejs_datablob_init, NULL, MPR_VAR_SCRIPT_HANDLE);
	return NT_STATUS_OK;
}
