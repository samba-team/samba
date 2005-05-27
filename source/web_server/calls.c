/* 
   Unix SMB/CIFS implementation.

   provide hooks into C calls from esp scripts

   Copyright (C) Andrew Tridgell 2005
   
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

#include "includes.h"
#include "web_server/esp/esp.h"


/*
  return the type of a variable
*/
static int esp_typeof(struct EspRequest *ep, int argc, struct MprVar **argv)
{
	const struct {
		MprType type;
		const char *name;
	} types[] = {
		{ MPR_TYPE_UNDEFINED, "undefined" },
		{ MPR_TYPE_NULL, "null" },
		{ MPR_TYPE_BOOL, "boolean" },
		{ MPR_TYPE_CFUNCTION, "function" },
		{ MPR_TYPE_FLOAT, "float" },
		{ MPR_TYPE_INT, "int" },
		{ MPR_TYPE_INT64, "int64" },
		{ MPR_TYPE_OBJECT, "object" },
		{ MPR_TYPE_FUNCTION, "function" },
		{ MPR_TYPE_STRING, "string" },
		{ MPR_TYPE_STRING_CFUNCTION, "function" }
	};
	int i;
	const char *type = "unknown";

	if (argc != 1) return -1;
	
	for (i=0;i<ARRAY_SIZE(types);i++) {
		if (argv[0]->type == types[i].type) {
			type = types[i].name;
			break;
		}
	}

	espSetReturnString(ep, type);
	return 0;
}


/*
  setup the C functions that be called from ejs
*/
void http_setup_ejs_functions(void)
{
	espDefineStringCFunction(NULL, "lpGet", esp_lpGet, NULL);
	espDefineCFunction(NULL, "typeof", esp_typeof, NULL);
}
