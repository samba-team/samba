/* 
 *  Unix SMB/CIFS implementation.
 *  Group Policy Object Support
 *  Copyright (C) Guenther Deschner 2005-2006
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "iniparser/src/iniparser.h"

/****************************************************************
 parse the local gpt.ini file
****************************************************************/

#define GPT_INI_SECTION_GENERAL "General"
#define GPT_INI_PARAMETER_VERSION "Version"
#define GPT_INI_PARAMETER_DISPLAYNAME "displayName"

NTSTATUS parse_gpt_ini(TALLOC_CTX *mem_ctx, const char *filename, uint32 *version, char **display_name)
{
	NTSTATUS result;
	uint32 v;
	char *name = NULL;
	dictionary *d;

	d = iniparser_load(filename);
	if (d == NULL) {
		return NT_STATUS_NO_SUCH_FILE;
	}

	if ((name = iniparser_getstring(d, GPT_INI_SECTION_GENERAL
			":"GPT_INI_PARAMETER_DISPLAYNAME, NULL)) == NULL) {
		/* the default domain policy and the default domain controller
		 * policy never have a displayname in their gpt.ini file */
		DEBUG(10,("parse_gpt_ini: no name in %s\n", filename));
	}

	if (name && display_name) {
		*display_name = talloc_strdup(mem_ctx, name);
		if (*display_name == NULL) {
			result = NT_STATUS_NO_MEMORY;
			goto out;
		}
	}

	if ((v = iniparser_getint(d, GPT_INI_SECTION_GENERAL
			":"GPT_INI_PARAMETER_VERSION, Undefined)) == Undefined) {
		DEBUG(10,("parse_gpt_ini: no version\n"));
		result = NT_STATUS_INTERNAL_DB_CORRUPTION;
		goto out;
	}

	if (version) {
		*version = v;
	}

	result = NT_STATUS_OK;
 out:
 	if (d) {
		iniparser_freedict(d);
	}

	return result;
}
