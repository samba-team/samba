/*
   Unix SMB/CIFS implementation.
   Security Descriptor (SD) helper functions

   Copyright (C) Andrew Tridgell 2000
   Copyright (C) Tim Potter      2000
   Copyright (C) Jeremy Allison  2000
   Copyright (C) Jelmer Vernooij 2003

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

#ifndef __UTIL_SD_H__
#define __UTIL_SD_H__

void SidToString(struct cli_state *cli, fstring str, const struct dom_sid *sid,
		 bool numeric);
bool StringToSid(struct cli_state *cli, struct dom_sid *sid, const char *str);
void print_ace(struct cli_state *cli, FILE *f, struct security_ace *ace,
	       bool numeric);
bool parse_ace(struct cli_state *cli, struct security_ace *ace,
	       const char *orig_str);
void sec_desc_print(struct cli_state *cli, FILE *f,
		    struct security_descriptor *sd, bool numeric);

#endif
