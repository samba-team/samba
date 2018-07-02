/*
   Unix SMB/CIFS implementation.

   ldb database library - Extended match rules

   Copyright (C) 2014 Samuel Cabrero <samuelcabrero@kernevil.me>

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

#ifndef _LDB_MATCHING_RULES_H_
#define _LDB_MATCHING_RULES_H_

/* This rule provides recursive search of a link attribute */
#define SAMBA_LDAP_MATCH_RULE_TRANSITIVE_EVAL	"1.2.840.113556.1.4.1941"
#define DSDB_MATCH_FOR_EXPUNGE	"1.3.6.1.4.1.7165.4.5.2"
#define DSDB_MATCH_FOR_DNS_TO_TOMBSTONE_TIME "1.3.6.1.4.1.7165.4.5.3"

#endif /* _LDB_MATCHING_RULES_H_ */
