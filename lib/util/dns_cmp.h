/*
   Unix SMB/CIFS implementation.

   Copyright (C) Stefan Metzmacher 2015

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

#ifndef _LIB_UTIL_DNS_CMP_H_
#define _LIB_UTIL_DNS_CMP_H_ 1

#define DNS_CMP_FIRST_IS_CHILD -2
#define DNS_CMP_FIRST_IS_LESS -1
#define DNS_CMP_MATCH 0
#define DNS_CMP_SECOND_IS_LESS 1
#define DNS_CMP_SECOND_IS_CHILD 2

#define DNS_CMP_IS_NO_MATCH(__cmp) \
	((__cmp == DNS_CMP_FIRST_IS_LESS) || (__cmp == DNS_CMP_SECOND_IS_LESS))

/*
 * this function assumes names are well formed DNS names.
 * it doesn't validate them
 *
 * It allows strings up to a length of UINT16_MAX - 1
 * with up to UINT8_MAX components. On overflow this
 * just returns the result of strcasecmp_m().
 *
 * Trailing dots (only one) are ignored.
 *
 * The DNS names are compared per component, starting from
 * the last one.
 *
 * The function is usable in a sort, but the return value contains more
 * information than a simple comparison. There are 5 return values, defined
 * above.
 *
 * DNS_CMP_FIRST_IS_CHILD (-2) means the first argument is a sub-domain of the
 * second. e.g. dns_cmp("foo.example.org", "example.org")
 *
 * DNS_CMP_FIRST_IS_LESS (-1) means the first argument sorts before the
 * second, but is not a sub-domain. e.g. dns_cmp("eggsample.org", "example.org").
 *
 * DNS_CMP_SECOND_IS_CHILD (+2) and DNS_CMP_SECOND_IS_LESS (+1) have the
 * similar expected meanings. DNS_CMP_MATCH (0) means equality.
 *
 * NULL values are the parent of all addresses, which means comparisons
 * between a string and NULL will return +2 or -2.
 */
int dns_cmp(const char *s1, const char *s2);

#endif /* _LIB_UTIL_DNS_CMP_H_ */
