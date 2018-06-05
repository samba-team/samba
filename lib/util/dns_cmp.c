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

#include "replace.h"
#include "lib/util/charset/charset.h"
#include "lib/util/fault.h"
#include "lib/util/dns_cmp.h"

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
int dns_cmp(const char *s1, const char *s2)
{
	size_t l1 = 0;
	const char *p1 = NULL;
	size_t num_comp1 = 0;
	uint16_t comp1[UINT8_MAX] = {0};
	size_t l2 = 0;
	const char *p2 = NULL;
	size_t num_comp2 = 0;
	uint16_t comp2[UINT8_MAX] = {0};
	size_t i;

	if (s1 == s2) {
		/* this includes the both NULL case */
		return DNS_CMP_MATCH;
	}
	if (s1 == NULL) {
		return DNS_CMP_SECOND_IS_CHILD;
	}
	if (s2 == NULL) {
		return DNS_CMP_FIRST_IS_CHILD;
	}

	l1 = strlen(s1);
	l2 = strlen(s2);

	/*
	 * trailing '.' are ignored.
	 */
	if (l1 > 1 && s1[l1 - 1] == '.') {
		l1--;
	}
	if (l2 > 1 && s2[l2 - 1] == '.') {
		l2--;
	}

	for (i = 0; i < ARRAY_SIZE(comp1); i++) {
		char *p;

		if (i == 0) {
			p1 = s1;

			if (l1 == 0 || l1 >= UINT16_MAX) {
				/* just use one single component on overflow */
				break;
			}
		}

		comp1[num_comp1++] = PTR_DIFF(p1, s1);

		p = strchr_m(p1, '.');
		if (p == NULL) {
			p1 = NULL;
			break;
		}

		p1 = p + 1;
	}

	if (p1 != NULL) {
		/* just use one single component on overflow */
		num_comp1 = 0;
		comp1[num_comp1++] = 0;
		p1 = NULL;
	}

	for (i = 0; i < ARRAY_SIZE(comp2); i++) {
		char *p;

		if (i == 0) {
			p2 = s2;

			if (l2 == 0 || l2 >= UINT16_MAX) {
				/* just use one single component on overflow */
				break;
			}
		}

		comp2[num_comp2++] = PTR_DIFF(p2, s2);

		p = strchr_m(p2, '.');
		if (p == NULL) {
			p2 = NULL;
			break;
		}

		p2 = p + 1;
	}

	if (p2 != NULL) {
		/* just use one single component on overflow */
		num_comp2 = 0;
		comp2[num_comp2++] = 0;
		p2 = NULL;
	}

	for (i = 0; i < UINT8_MAX; i++) {
		int cmp;

		if (i < num_comp1) {
			size_t idx = num_comp1 - (i + 1);
			p1 = s1 + comp1[idx];
		} else {
			p1 = NULL;
		}

		if (i < num_comp2) {
			size_t idx = num_comp2 - (i + 1);
			p2 = s2 + comp2[idx];
		} else {
			p2 = NULL;
		}

		if (p1 == NULL && p2 == NULL) {
			return DNS_CMP_MATCH;
		}
		if (p1 != NULL && p2 == NULL) {
			return DNS_CMP_FIRST_IS_CHILD;
		}
		if (p1 == NULL && p2 != NULL) {
			return DNS_CMP_SECOND_IS_CHILD;
		}

		cmp = strcasecmp_m(p1, p2);
		if (cmp < 0) {
			return DNS_CMP_FIRST_IS_LESS;
		}
		if (cmp > 0) {
			return DNS_CMP_SECOND_IS_LESS;
		}
	}

	smb_panic(__location__);
	return -1;
}
