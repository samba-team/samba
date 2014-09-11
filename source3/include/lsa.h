/*
 * Helper functions related to the LSA server
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
#ifndef LSA_H
#define LSA_H

int init_lsa_ref_domain_list(TALLOC_CTX *mem_ctx,
			     struct lsa_RefDomainList *ref,
			     const char *dom_name,
			     struct dom_sid *dom_sid);

#endif
