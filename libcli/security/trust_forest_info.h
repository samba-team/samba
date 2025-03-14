/*
   Unix SMB/CIFS implementation.
   Authentication utility functions
   Copyright (C) Stefan Metzmacher 2018,2025

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

#ifndef _LIBCLI_SECURITY_TRUST_FOREST_INFO_H_
#define _LIBCLI_SECURITY_TRUST_FOREST_INFO_H_

struct ForestTrustInfo;
struct lsa_ForestTrustInformation;
struct lsa_ForestTrustInformation2;

NTSTATUS trust_forest_info_from_lsa(TALLOC_CTX *mem_ctx,
				const struct lsa_ForestTrustInformation *lfti,
				struct ForestTrustInfo **_fti);
NTSTATUS trust_forest_info_to_lsa(TALLOC_CTX *mem_ctx,
				  const struct ForestTrustInfo *fti,
				  struct lsa_ForestTrustInformation **_lfti);
NTSTATUS trust_forest_info_from_lsa2(TALLOC_CTX *mem_ctx,
				const struct lsa_ForestTrustInformation2 *lfti,
				struct ForestTrustInfo **_fti);
NTSTATUS trust_forest_info_to_lsa2(TALLOC_CTX *mem_ctx,
				   const struct ForestTrustInfo *fti,
				   struct lsa_ForestTrustInformation2 **_lfti);
NTSTATUS trust_forest_info_lsa_1to2(TALLOC_CTX *mem_ctx,
				const struct lsa_ForestTrustInformation *lfti,
				struct lsa_ForestTrustInformation2 **_lfti2);
NTSTATUS trust_forest_info_lsa_2to1(TALLOC_CTX *mem_ctx,
				const struct lsa_ForestTrustInformation2 *lfti2,
				struct lsa_ForestTrustInformation **_lfti);
NTSTATUS trust_forest_info_lsa_2to2(TALLOC_CTX *mem_ctx,
				const struct lsa_ForestTrustInformation2 *in,
				struct lsa_ForestTrustInformation2 **_out);

bool trust_forest_info_tln_match(
		const struct lsa_ForestTrustInformation2 *info,
		const char *tln);
bool trust_forest_info_tln_ex_match(
		const struct lsa_ForestTrustInformation2 *info,
		const char *tln);
bool trust_forest_info_match_tln_namespace(
		const struct lsa_ForestTrustInformation2 *info,
		const char *tln);

#endif /* _LIBCLI_SECURITY_TRUST_FOREST_INFO_H_ */
