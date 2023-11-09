/*
 *  Unix SMB/CIFS implementation.
 *
 *  Window Search Service
 *
 *  Copyright (c) Noel Power
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
#ifndef __LIBRPC_WSP_UTIL_H__
#define __LIBRPC_WSP_UTIL_H__

#include "librpc/gen_ndr/misc.h"

struct safearraybound;
struct wsp_cfullpropspec;
struct wsp_cbasestoragevariant;
struct wsp_crestriction;

struct full_propset_info {
	uint32_t id;
	const char *name;
	uint16_t vtype;
	bool extra_info;
	bool in_inverted_index;
	bool is_column;
	bool can_col_be_indexed;
	uint16_t max_size;
};

struct full_guid_propset {
	struct GUID guid;
	const struct full_propset_info *prop_info;
};

extern const struct full_guid_propset full_propertyset[];

char *prop_from_fullprop(TALLOC_CTX *ctx, struct wsp_cfullpropspec *fullprop);
const struct full_propset_info *get_prop_info(const char *prop_name);
const struct full_propset_info *get_propset_info_with_guid(
						const char *prop_name,
						struct GUID *guid);
const char * get_vtype_name(uint32_t type);
bool is_variable_size(uint16_t vtype);
const char *get_store_status(uint8_t status_byte);

bool is_operator(struct wsp_crestriction *restriction);
const char *op_as_string(struct wsp_crestriction *restriction);
const char *genmeth_to_string(uint32_t genmethod);
const char *variant_as_string(TALLOC_CTX *ctx,
                        struct wsp_cbasestoragevariant *value,
                        bool quote);
void set_variant_lpwstr(TALLOC_CTX *ctx,
			struct wsp_cbasestoragevariant *vvalue,
			const char *string_val);
void set_variant_i4(TALLOC_CTX *ctx,
		    struct wsp_cbasestoragevariant *vvalue,
		    uint32_t val);
void set_variant_vt_bool(TALLOC_CTX *ctx,
			struct wsp_cbasestoragevariant *variant,
			bool bval);
void set_variant_bstr(TALLOC_CTX *ctx, struct wsp_cbasestoragevariant *variant,
		      const char *string_val);
void set_variant_lpwstr_vector(TALLOC_CTX *ctx,
			      struct wsp_cbasestoragevariant *variant,
			      const char **string_vals, uint32_t elems);
void set_variant_array_bstr(TALLOC_CTX *ctx,
			   struct wsp_cbasestoragevariant *variant,
			   const char **string_vals, uint16_t elems);
void set_variant_i4_vector(TALLOC_CTX *ctx,
			   struct wsp_cbasestoragevariant *variant,
			   int32_t* ivector, uint32_t elems);
void set_variant_array_i4(TALLOC_CTX *ctx,
			 struct wsp_cbasestoragevariant *variant,
			 int32_t *vals, uint16_t elems);

struct wsp_cfullpropspec *get_full_prop(struct wsp_crestriction *restriction);
#endif /* __LIBRPC_WSP_UTIL_H__ */
