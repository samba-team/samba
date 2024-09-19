/*
 *  Unix SMB/CIFS implementation.
 *
 *  Window Search Service
 *
 *  Copyright (c)  Noel Power
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
#include "client.h"
#include "rpc_client/wsp_cli.h"
#include "rpc_client/rpc_client.h"
#include "param/param.h"
#include "auth/credentials/credentials.h"
#include <tevent.h>
#include <util/tevent_ntstatus.h>
#include "libcli/tstream_binding_handle/tstream_binding_handle.h"
#include "lib/tsocket/tsocket.h"
#include "librpc/wsp/wsp_util.h"
#include "librpc/gen_ndr/ndr_wsp.h"
#include "rpc_client/cli_pipe.h"
#include "libcli/smb/smbXcli_base.h"

#define MSG_HDR_SIZE 16
#define USED 1
/*
 * 32-bit Windows XP operating system, 32-bit Windows Server 2003 operating
 * system, 32-bit Windows Home Server server software, 32-bit Windows Vista
 * with Windows Search 4.0, 32-bit Windows Server 2003 with Windows
 * Search 4.0. All of these versions of Windows are running
 * Windows Search 4.0.
*/

static const uint32_t CLIENTVERSION = 0x00010700;

/*
 * DBPROP_CI_SCOPE_FLAGS
 * containing QUERY_DEEP
 *    QUERY_DEEP (0x1) indicates that files in the scope directory and all
 *    subdirectories are included in the results. If clear, only files in
 *    the scope directory are included in the results.
 */
static int32_t scope_flags_vector[] = {0x00000001};
/*
 * Search everywhere "\\" is the root scope
 */
static const char * root_scope_string_vector[] = {"\\"};

/* sets sensible defaults */
static void init_wsp_prop(struct wsp_cdbprop *prop)
{
	*prop = (struct wsp_cdbprop){0};
	prop->colid.ekind = DBKIND_GUID_PROPID;
}


static bool create_restriction_array(TALLOC_CTX *ctx,
			       struct wsp_crestriction **pelements,
			       uint32_t nnodes)
{
	struct wsp_crestriction *elements = talloc_zero_array(ctx,
						       struct wsp_crestriction,
						       nnodes);
	if (elements == NULL) {
		return false;
	}
	*pelements = elements;
	return true;
}


static bool create_noderestriction(TALLOC_CTX *ctx,
			       struct wsp_cnoderestriction *pnode,
			       uint32_t nnodes)
{
	bool ok;
	pnode->cnode = nnodes;
	ok = create_restriction_array(ctx, &pnode->panode, nnodes);
	return ok;
}

static bool fill_sortarray(TALLOC_CTX *ctx, struct wsp_csort **dest,
			   struct wsp_csort *src, uint32_t num)
{
	uint32_t i;
	struct wsp_csort *psort = talloc_zero_array(ctx, struct wsp_csort,
						    num);
	if (psort == NULL) {
		return false;
	}
	for (i = 0; i < num; i++) {
		psort[i] = src[i];
	}
	*dest = psort;
	return true;
}



static bool set_fullpropspec(TALLOC_CTX *ctx, struct wsp_cfullpropspec *prop,
			     const char* propname, uint32_t kind)
{
	struct GUID guid = {0};
	const struct full_propset_info *prop_info = NULL;

	prop_info = get_propset_info_with_guid(propname, &guid);
	if (!prop_info) {
		DBG_ERR("Failed to handle property named %s\n",
			propname);
		return false;
	}
	prop->guidpropset = guid;
	prop->ulkind = kind;
	if (kind == PRSPEC_LPWSTR) {
		prop->name_or_id.propname.vstring = talloc_strdup(ctx,
								   propname);
		if (prop->name_or_id.propname.vstring == NULL) {
			DBG_ERR("out of memory");
			return false;
		}
		prop->name_or_id.propname.len = strlen(propname);
	} else {
		prop->name_or_id.prspec = prop_info->id;
	}
	return true;
}

struct binding
{
	uint32_t status_off;
	uint32_t value_off;
	uint32_t len_off;
};

static bool set_ctablecolumn(TALLOC_CTX *ctx, struct wsp_ctablecolumn *tablecol,
		const char* propname, struct binding *offsets,
		uint32_t value_size)
{
	struct wsp_cfullpropspec *prop = &tablecol->propspec;

	if (!set_fullpropspec(ctx, prop, propname, PRSPEC_PROPID)) {
		return false;
	}
	tablecol->vtype =VT_VARIANT ;
	tablecol->aggregateused = USED;
	tablecol->valueused = USED;
	tablecol->valueoffset.value = offsets->value_off;
	tablecol->valuesize.value = value_size;
	tablecol->statusused = USED;
	tablecol->statusoffset.value = offsets->status_off;
	tablecol->lengthused = USED;
	tablecol->lengthoffset.value = offsets->len_off;
	return true;
}


static bool fill_uint32_vec(TALLOC_CTX* ctx,
			    uint32_t **pdest,
			    uint32_t* ivector, uint32_t elems)
{
	uint32_t i;
	uint32_t *dest = talloc_zero_array(ctx, uint32_t, elems);
	if (dest == NULL) {
		return false;
	}

	for ( i = 0; i < elems; i++ ) {
		dest[ i ] = ivector[ i ];
	}
	*pdest = dest;
	return true;
}

static bool init_propset1(TALLOC_CTX* tmp_ctx,
					struct wsp_cdbpropset *propertyset)
{
	uint32_t i;
	GUID_from_string(DBPROPSET_FSCIFRMWRK_EXT,
			 &propertyset->guidpropertyset);

	propertyset->cproperties = 4;
	propertyset->aprops =
		talloc_zero_array(tmp_ctx, struct wsp_cdbprop,
			     propertyset->cproperties);
	if (propertyset->aprops == NULL) {
		return false;
	}

	/* initialise first 4 props */
	for( i = 0; i < propertyset->cproperties; i++) {
		init_wsp_prop(&propertyset->aprops[i]);
	}

	/*
	 * see MS-WSP 2.2.1.31.1 & 4.1 Protocol examples, Example 1
	 *   and also as seen in various windows network traces
	 * set value prop[0] - 'catalog to search'
	 */

	propertyset->aprops[0].dbpropid = DBPROP_CI_CATALOG_NAME;
	/* The name of the Catalog to Query */
	set_variant_lpwstr(tmp_ctx, &propertyset->aprops[0].vvalue,
			"Windows\\SystemIndex");
	/*
	 * set value prop[1] 'Regular Query'
	 */

	propertyset->aprops[1].dbpropid = DBPROP_CI_QUERY_TYPE;
	set_variant_i4(tmp_ctx, &propertyset->aprops[1].vvalue,
		       CINORMAL);

	/*
	 * set value prop[2] 'search subfolders'
	 */
	propertyset->aprops[2].dbpropid = DBPROP_CI_SCOPE_FLAGS;
	set_variant_i4_vector(tmp_ctx, &propertyset->aprops[2].vvalue,
		       scope_flags_vector, ARRAY_SIZE(scope_flags_vector));

	/*
	 * set value prop[3] 'root scope'
	 */
	propertyset->aprops[3].dbpropid = DBPROP_CI_INCLUDE_SCOPES;
	set_variant_lpwstr_vector(tmp_ctx,
				  &propertyset->aprops[3].vvalue,
				  root_scope_string_vector,
				  ARRAY_SIZE(root_scope_string_vector));
	return true;
}

static bool init_propset2(TALLOC_CTX* tmp_ctx,
			  struct wsp_cdbpropset *propertyset,
			  const char* server)
{
	uint32_t i;

	GUID_from_string(DBPROPSET_CIFRMWRKCORE_EXT,
			 &propertyset->guidpropertyset);

	propertyset->cproperties = 1;
	propertyset->aprops =
		talloc_zero_array(tmp_ctx, struct wsp_cdbprop,
			     propertyset->cproperties);
	if (propertyset->aprops == NULL) {
		return false;
	}

	/* initialise first 1 props */
	for( i = 0; i < propertyset->cproperties; i++) {
		init_wsp_prop(&propertyset->aprops[i]);
	}

	/*
	 * see MS-WSP 2.2.1.31.1 & 4.1 Protocol examples, Example 1
	 *   and also as seen in various windows network traces
	 * set value prop[0] - 'machines to search'
	 */
	propertyset->aprops[0].dbpropid = DBPROP_MACHINE;
	set_variant_bstr(tmp_ctx, &propertyset->aprops[0].vvalue,
			server);
	return true;
}

static bool init_apropset0(TALLOC_CTX* tmp_ctx,
			   struct wsp_cdbpropset *propertyset)
{
	uint32_t i;

	GUID_from_string(DBPROPSET_MSIDXS_ROWSETEXT,
			 &propertyset->guidpropertyset);

	propertyset->cproperties = 7;
	propertyset->aprops =
		talloc_zero_array(tmp_ctx, struct wsp_cdbprop,
			     propertyset->cproperties);
	if (propertyset->aprops == NULL) {
		return false;
	}

	/* initialise props */
	for( i = 0; i < propertyset->cproperties; i++) {
		init_wsp_prop(&propertyset->aprops[i]);
	}

	/*
	 * see MS-WSP 2.2.1.31.1 & 4.1 Protocol examples, Example 1
	 * set value prop[0]
	 * MSIDXSPROP_ROWSETQUERYSTATUS - 'ignored'
	 */
	propertyset->aprops[0].dbpropid = MSIDXSPROP_ROWSETQUERYSTATUS;
	set_variant_i4(tmp_ctx,  &propertyset->aprops[0].vvalue, 0x00000000);

	/*
	 * set value prop[1]
	 * MSIDXSPROP_COMMAND_LOCALE_STRING - 'EN'
	 */
	propertyset->aprops[1].dbpropid = MSIDXSPROP_COMMAND_LOCALE_STRING;
	set_variant_bstr(tmp_ctx, &propertyset->aprops[1].vvalue,
			"en-us");

	/*
	 * set value prop[2]
	 * MSIDXSPROP_QUERY_RESTRICTION - 'ignored'
	 */
	propertyset->aprops[2].dbpropid = MSIDXSPROP_QUERY_RESTRICTION;
	set_variant_bstr(tmp_ctx, &propertyset->aprops[2].vvalue,
			"");

	/*
	 * set value prop[3]
	 * MSIDXSPROP_PARSE_TREE - 'ignored'
	 */
	propertyset->aprops[3].dbpropid = MSIDXSPROP_PARSE_TREE;
	set_variant_bstr(tmp_ctx, &propertyset->aprops[3].vvalue,
			"");

	/*
	 * set value prop[4]
	 * MSIDXSPROP_MAX_RANK - 'ignored'
	 */
	propertyset->aprops[4].dbpropid = MSIDXSPROP_MAX_RANK;
	set_variant_i4(tmp_ctx,  &propertyset->aprops[4].vvalue, 0x00000000);

	/*
	 * set value prop[5]
	 * MSIDXSPROP_RESULTS_FOUND - 'ignored'
	 */
	propertyset->aprops[5].dbpropid = MSIDXSPROP_RESULTS_FOUND;
	set_variant_i4(tmp_ctx,  &propertyset->aprops[5].vvalue, 0x00000000);

	/*
	 * set value prop[6]
	 * ? - '' (unknown property id)
	 */
	propertyset->aprops[6].dbpropid = 0x00000008;
	set_variant_i4(tmp_ctx,  &propertyset->aprops[6].vvalue, 0x00000000);
	return true;
}

static bool init_apropset1(TALLOC_CTX* tmp_ctx,
			       struct wsp_cdbpropset *propertyset)
{
	uint32_t i;
	GUID_from_string(DBPROPSET_QUERYEXT,
			 &propertyset->guidpropertyset);

	propertyset->cproperties = 11;
	propertyset->aprops =
		talloc_zero_array(tmp_ctx, struct wsp_cdbprop,
			     propertyset->cproperties);
	if (propertyset->aprops == NULL) {
		return false;
	}

	/* init properties */
	for( i = 0; i < propertyset->cproperties; i++) {
		init_wsp_prop(&propertyset->aprops[i]);
	}

	/*
	 * see MS-WSP 2.2.1.31.1 & 4.1 Protocol examples, Example 1
	 * set value prop[0]
	 * DBPROP_USECONTENTINDEX - 'forced use of the full text index
	 *                           is false.'
	 */
	propertyset->aprops[0].dbpropid = DBPROP_USECONTENTINDEX;
	set_variant_vt_bool(tmp_ctx,  &propertyset->aprops[0].vvalue, false);

	/*
	 * set value prop[1]
	 * DBPROP_DEFERNONINDEXEDTRIMMING - 'trimming of security
	 *                                   results will not be deferred'
	 */
	propertyset->aprops[1].dbpropid = DBPROP_DEFERNONINDEXEDTRIMMING;
	set_variant_vt_bool(tmp_ctx,  &propertyset->aprops[1].vvalue, false);

	/*
	 * set value prop[2]
	 * DBPROP_USEEXTENDEDDBTYPES  - 'extended DB types are not used'
	 */
	propertyset->aprops[2].dbpropid = DBPROP_USEEXTENDEDDBTYPES;
	set_variant_vt_bool(tmp_ctx,  &propertyset->aprops[2].vvalue, false);

	/*
	 * set value prop[3]
	 * DBPROP_IGNORENOISEONLYCLAUSES = 'full text clauses consisting
	 *                                  entirely of noise words will
	 *                                  result in an error being returned'
	 */
	propertyset->aprops[3].dbpropid = DBPROP_IGNORENOISEONLYCLAUSES;
	set_variant_vt_bool(tmp_ctx,  &propertyset->aprops[3].vvalue, false);

	/*
	 * set value prop[4]
	 * DBPROP_GENERICOPTIONS_STRING - 'no generic options set'
	 */
	propertyset->aprops[4].dbpropid = DBPROP_GENERICOPTIONS_STRING;
	set_variant_bstr(tmp_ctx,  &propertyset->aprops[4].vvalue, "");

	/*
	 * set value prop[5]
	 * DBPROP_DEFERCATALOGVERIFICATION - 'catalog verification is not
	 *                                    deferred.'
	 */
	propertyset->aprops[5].dbpropid = DBPROP_DEFERCATALOGVERIFICATION;
	set_variant_vt_bool(tmp_ctx,  &propertyset->aprops[5].vvalue, false);

	/*
	 * set value prop[6]
	 * DBPROP_IGNORESBRI - 'query can use the sort-by-rank index
	 *                      optimization'
	 */
	propertyset->aprops[6].dbpropid = DBPROP_IGNORESBRI;
	set_variant_vt_bool(tmp_ctx,  &propertyset->aprops[6].vvalue, false);

	/*
	 * set value prop[7]
	 * DBPROP_GENERATEPARSETREE - 'a parse tree is not generated for
	 *                             debugging.'
	 */
	propertyset->aprops[7].dbpropid = DBPROP_GENERATEPARSETREE;
	set_variant_vt_bool(tmp_ctx,  &propertyset->aprops[7].vvalue, false);

	/*
	 * set value prop[8]
	 * DBPROP_FREETEXTANYTERM - 'all terms from a FREETEXT clause
	 *                           appear in every matching document'
	 */
	propertyset->aprops[8].dbpropid = DBPROP_FREETEXTANYTERM;
	set_variant_vt_bool(tmp_ctx,  &propertyset->aprops[8].vvalue, false);
	/*
	 * set value prop[9]
	 * DBPROP_FREETEXTUSESTEMMING - 'stemming is not used when interpreting
	 *                               a FREETEXT clause'
	 */
	propertyset->aprops[9].dbpropid = DBPROP_FREETEXTUSESTEMMING;
	set_variant_vt_bool(tmp_ctx,  &propertyset->aprops[9].vvalue, false);

	/*
	 * set value prop[10]
	 * ? - ''
	 */
	propertyset->aprops[10].dbpropid = 0x0000000f; /* ??? */
	set_variant_vt_bool(tmp_ctx,  &propertyset->aprops[10].vvalue, false);
	return true;
}

static bool init_apropset2(TALLOC_CTX* tmp_ctx,
			   struct wsp_cdbpropset *propertyset,
			   const char* server)
{
	uint32_t i;
	GUID_from_string(DBPROPSET_CIFRMWRKCORE_EXT,
			 &propertyset->guidpropertyset);

	propertyset->cproperties = 1;
	propertyset->aprops =
		talloc_zero_array(tmp_ctx, struct wsp_cdbprop,
			     propertyset->cproperties);
	if (propertyset->aprops == NULL) {
		return false;
	}

	/* init properties */
	for( i = 0; i < propertyset->cproperties; i++) {
		init_wsp_prop(&propertyset->aprops[i]);
	}

	/*
	 * see MS-WSP 2.2.1.31.1 & 4.1 Protocol examples, Example 1
	 *   and also as seen in various windows network traces
	 * set value prop[0]
	 * DBPROP_MACHINE - 'target server'
	 */
	propertyset->aprops[0].dbpropid = DBPROP_MACHINE;
	set_variant_bstr(tmp_ctx,  &propertyset->aprops[0].vvalue, server);
	return true;
}


static bool init_apropset3(TALLOC_CTX* tmp_ctx,
			   struct wsp_cdbpropset *propertyset)
{
	uint32_t i;

	GUID_from_string(DBPROPSET_FSCIFRMWRK_EXT,
			 &propertyset->guidpropertyset);

	propertyset->cproperties = 3;
	propertyset->aprops =
		talloc_zero_array(tmp_ctx, struct wsp_cdbprop,
			     propertyset->cproperties);
	if (propertyset->aprops == NULL) {
		return false;
	}

	/* init properties */
	for( i = 0; i < propertyset->cproperties; i++) {
		init_wsp_prop(&propertyset->aprops[i]);
	}

	/*
	 * see MS-WSP 2.2.1.31.1 & 4.1 Protocol examples, Example 1
	 *   and also as seen in various windows network traces
	 * set value prop[0]
	 * DBPROP_CI_INCLUDE_SCOPES - 'search everywhere'
	 */
	propertyset->aprops[0].dbpropid = DBPROP_CI_INCLUDE_SCOPES;
	set_variant_array_bstr(tmp_ctx, &propertyset->aprops[0].vvalue,
			       root_scope_string_vector,
			       ARRAY_SIZE(root_scope_string_vector));

	/*
	 * set value prop[1]
	 * DBPROP_CI_SCOPE_FLAGS - 'QUERY_DEEP'
	 */
	propertyset->aprops[1].dbpropid = DBPROP_CI_SCOPE_FLAGS;
	set_variant_array_i4(tmp_ctx, &propertyset->aprops[1].vvalue,
			     scope_flags_vector,
			     ARRAY_SIZE(scope_flags_vector));

	/*
	 * set value prop[2]
	 * DBPROP_CI_CATALOG_NAME - 'index to use' (always the same)
	 */
	propertyset->aprops[2].dbpropid = DBPROP_CI_CATALOG_NAME;
	set_variant_bstr(tmp_ctx, &propertyset->aprops[2].vvalue,
			 "Windows\\SystemIndex");
	return true;
}

bool init_connectin_request(TALLOC_CTX *ctx,
			    struct wsp_request* request,
			    const char* clientmachine,
			    const char* clientuser,
			    const char* server)
{
	enum ndr_err_code err;
	struct connectin_propsets *props = NULL;
	struct connectin_extpropsets *ext_props = NULL;
	DATA_BLOB props_blob = data_blob_null;
	struct ndr_push *ndr_props = NULL;
	ndr_flags_type ndr_flags = NDR_SCALARS | NDR_BUFFERS;
	bool result;
	struct wsp_cpmconnectin *connectin =
		&request->message.cpmconnect;

	props = talloc_zero(ctx, struct connectin_propsets);
	if (props == NULL) {
		result = false;
		DBG_ERR("out of memory\n");
		goto out;
	}

	ext_props = talloc_zero(ctx, struct connectin_extpropsets) ;
	if (ext_props == NULL) {
		result = false;
		DBG_ERR("out of memory\n");
		goto out;
	}

	request->header.msg = CPMCONNECT;
	connectin->iclientversion = CLIENTVERSION;
	/*
	 * hmm just say the client is remote, if we
	 * are talking to windows it is, if not does
	 * it really matter?
	 */
	connectin->fclientisremote = 0x00000001;
	connectin->machinename = clientmachine;
	connectin->username = clientuser;
	props->cpropsets = 2;

	/* =================== */
	/* set up PropertySet1 */
	/* =================== */
	if (!init_propset1(ctx, &props->propertyset1)) {
		result = false;
		DBG_ERR("initialising propset1 failed\n");
		goto out;
	}

	/* =================== */
	/* set up PropertySet2 */
	/* =================== */
	if (!init_propset2(ctx, &props->propertyset2, server)) {
		result = false;
		DBG_ERR("initialising propset2 failed\n");
		goto out;
	}

	/* 4 ExtPropSets */
	ext_props->cextpropset = 4;
	ext_props->apropertysets = talloc_zero_array(ctx, struct wsp_cdbpropset,
			     ext_props->cextpropset);

	if (ext_props->apropertysets == NULL) {
		result = false;
		DBG_ERR("out of memory\n");
		goto out;
	}

	/* ======================= */
	/* set up aPropertySets[0] */
	/* ======================= */
	if (!init_apropset0(ctx, &ext_props->apropertysets[0])) {
		result = false;
		DBG_ERR("initialisation of apropset0 failed\n");
		goto out;
	}

	/* ======================= */
	/* set up aPropertySets[1] */
	/* ======================= */
	if (!init_apropset1(ctx, &ext_props->apropertysets[1])) {
		result = false;
		DBG_ERR("initialisation of apropset1 failed\n");
		goto out;
	}

	/* ======================= */
	/* set up aPropertySets[2] */
	/* ======================= */
	if (!init_apropset2(ctx, &ext_props->apropertysets[2], server)) {
		result = false;
		DBG_ERR("initialisation of apropset2 failed\n");
		goto out;
	}

	/* ======================= */
	/* set up aPropertySets[3] */
	/* ======================= */
	if (!init_apropset3(ctx, &ext_props->apropertysets[3])) {
		result = false;
		DBG_ERR("initialisation of apropset3 failed\n");
		goto out;
	}

	/* we also have to fill the opaque blobs that contain the propsets */
	ndr_props = ndr_push_init_ctx(ctx);
	if (ndr_props == NULL) {
		result = false;
		DBG_ERR("out of memory\n");
		goto out;
	}

	/* first connectin_propsets */
	err = ndr_push_connectin_propsets(ndr_props, ndr_flags, props);
	if (err) {
		DBG_ERR("Failed to push propset, error %d\n", err);
		result = false;
		goto out;
	}
	props_blob = ndr_push_blob(ndr_props);
	connectin->cbblob1 = props_blob.length;
	connectin->propsets = talloc_zero_array(ctx, uint8_t,
				   connectin->cbblob1);
	if (connectin->propsets == NULL) {
		result = false;
		DBG_ERR("out of memory\n");
		goto out;
	}

	memcpy(connectin->propsets, props_blob.data, props_blob.length);

	/* then connectin_extpropsets */
	TALLOC_FREE(ndr_props);
	ndr_props = ndr_push_init_ctx(ctx);

	if (ndr_props == NULL) {
		result = false;
		DBG_ERR("out of memory\n");
		goto out;
	}

	err = ndr_push_connectin_extpropsets(ndr_props, ndr_flags, ext_props);

	if (err) {
		DBG_ERR("Failed to push extpropset, error %d\n", err);
		result = false;
		goto out;
	}

	props_blob = ndr_push_blob(ndr_props);
	connectin->cbblob2 = props_blob.length;
	connectin->extpropsets = talloc_zero_array(ctx, uint8_t,
						   connectin->cbblob2);

	if (connectin->extpropsets == NULL) {
		result = false;
		DBG_ERR("out of memory\n");
		goto out;
	}

	memcpy(connectin->extpropsets, props_blob.data, props_blob.length);
	TALLOC_FREE(ndr_props);
	result = true;
out:
	return result;
}

void create_seekat_getrows_request(TALLOC_CTX * ctx,
				   struct wsp_request* request,
				   uint32_t cursor,
				   uint32_t bookmark,
				   uint32_t skip,
				   uint32_t rows,
				   uint32_t cbreserved,
				   uint32_t ulclientbase,
				   uint32_t cbrowwidth,
				   uint32_t fbwdfetch)
{
	struct wsp_cpmgetrowsin *getrows =
		&request->message.cpmgetrows;
	/* msg type */
	request->header.msg = CPMGETROWS;
	/* position */
	getrows->hcursor = cursor;
	/* max no. rows to receive */
	getrows->crowstotransfer = rows;
	/*
	 * size (length) of row in bytes, determined from value set
	 * by CPMSetBindings message
	 */
	getrows->cbrowWidth = cbrowwidth;
	/*
	 * according to we should calculate this (see MS-WSP 3.2.4.2.4)
	 * but it seems window always sets this to the max 16KB limit
	 * (most likely when any row value is variable size e.g. like a
	 * string/path)
	 */
	getrows->cbreadbuffer = 0x00004000;
	/*
	 * base value of buffer pointer
	 */
	getrows->ulclientbase = ulclientbase;
	getrows->cbreserved = cbreserved;
	/* fetch rows in forward order */
	getrows->fbwdfetch = fbwdfetch;
	/* eRowSeekAt */
	getrows->etype = EROWSEEKAT;
	/* we don't handle chapters */
	getrows->chapt = 0;
	/* CRowsSeekAt (MS-WSP 2.2.1.37) */
	getrows->seekdescription.crowseekat.bmkoffset = bookmark;
	getrows->seekdescription.crowseekat.cskip = skip;
	getrows->seekdescription.crowseekat.hregion = 0;
}

static bool extract_rowbuf_variable_type(TALLOC_CTX *ctx,
		uint16_t type,
		uint64_t offset,
		DATA_BLOB *rows_buf, uint32_t len,
		struct wsp_cbasestoragevariant  *val)
{
	enum ndr_err_code err;
	struct ndr_pull *ndr_pull = NULL;
	ndr_flags_type ndr_flags = NDR_SCALARS | NDR_BUFFERS;
	DATA_BLOB variant_blob = data_blob_null;
	if (offset >= rows_buf->length) {
		DBG_ERR("offset %"PRIu64" outside buffer range (buf len - %zu)",
			offset,
			rows_buf->length);
		return false;
	}
	variant_blob.data = rows_buf->data + offset;
	variant_blob.length = len;
	ndr_pull = ndr_pull_init_blob(&variant_blob, ctx);

	if (ndr_pull == NULL) {
		DBG_ERR("out of memory\n");
		return false;
	}

	switch (type) {
		case VT_LPWSTR: {
			const char *string = NULL;
			ndr_set_flags(&ndr_pull->flags, LIBNDR_FLAG_STR_NULLTERM);
			err = ndr_pull_string(ndr_pull, ndr_flags, &string);
			if (err) {
				DBG_ERR("error unmarshalling string from %p\n", variant_blob.data );
			} else {
				DBG_INFO("\tstring val ->%s<-\n", string );
				val->vtype = type;
				val->vvalue.vt_lpwstr.value = string;
			}
			break;
		}
		default:
			DBG_ERR("#FIXME Unhandled variant type %s\n", get_vtype_name(type));
			break;
	}
	return true;
}

static bool convert_variant_array_to_vector(TALLOC_CTX *ctx,
		uint64_t count,
		struct wsp_cbasestoragevariant **variant_array,
		struct wsp_cbasestoragevariant *outval)
{
	uint64_t i;
	uint16_t vtype;
	union variant_types vvalue = {0};
	vtype = variant_array[0]->vtype;

	if (outval == NULL) {
		return false;
	}

	if (count) {
		switch (vtype) {
			case VT_BSTR:
				vvalue.vt_bstr_v.vvector_elements = count;
				vvalue.vt_bstr_v.vvector_data =
					talloc_zero_array(ctx,
						struct vt_bstr, count);
				if (vvalue.vt_bstr_v.vvector_data == NULL) {
					return false;
				}
				break;
			case VT_LPWSTR:
				vvalue.vt_lpwstr_v.vvector_elements = count;
				vvalue.vt_lpwstr_v.vvector_data =
					talloc_zero_array(ctx,
						struct vt_lpwstr, count);
				if (vvalue.vt_lpwstr_v.vvector_data == NULL) {
					return false;
				}
				break;
			case VT_COMPRESSED_LPWSTR:
				vvalue.vt_compresseed_lpwstr_v.vvector_elements
					= count;
				vvalue.vt_compresseed_lpwstr_v.vvector_data =
					talloc_zero_array(ctx,
						struct vt_compressed_lpwstr,
						count);
				if (vvalue.vt_compresseed_lpwstr_v.vvector_data == NULL) {
					return false;
				}
				break;
			default:
				DBG_ERR("Can't convert array of %s to VECTOR\n",
					get_vtype_name(vtype));
				return false;
		}
	}
	for (i = 0; i < count; i++) {
		if (variant_array[i]->vtype != vtype) {
			DBG_ERR("array item type %s doesn't match extpected "
				"type %s\n",
				get_vtype_name(variant_array[i]->vtype),
				get_vtype_name(vtype));
			return false;
		}
		switch (variant_array[i]->vtype) {
			case VT_BSTR:
				vvalue.vt_bstr_v.vvector_data[i]
					= variant_array[i]->vvalue.vt_bstr;
				break;
			case VT_LPWSTR:
				vvalue.vt_lpwstr_v.vvector_data[i]
					= variant_array[i]->vvalue.vt_lpwstr;
				break;
			case VT_COMPRESSED_LPWSTR:
				vvalue.vt_compresseed_lpwstr_v.vvector_data[i]
					= variant_array[i]->vvalue.vt_compressed_lpwstr;
				break;
			default:
				DBG_ERR("Can't convert array of %s to VECTOR\n",
					get_vtype_name(vtype));
				return false;
		}
	}
	outval->vtype = vtype | VT_VECTOR;
	outval->vvalue = vvalue;
	return true;
}

/*
 * get the addresses in rowbuf of variants to read from
 * pvec_address will point to addresses,
 * an array of n elements for a vector or array of 1 element
 * if non-vector item.
 *
 * addresses stored in pvec_address
 *
 */
static enum ndr_err_code extract_variant_addresses(TALLOC_CTX *ctx,
			       struct wsp_ctablevariant *tablevar,
			       bool is_64bit,
			       struct ndr_pull *ndr_pull,
			       ndr_flags_type flags,
			       uint64_t baseaddress,
			       DATA_BLOB *rows_buf,
			       uint64_t *pcount,
			       uint64_t **pvec_address)
{
	bool is_vector = tablevar->vtype & VT_VECTOR;
	uint64_t count;
	uint64_t addr;
	uint64_t *vec_address = NULL;
	enum ndr_err_code err;

	/* read count (only if this is a vector) */
	if (is_vector) {
		if (is_64bit) {
			err = ndr_pull_udlong(ndr_pull,
					flags,
					&count);
			if (err) {
				DBG_ERR("Failed to extract count\n");
				goto out;
			}
		} else {
			uint32_t count_32;
			err = ndr_pull_uint32(ndr_pull,
					flags,
					&count_32);
			if (err) {
				DBG_ERR("Failed to extract count\n");
				goto out;
			}
			count = (uint64_t)count_32;
		}
	} else {
		count = 1;
	}

	/* ensure count is at least within buffer range */
	if (count >= MAX_ROW_BUFF_SIZE || count >= rows_buf->length) {
		DBG_ERR("count %"PRIu64" either exceeds max buffer size "
			"or buffer size (%zu)",
			count,  rows_buf->length);
		err = NDR_ERR_VALIDATE;
		goto out;
	}

	/* read address */
	if (is_64bit) {
		err = ndr_pull_udlong(ndr_pull,
				flags,
				&addr);
		if (err) {
			DBG_ERR("Failed to extract address\n");
			goto out;
		}
	} else {
		uint32_t addr_32;
		err = ndr_pull_uint32(ndr_pull, flags, &addr_32);
		if (err) {
			DBG_ERR("Failed to extract address\n");
			goto out;
		}
		addr = addr_32;
	}

	if ((addr - baseaddress) >= rows_buf->length) {
		DBG_ERR("offset %"PRIu64" outside buffer range "
			"(buf len - %zu)\n",
			addr - baseaddress,
			rows_buf->length);
		err = NDR_ERR_VALIDATE;
		goto out;
	}

	vec_address = talloc_zero_array(ctx,
			uint64_t, count);

	if (vec_address == NULL) {
		err = NDR_ERR_ALLOC;
		goto out;
	}

	/*
	 * non vector case addr points to value
	 * otherwise addr points to list of addresses
	 * for the values in vector
	 */
	if (is_vector == false) {
		vec_address[0] = addr;
	} else {
		uint64_t array_offset = addr - baseaddress;
		uint64_t i;
		uint32_t intsize;

		if (is_64bit) {
			intsize = 8;
		} else {
			intsize = 4;
		}

		if (array_offset >= MAX_ROW_BUFF_SIZE
		    || array_offset >= rows_buf->length) {
			DBG_ERR("offset %"PRIu64" either exceeds max buf size "
				"or buffer size (%zu)",
				array_offset,  rows_buf->length);
			err = NDR_ERR_VALIDATE;
			goto out;
		}

		/* addr points to a list of int32 or int64 addresses */
		for (i = 0; i < count; i++) {
			/*
			 * read the addresses of the vector elements
			 * note: we can safely convert the uint64_t
			 *       values here to uint32_t values as
			 *       we are sure they are within range
			 *       due to previous checks above.
			 */
			if (smb_buffer_oob((uint32_t)rows_buf->length,
					   (uint32_t)array_offset,
					   intsize)) {
				DBG_ERR("offset %"PRIu64" will be outside "
					"buffer range (buf len - %zu) after "
					"reading %s address\n",
					array_offset,
					rows_buf->length,
					is_64bit ? "64 bit" : "32 bit");
				err = NDR_ERR_VALIDATE;
				goto out;
			}
			if (is_64bit) {
				vec_address[i] =
					PULL_LE_I64(rows_buf->data,
						array_offset);
			} else {
				vec_address[i] =
					(uint32_t)PULL_LE_I32(rows_buf->data,
							array_offset);
			}
			array_offset += intsize;
		}
	}
	err  = NDR_ERR_SUCCESS;
	*pcount = count;
	*pvec_address = vec_address;
out:
	return err;
}

static enum ndr_err_code extract_crowvariant_variable(TALLOC_CTX *ctx,
	struct wsp_ctablevariant *tablevar,
	bool is_64bit,
	struct ndr_pull *ndr_pull,
	ndr_flags_type flags,
	uint64_t baseaddress,
	DATA_BLOB *rows_buf,
	uint32_t len,
	struct wsp_cbasestoragevariant *val)
{
	enum ndr_err_code err;
	bool is_vector = tablevar->vtype & VT_VECTOR;
	uint64_t count = 0;

	uint64_t *vec_address = NULL;
	struct wsp_cbasestoragevariant **variant_array = NULL;
	int i;


	err = extract_variant_addresses(ctx,
			tablevar,
			is_64bit,
			ndr_pull,
			flags,
			baseaddress,
			rows_buf,
			&count,
			&vec_address);

	if (err) {
		DBG_ERR("Failed to extract address and/or count\n");
		goto out;
	}

	variant_array = talloc_zero_array(ctx,
			struct wsp_cbasestoragevariant*,
			count);

	if (variant_array == NULL) {
		err = NDR_ERR_ALLOC;
		goto out;
	}

	if (is_vector == false) {
		variant_array[0] = val;
	} else {
		for (i = 0; i < count; i++) {
			variant_array[i] = talloc_zero(ctx,
				struct wsp_cbasestoragevariant);
			if (variant_array[i] == NULL) {
					err = NDR_ERR_ALLOC;
					goto out;
				}
		}
	}

	for (i = 0; i < count; i++) {
		uint32_t tmplen = len;
		uint64_t buf_offset;
		buf_offset = vec_address[i] - baseaddress;
		if (buf_offset >= rows_buf->length) {
			DBG_ERR("offset %"PRIu64" outside buffer range "
				"(buf len - %zu)\n",
				buf_offset,
				rows_buf->length);
			err = NDR_ERR_VALIDATE;
			goto out;
		}
		if (is_64bit
		    && (tablevar->vtype & ~(VT_VECTOR)) == VT_LPWSTR) {
			/*
			 * we can't trust len if 64 bit mode
			 * (in 32 bit mode the length reported at len offset
			 * seem consistent and correct)
			 * So in this case instead of using the len
			 * at len offset we just use the full buffer
			 * from the point the value is stored at
			 * till the end of the buffer
			 */
			tmplen = rows_buf->length - buf_offset;
		}
		if (!extract_rowbuf_variable_type(ctx,
					tablevar->vtype & ~VT_VECTOR,
					buf_offset,
					rows_buf,
					tmplen,
					variant_array[i])) {
			err = NDR_ERR_VALIDATE;
			goto out;
		}
	}

	if (is_vector) {
		if (!convert_variant_array_to_vector(ctx,
						count,
						variant_array,
						val)) {
				err = NDR_ERR_VALIDATE;
				goto out;
			}
	}
	err  = NDR_ERR_SUCCESS;
out:
	return err;
}

static enum ndr_err_code extract_crowvariant(TALLOC_CTX *ctx,
			       struct wsp_ctablevariant *tablevar,
			       bool is_64bit,
			       struct ndr_pull *ndr_pull,
			       ndr_flags_type flags,
			       uint64_t baseaddress,
			       DATA_BLOB *rows_buf, uint32_t len,
			       struct wsp_cbasestoragevariant *val)
{
	enum ndr_err_code err  = NDR_ERR_SUCCESS;
	bool is_vector = tablevar->vtype & VT_VECTOR;
	bool is_array = tablevar->vtype & VT_ARRAY;

	if (is_array) {
		DBG_ERR("Not handling ARRAYs!!!\n");
		err = NDR_ERR_VALIDATE;
		goto out;
	}

	if (is_variable_size((tablevar->vtype & ~(VT_VECTOR)))) {
		err = extract_crowvariant_variable(ctx,
				tablevar,
				is_64bit,
				ndr_pull,
				flags,
				baseaddress,
				rows_buf,
				len,
				val);

	} else {
		if (is_vector) {
			DBG_ERR("Not handling VECTORs of fixed size values!!!\n");
			err = NDR_ERR_VALIDATE;
			goto out;
		}
		NDR_CHECK(ndr_pull_set_switch_value(ndr_pull,
					&val->vvalue,
					tablevar->vtype));
		NDR_CHECK(ndr_pull_variant_types(ndr_pull, NDR_SCALARS, &val->vvalue));
		val->vtype = tablevar->vtype;
	}
out:
	return err;
}

static enum ndr_err_code process_columns(TALLOC_CTX *ctx,
					 bool is_64bit,
					 uint64_t baseaddress,
					 struct wsp_cpmsetbindingsin *bindingin,
					 DATA_BLOB *rows_buf,
					 uint32_t nrow,
					 struct wsp_cbasestoragevariant *cols)
{
	uint32_t i;
	enum ndr_err_code err  = NDR_ERR_SUCCESS;
	struct ndr_pull *ndr_pull = NULL;
	ndr_flags_type ndr_flags = NDR_SCALARS | NDR_BUFFERS;
	uint64_t nrow_offset = (uint64_t)nrow * bindingin->brow;

	if (nrow_offset >= rows_buf->length) {
		DBG_ERR("offset %"PRIu64" outside buffer range (buf len - %zu)\n",
			nrow_offset,
			rows_buf->length);
		err = NDR_ERR_ALLOC;
		goto out;
	}

	/*
	 * process columns, column info is contained in cpmsetbindings
	 * for more information see 'Rows' description MS-WSP 2.2.4.1.2
	 * which describes how the server fills the buffer.
	 */
	for (i = 0; i < bindingin->ccolumns; i++) {
		struct wsp_ctablecolumn *tab_col = &bindingin->acolumns[i];
		DATA_BLOB col_val_blob = data_blob_null;
		uint64_t val_offset;
		struct wsp_ctablevariant tablevariant = {0};
		DBG_INFO("\nRow[%d]Col[%d] property %s type %s\n",nrow, i,
		      prop_from_fullprop(ctx, &tab_col->propspec),
		      get_vtype_name(tab_col->vtype));
		if (tab_col->statusused) {
			val_offset = nrow_offset + tab_col->statusoffset.value;
			if (val_offset >=  rows_buf->length) {
				DBG_ERR("offset %"PRIu64" outside buffer range "
					"(buf len - %zu)\n",
					val_offset,
					rows_buf->length);
				err = NDR_ERR_ALLOC;
				goto out;
			}
			DBG_INFO("\n\tstatusoffset 0x%x status is %s\n",
			      tab_col->statusoffset.value,
			      get_store_status(
				      (uint8_t)*(rows_buf->data
					+ val_offset)));
		}
		if (tab_col->lengthused) {
			val_offset = nrow_offset + tab_col->lengthoffset.value;
			if (val_offset >=  rows_buf->length) {
				DBG_ERR("offset %"PRIu64" outside buffer range "
					"(buf len - %zu)\n",
					val_offset,
					rows_buf->length);
				err = NDR_ERR_ALLOC;
				goto out;
			}
			DBG_INFO("\n\tlen offset 0x%x value at length is 0x%x\n",
				tab_col->lengthoffset.value,
				PULL_LE_I32(rows_buf->data,
					val_offset));
		}
		if (tab_col->valueused) {
			uint32_t len = 0;
			val_offset = nrow_offset + tab_col->valueoffset.value;
			if (val_offset >=  rows_buf->length) {
				DBG_ERR("offset %"PRIu64" outside buffer range "
					"(buf len - %zu)\n",
					val_offset,
					rows_buf->length);
				err = NDR_ERR_ALLOC;
				goto out;
			}
			DBG_INFO("\n\tvalueoffset:valuesize 0x%x:0x%x "
				"crowvariant address = 0x%"PRIx64"\n",
				tab_col->valueoffset.value,
				tab_col->valuesize.value,
				val_offset);

			col_val_blob.data = rows_buf->data + val_offset;
			col_val_blob.length = tab_col->valuesize.value;


			if (tab_col->vtype != VT_VARIANT) {
				DBG_ERR("Not handling non variant column "
					"values\n");
				err = NDR_ERR_VALIDATE;
				goto out;
			}
			ndr_pull = ndr_pull_init_blob(&col_val_blob, ctx);
			if (ndr_pull == NULL) {
				err = NDR_ERR_ALLOC;
				DBG_ERR("out of memory\n");
				goto out;
			}

			err = ndr_pull_wsp_ctablevariant(ndr_pull,
				ndr_flags,
				&tablevariant);
			if (err) {
				DBG_ERR("!!! failed to pull fixed part of variant data for col data\n");
				goto out;
			}
			DBG_INFO("\n");
			DBG_INFO("\tcrowvariant contains %s \n",
				get_vtype_name(tablevariant.vtype));

			if (tab_col->lengthused) {
				/*
				 * it seems the size is what's at
				 * lengthoffset - tab_col->valuesize.value
				 */
				len = PULL_LE_I32(rows_buf->data,
					nrow_offset
					+ tab_col->lengthoffset.value);
				len = len - tab_col->valuesize.value;
			}
			err = extract_crowvariant(ctx,
					&tablevariant,
					is_64bit,
					ndr_pull,
					ndr_flags,
					baseaddress,
					rows_buf,
					len,
					&cols[i]);
		}
	}
out:
	return err;
}

/*
 * extracts values from rows_buf into rowsarray
 * based on the information in bindingsin
 */
enum ndr_err_code extract_rowsarray(
			TALLOC_CTX * ctx,
			DATA_BLOB *rows_buf,
			bool is_64bit,
			struct wsp_cpmsetbindingsin *bindingsin,
			uint32_t cbreserved,
			uint64_t baseaddress,
			uint32_t rows,
			struct wsp_cbasestoragevariant **rowsarray)
{
	uint32_t i;
	enum ndr_err_code err  = NDR_ERR_SUCCESS;
	/*
	 * limit check the size of rows_buf
	 * see MS-WSP 2.2.3.11 which describes the size
	 * of the rows buffer MUST not exceed 0x0004000 bytes.
	 * This limit will ensure we can safely check
	 * limits based on uint32_t offsets
	 */

	if (rows_buf->length > MAX_ROW_BUFF_SIZE) {
		DBG_ERR("Buffer size 0x%zx exceeds 0x%x max buffer size\n",
			rows_buf->length, MAX_ROW_BUFF_SIZE);
		return NDR_ERR_BUFSIZE;
	}

	for (i = 0; i < rows; i++ ) {
		struct wsp_cbasestoragevariant *cols =
				talloc_zero_array(ctx,
					  struct wsp_cbasestoragevariant,
					  bindingsin->ccolumns);
		uint64_t adjusted_address;
		if (cols == NULL) {
			return NDR_ERR_ALLOC;
		}

		/*
		 * cater for paddingrows (see MS-WSP 2.2.3.12)
		 * Rows buffer starts cbreserved bytes into messages
		 */
		adjusted_address = baseaddress + cbreserved;

		err = process_columns(ctx,
				      is_64bit,
				      adjusted_address,
				      bindingsin,
				      rows_buf,
				      i,
				      cols);
		if (err) {
			break;
		}
		rowsarray[i] = cols;
	}
	return err;
}

static bool process_query_node(TALLOC_CTX *ctx,
			struct wsp_crestriction *crestriction,
			t_query *node);

static bool process_andornot_node(TALLOC_CTX *ctx,
			struct wsp_crestriction *crestr,
			t_query *node,
			struct wsp_crestriction **left,
			struct wsp_crestriction **right)
{
	struct wsp_cnoderestriction *restriction_node = NULL;

	*left = NULL;
	*right = NULL;

	restriction_node =
		&crestr->restriction.cnoderestriction;

	crestr->weight = 1000;

	if (node->type == eAND || node->type == eOR) {
		if (node->type == eAND) {
			crestr->ultype = RTAND;
		} else {
			crestr->ultype = RTOR;
		}
		if (!create_noderestriction(ctx, restriction_node, 2)) {
			return false;
		}
		*left = &restriction_node->panode[0];
		*right = &restriction_node->panode[1];
	} else {
		crestr->ultype = RTNOT;
		crestr->restriction.restriction.restriction =
			talloc_zero(ctx, struct wsp_crestriction);
		if (crestr->restriction.restriction.restriction == NULL) {
			DBG_ERR("out of memory\n");
			return false;
		}
		crestr =
			crestr->restriction.restriction.restriction;
	}
	if (*left == NULL) {
		*left = crestr;
	}
	if (*right == NULL) {
		*right = crestr;
	}
	return true;
}

static void process_value_node(TALLOC_CTX *ctx,
			struct wsp_crestriction *crestriction,
			t_query *node)
{
	*crestriction = *node->restriction;
}

static bool process_query_node(TALLOC_CTX *ctx,
			struct wsp_crestriction *crestriction,
			t_query *node)
{
	struct wsp_crestriction *left = NULL, *right = NULL;
	if (node == NULL) {
		return true;
	}
	switch (node->type) {
		case eAND:
		case eOR:
		case eNOT:
			if (!process_andornot_node(ctx, crestriction, node,
					      &left, &right)) {
				return false;
			}
			break;
		case eVALUE:
			process_value_node(ctx, crestriction, node);
			break;
		default:
			break;
	}
	if (!process_query_node(ctx, left, node->left)) {
		return false;
	}
	if (!process_query_node(ctx, right, node->right)) {
		return false;
	}
	return true;
}

bool create_querysearch_request(TALLOC_CTX * ctx,
				struct wsp_request* request,
				t_select_stmt *sql)
{
	uint32_t indices[sql->cols->num_cols];
	uint32_t i;
	uint32_t j;
	struct wsp_cpmcreatequeryin *createquery =
		&request->message.cpmcreatequery;

	for (i = 0; i < sql->cols->num_cols; i++) {
		indices[i] = i;
	}

	request->header.msg = CPMCREATEQUERY;
	createquery->ccolumnsetpresent = 1;
	createquery->columnset.columnset.count = sql->cols->num_cols;
	if (!fill_uint32_vec(ctx, &createquery->columnset.columnset.indexes,
			indices,
			sql->cols->num_cols)) {
		return false;
	}

	/* handle restrictions */
	createquery->crestrictionpresent = 1;
	createquery->restrictionarray.restrictionarray.count = 1;
	createquery->restrictionarray.restrictionarray.ispresent = 1;

	if (!create_restriction_array(ctx,
		 &createquery->restrictionarray.restrictionarray.restrictions,
		 createquery->restrictionarray.restrictionarray.count)) {
		return false;
	}


	if (!process_query_node(ctx,
		&createquery->restrictionarray.restrictionarray.restrictions[0],
		sql->where)) {
		return false;
	}


	/* handle rest */
	createquery->csortsetpresent = 1;
	if (createquery->csortsetpresent) {
		/* sort on first column */
		struct wsp_csort data[] = {
			{0x00000000, 0x00000000, 0x00000000, WSP_DEFAULT_LCID},
		};
		struct wsp_csortset *sortset = NULL;
		struct wsp_cingroupsortaggregsets *aggregsets = NULL;

		aggregsets = &createquery->sortset.groupsortaggregsets;
		aggregsets->ccount = 1;
		aggregsets->sortsets =
			talloc_zero_array(ctx,
					  struct wsp_cingroupsortaggregset,
					  aggregsets->ccount);
		sortset = &aggregsets->sortsets[0].sortaggregset;
		sortset->count = ARRAY_SIZE(data);
		if (!fill_sortarray(ctx,
				&sortset->sortarray,
				data,sortset->count)) {
			return false;
		}
	}

	createquery->ccategorizationsetpresent = 0;

	createquery->rowsetproperties.ubooleanoptions = 0x00000203;
	createquery->rowsetproperties.ulmaxopenrows = 0x00000000;
	createquery->rowsetproperties.ulmemoryusage = 0x00000000;
	createquery->rowsetproperties.cmaxresults = 0x00000000;
	createquery->rowsetproperties.ccmdtimeout = 0x00000005;

	createquery->pidmapper.count = sql->cols->num_cols;
	createquery->pidmapper.apropspec = talloc_zero_array(ctx,
						struct wsp_cfullpropspec,
						createquery->pidmapper.count);

	if (createquery->pidmapper.apropspec == NULL) {
		DBG_ERR("out of memory\n");
		return false;
	}

	for(i = 0, j = 0; i < sql->cols->num_cols; i++) {
		struct wsp_cfullpropspec *prop =
				&createquery->pidmapper.apropspec[j];
		char *propname = sql->cols->cols[i];
		/*
		 * don't put RowID in pidmapper or windows will reject
		 * the query.
		 */
		if (strequal(propname, "System.Search.RowID")) {
			continue;
		}
		if (!set_fullpropspec(ctx,
				      prop, sql->cols->cols[i],
				      PRSPEC_PROPID)) {
			DBG_ERR("Failed to handle property named %s\n",
				sql->cols->cols[i]);
			continue;
		}
		j++;
	}
	createquery->columnset.columnset.count = j;
	createquery->pidmapper.count = j;
	createquery->lcid = WSP_DEFAULT_LCID;
	return true;
}

static int32_t getNextAddress(int32_t value_off,
		int32_t status_off,
		int32_t len_off,
		int32_t max_value_size)
{
	return MAX(MAX(value_off + max_value_size, status_off + 1), len_off + 2);
}

static void create_binding_offsets(struct binding *binding, int no_cols,
		int max_value_size)
{
	uint32_t buf_addr = 0x0;
	uint32_t i;

	uint32_t value_off = 0;
	uint32_t len_off = 0;

	/* initial state this will get incremented to the desired 0x2 */
	uint32_t status_off = 0x1;
	uint32_t avail = 0x4;
	int status_remain = 0x2;
	int len_remain = -1;

	const static uint32_t WINDOW = 0x8;
	const static uint32_t LEN_STAT_SIZE = 0x4;
	for (i = 0; i < no_cols; i++) {
		buf_addr = buf_addr + WINDOW;
		value_off = buf_addr;

		if (status_remain <= 0) {
			if (avail) {
				status_off = avail;
				status_remain = LEN_STAT_SIZE;
				avail = 0;
			} else {
				/*
				 * we prepare the address to allocate
				 * another block from here. It will
				 * be allocated automatically when we
				 * re-enter the loop
				 */
				status_off = getNextAddress(value_off,
						status_off,
						len_off,
						max_value_size) + WINDOW;
				status_remain = LEN_STAT_SIZE;
				buf_addr = status_off;
				avail = buf_addr + LEN_STAT_SIZE;
			}
		} else {
			status_off++;
			buf_addr = getNextAddress(value_off,
					status_off,
					len_off,
					max_value_size);
		}

		if (len_remain <= 0) {
			if (avail) {
				len_off = avail;
				len_remain = LEN_STAT_SIZE;
				avail = 0;
			} else {
				/*
				 * we prepare the address to allocate
				 * another block from here. It will
				 * be allocated automatically when we
				 * re-enter the loop
				 */
				len_off = getNextAddress(value_off,
						status_off,
						len_off,
						max_value_size) + WINDOW;
				len_remain = LEN_STAT_SIZE;
				buf_addr = len_off;
				avail = buf_addr + LEN_STAT_SIZE;
			}
		} else {
			len_off += 0x4;
			buf_addr = getNextAddress(value_off,
					status_off,
					len_off,
					max_value_size);
		}
		status_remain--;
		len_remain -= LEN_STAT_SIZE;
		binding[i].value_off = value_off;
		binding[i].status_off = status_off;
		binding[i].len_off = len_off;
	}
}

static bool fill_bindings(TALLOC_CTX *ctx,
		   struct wsp_cpmsetbindingsin *bindingsin,
		   char **col_names,
		   bool is_64bit)
{
	uint32_t i;
	struct binding *offsets = NULL;
	uint32_t num_cols;
	int maxvalue = is_64bit ? 0x18 : 0x10;

	struct wsp_ctablecolumn *tablecols = bindingsin->acolumns;
	bindingsin->brow = 0x0;
	num_cols = bindingsin->ccolumns;

	offsets = talloc_zero_array(ctx, struct binding, num_cols);

	if (offsets == NULL) {
		DBG_ERR("out of memory\n");
		return false;
	}

	create_binding_offsets(offsets,
			num_cols,
			maxvalue);

	for (i = 0; i < num_cols; i++) {
		uint32_t max_off;
		if (!set_ctablecolumn(ctx, &tablecols[i], col_names[i],
				      &offsets[i], maxvalue)) {
			DBG_ERR("Failed to handle property named %s\n",
				col_names[i]);
			continue;
		}
		max_off = MAX(offsets[i].value_off + maxvalue,
			      offsets[i].status_off + 1);
		max_off = MAX(max_off, offsets[i].len_off + 2);
		if (max_off > bindingsin->brow) {
			bindingsin->brow = max_off;
		}
	}
	/* important */
	bindingsin->brow += ndr_align_size(bindingsin->brow,4);
	return true;
}

bool create_setbindings_request(TALLOC_CTX * ctx,
				struct wsp_request* request,
				t_select_stmt *sql,
				uint32_t cursor,
				bool is_64bit)
{
	struct wsp_cpmsetbindingsin *bindingsin =
		&request->message.cpmsetbindings;

	request->header.msg = CPMSETBINDINGSIN;
	bindingsin->hcursor = cursor;
	bindingsin->ccolumns = sql->cols->num_cols;

	bindingsin->acolumns = talloc_zero_array(ctx,
			struct wsp_ctablecolumn,
			bindingsin->ccolumns);

	if (bindingsin->acolumns == NULL) {
		DBG_ERR("out of memory\n");
		return false;
	}

	if (!fill_bindings(ctx, bindingsin, sql->cols->cols, is_64bit)) {
		return false;
	}

	return true;
}

enum search_kind get_kind(const char* kind_str)
{
	enum search_kind result = UNKNOWN;
	int i;
	const static struct {
		const char* str;
		enum search_kind search_kind;
	} kind_map[] = {
		{"Calendar", CALENDAR},
		{"Communication", COMMUNICATION},
		{"Contact", CONTACT},
		{"Document", DOCUMENT},
		{"Email", EMAIL},
		{"Feed", FEED},
		{"Folder", FOLDER},
		{"Game", GAME},
		{"InstantMessage", INSTANTMESSAGE},
		{"Journal", JOURNAL},
		{"Link", LINK},
		{"Movie", MOVIE},
		{"Music", MUSIC},
		{"Note", NOTE},
		{"Picture", PICTURE},
		{"Program", PROGRAM},
		{"RecordedTV", RECORDEDTV},
		{"SearchFolder", SEARCHFOLDER},
		{"Task", TASK},
		{"Video", VIDEO},
		{"WebHistory", WEBHISTORY},
	};
	for (i = 0; i < ARRAY_SIZE(kind_map); i++) {
		if (strequal(kind_str, kind_map[i].str)) {
			result = kind_map[i].search_kind;
			break;
		}
	}
	return result;
}

struct wsp_client_ctx
{
	struct dcerpc_binding_handle *h;
};

static NTSTATUS wsp_resp_pdu_complete(struct tstream_context *stream,
				      void *private_data,
				      DATA_BLOB blob,
				      size_t *packet_size)
{
	ssize_t to_read;

	to_read = tstream_pending_bytes(stream);
	if (to_read == -1) {
		return NT_STATUS_IO_DEVICE_ERROR;
	}

	if (to_read > 0) {
		*packet_size = blob.length + to_read;
		return STATUS_MORE_ENTRIES;
	}

	return NT_STATUS_OK;
}

static NTSTATUS wsp_rpc_transport_np_connect(struct cli_state *cli,
			  const struct ndr_interface_table *table,
			  TALLOC_CTX *mem_ctx,
			  struct rpc_cli_transport **presult)
{
	struct tevent_context *ev = NULL;
	struct tevent_req *req = NULL;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	ev = samba_tevent_context_init(mem_ctx);
	if (ev == NULL) {
		goto fail;
	}
	req = rpc_transport_np_init_send(ev, ev, cli, table);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = rpc_transport_np_init_recv(req, mem_ctx, presult);
fail:
	TALLOC_FREE(req);
	TALLOC_FREE(ev);
	return status;
}

NTSTATUS wsp_server_connect(TALLOC_CTX *mem_ctx,
			    const char *servername,
			    struct tevent_context *ev_ctx,
			    struct loadparm_context *lp_ctx,
			    struct cli_credentials *credentials,
			    struct cli_state *cli,
			    struct wsp_client_ctx **wsp_ctx)
{
	struct wsp_client_ctx *ctx = NULL;
	struct rpc_cli_transport *transport = NULL;
	struct tstream_context *stream = NULL;
	NTSTATUS status;

	bool smb2_or_greater =
		(lpcfg_client_max_protocol(lp_ctx) >= PROTOCOL_SMB2_02);

	if (!smb2_or_greater) {
		return NT_STATUS_PROTOCOL_NOT_SUPPORTED;
	}

	ctx = talloc_zero(mem_ctx, struct wsp_client_ctx);
	if (ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = smb2cli_ioctl_pipe_wait(
			cli->conn,
			cli->timeout,
			cli->smb2.session,
			cli->smb2.tcon,
			"MsFteWds",
			1);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("wait for pipe failed: %s)\n",
			nt_errstr(status));
		TALLOC_FREE(ctx);
		return status;
	}

	status = wsp_rpc_transport_np_connect(cli,
			&ndr_table_msftewds,
			cli,
			&transport);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("failed to int the pipe)\n");
		TALLOC_FREE(ctx);
		return status;
	}

	stream = rpc_transport_get_tstream(transport);
	ctx->h = tstream_binding_handle_create(ctx,
					       NULL,
					       &stream,
					       MSG_HDR_SIZE,
					       wsp_resp_pdu_complete,
					       ctx, 42280);
	if (ctx->h == NULL) {
		DBG_ERR("failed to create the pipe handle)\n");
		TALLOC_FREE(ctx);
		return NT_STATUS_UNSUCCESSFUL;
	}

	*wsp_ctx = ctx;

	return status;
}

static NTSTATUS write_something(TALLOC_CTX* ctx,
				struct dcerpc_binding_handle *handle,
				DATA_BLOB *blob_in,
				DATA_BLOB *blob_out)
{
	uint32_t outflags;
	NTSTATUS status;

	status = dcerpc_binding_handle_raw_call(handle,
						NULL,
						0,
						0,
						blob_in->data,
						blob_in->length,
						ctx,
						&blob_out->data,
						&blob_out->length,
						&outflags);
	return status;
}

/* msg is expected to be created on the heap with talloc */
static enum ndr_err_code parse_blob(TALLOC_CTX *ctx, DATA_BLOB *blob,
		struct wsp_request *request,
		struct wsp_response *response,
		DATA_BLOB *unread)
{
	struct ndr_pull *ndr = NULL;
	enum ndr_err_code err;
	ndr_flags_type ndr_flags = NDR_SCALARS | NDR_BUFFERS;
	uint32_t status = 0;

	ndr = ndr_pull_init_blob(blob, ctx);

	if (ndr == NULL) {
		return NDR_ERR_ALLOC;
	}

	/* peek at the status */
	status = PULL_LE_I32(blob->data, 4);

	/* is hard error ?*/
	if (status & 0x80000000 && blob->length == MSG_HDR_SIZE) {
		/* just pull the header */
		err = ndr_pull_wsp_header(ndr, ndr_flags, &response->header);
		DBG_ERR("error: %s\n", nt_errstr(NT_STATUS(status)));
		goto out;
	}
	err = ndr_pull_wsp_response(ndr, ndr_flags, response);
	if (err) {
		DBG_ERR("Failed to pull header from response blob error %d\n",  err);
		goto out;
	}
	if (DEBUGLEVEL >=6) {
		NDR_PRINT_DEBUG(wsp_response, response);
	}
	if (response->header.msg == CPMGETROWS) {
		if (request) {
			/* point to rows buffer */
			struct wsp_cpmgetrowsin *getrows =
				&request->message.cpmgetrows;
			ndr->offset = getrows->cbreserved;
		}
	}

	if (ndr->offset < blob->length) {
		int bytes = blob->length - ndr->offset;
		*unread = data_blob_named(blob->data + ndr->offset,
					  bytes, "UNREAD");
		DBG_WARNING("\nThere are unprocessed bytes (len 0x%x) "
			    "at end of message\n", bytes);
	}

out:
	return err;
}

static void set_msg_checksum(DATA_BLOB *blob, struct wsp_header *hdr)
{
	/* point at payload */
	uint32_t i;
	uint8_t *buffer = blob->data + MSG_HDR_SIZE;
	uint32_t buf_size = blob->length - MSG_HDR_SIZE;
	uint32_t nwords = buf_size/4;
	uint32_t offset = 0;
	uint32_t checksum = 0;

	static const uint32_t xor_const = 0x59533959;
	for(i = 0; i < nwords; i++) {
		checksum += PULL_LE_I32(buffer, offset);
		offset += 4;
	}

	checksum ^= xor_const;
	checksum -= hdr->msg;
	hdr->checksum = checksum;
}

static enum ndr_err_code insert_header_and_checksum(TALLOC_CTX *ctx,
		DATA_BLOB* blob,
		struct wsp_header *header)
{
	enum ndr_err_code err;
	ndr_flags_type ndr_flags = NDR_SCALARS | NDR_BUFFERS;
	struct ndr_push *header_ndr = ndr_push_init_ctx(ctx);

	if (header_ndr == NULL) {
		return NDR_ERR_ALLOC;
	}

	if (header->msg == CPMCONNECT
	|| header->msg == CPMCREATEQUERY
	|| header->msg == CPMSETBINDINGSIN
	|| header->msg == CPMGETROWS
	|| header->msg == CPMFETCHVALUE) {

		set_msg_checksum(blob, header);
	}
	err = ndr_push_wsp_header(header_ndr, ndr_flags, header);
	if (err) {
		DBG_ERR("Failed to push header, error %d\n", err);
		return err;
	}
	memcpy(blob->data, header_ndr->data, MSG_HDR_SIZE);
	return err;
}

NTSTATUS wsp_request_response(TALLOC_CTX* ctx,
			      struct wsp_client_ctx *wsp_ctx,
			      struct wsp_request* request,
			      struct wsp_response *response,
			      DATA_BLOB *unread)
{
	NTSTATUS status = NT_STATUS_OK;

	ndr_flags_type ndr_flags = NDR_SCALARS | NDR_BUFFERS;
	struct ndr_push* push_ndr = NULL;

	enum ndr_err_code err;

	DATA_BLOB req_blob;
	DATA_BLOB resp_blob;

	ZERO_STRUCT(req_blob);
	ZERO_STRUCT(resp_blob);

	push_ndr = ndr_push_init_ctx(ctx);
	if (push_ndr == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* write message payload first */
	push_ndr->offset = MSG_HDR_SIZE;
	DBG_INFO("\n");

	switch(request->header.msg) {
		case CPMCONNECT:
		{
			struct wsp_cpmconnectin *connectin =
				&request->message.cpmconnect;
			err =  ndr_push_wsp_cpmconnectin(push_ndr, ndr_flags,
						connectin);
			break;
		 }
		case CPMCREATEQUERY:
		{
			struct wsp_cpmcreatequeryin* createquery =
				&request->message.cpmcreatequery;
			err = ndr_push_wsp_cpmcreatequeryin(push_ndr,
					ndr_flags,
					createquery);
			req_blob = ndr_push_blob(push_ndr);
			/* we need to set cpmcreatequery.size */
			createquery->size =
				req_blob.length - MSG_HDR_SIZE;
			PUSH_LE_U32(req_blob.data, MSG_HDR_SIZE,
			      createquery->size);

			break;
		}
		case CPMSETBINDINGSIN:
		{
			struct wsp_cpmsetbindingsin *bindingsin =
				&request->message.cpmsetbindings;
			err = ndr_push_wsp_cpmsetbindingsin(push_ndr, ndr_flags,
						bindingsin);
			req_blob = ndr_push_blob(push_ndr);
			/* we need to set cpmsetbindings.bbindingdesc (size) */
			bindingsin->bbindingdesc =
					req_blob.length - MSG_HDR_SIZE - 16;
			PUSH_LE_U32(req_blob.data, MSG_HDR_SIZE + 8,
			      bindingsin->bbindingdesc);
			break;
		}
		case CPMGETROWS:
		{
			struct wsp_cpmgetrowsin *getrows =
				&request->message.cpmgetrows;
			err = ndr_push_wsp_cpmgetrowsin(push_ndr, ndr_flags,
						getrows);
			req_blob = ndr_push_blob(push_ndr);
			getrows->cbseek = req_blob.length - MSG_HDR_SIZE - 32;
			/* we need to set cpmgetrowsin.cbseek (size) */
			PUSH_LE_U32(req_blob.data, MSG_HDR_SIZE + 12,
			      getrows->cbseek);
			PUSH_LE_U32(req_blob.data, MSG_HDR_SIZE + 16,
			      getrows->cbreserved);
			break;
		}
		case CPMGETQUERYSTATUS:
		{
			struct wsp_cpmgetquerystatusin *querystatus =
				&request->message.cpmgetquerystatus;
			err = ndr_push_wsp_cpmgetquerystatusin(
					push_ndr,
					ndr_flags,
					querystatus);
			break;
		}
		case CPMGETQUERYSTATUSEX:
		{
			struct wsp_cpmgetquerystatusexin *statusexin =
				&request->message.cpmgetquerystatusex;
			err = ndr_push_wsp_cpmgetquerystatusexin(
					push_ndr,
					ndr_flags,
					statusexin);
			break;
		}
		case CPMFREECURSOR:
		{
			struct wsp_cpmfreecursorin *freecursor =
				&request->message.cpmfreecursor;
			err = ndr_push_wsp_cpmfreecursorin(
					push_ndr,
					ndr_flags,
					freecursor);
			break;
		}
		case CPMFETCHVALUE:
		{
			struct wsp_cpmfetchvaluein *fetchvalue =
				&request->message.cpmfetchvalue;
			err = ndr_push_wsp_cpmfetchvaluein(
					push_ndr,
					ndr_flags,
					fetchvalue);
			break;
		}

		case CPMGETAPPROXIMATEPOSITION:
		{
			struct wsp_cpmgetapproximatepositionin *position =
				&request->message.getapproximateposition;
			err = ndr_push_wsp_cpmgetapproximatepositionin(
				push_ndr,
				ndr_flags,
				position);
			break;
		}
		default:
			status = NT_STATUS_MESSAGE_NOT_FOUND;
			goto out;
			break;
	}
	if (err) {
		DBG_ERR("failed to serialise message! (%d)\n", err);
		status = NT_STATUS_UNSUCCESSFUL;
		goto out;
	}
	if (!req_blob.data) {
		req_blob = ndr_push_blob(push_ndr);
	}
	err = insert_header_and_checksum(ctx, &req_blob, &request->header);

	DBG_NOTICE("\nsending raw message from client len %d\n", (int)req_blob.length);
	DBG_NOTICE("\nsending raw message from client\n");
	DBG_NOTICE(  "===============================\n");

	dump_data(5, req_blob.data, req_blob.length);

	status = write_something(ctx, wsp_ctx->h, &req_blob, &resp_blob);

	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to write message\n");
		goto out;
	}
	DBG_NOTICE("\nraw response from server\n");
	DBG_NOTICE(  "========================\n");
	dump_data(5,  resp_blob.data, resp_blob.length);

	err = parse_blob(ctx,
			&resp_blob,
			request,
			response,
			unread);
	if (err) {
		DBG_ERR("Failed to parse response error %d\n", err);
		status = NT_STATUS_UNSUCCESSFUL;
		goto out;
	}
	DBG_NOTICE("response status is 0x%x\n", response->header.status);
	/* propagate error status to return status */
	if (response->header.status & 0x80000000) {
		status = NT_STATUS_UNSUCCESSFUL;
	}
out:
	return status;
}

struct dcerpc_binding_handle* get_wsp_pipe(struct wsp_client_ctx *ctx)
{
	return ctx->h;
}
