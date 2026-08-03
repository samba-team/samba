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

#include "includes.h"
#include "wsp_es_conv.h"
#include "talloc.h"
#include "util/talloc_stack.h"
#include "wsp_backend.h"
#include "librpc/wsp/wsp_util.h"
#include "smbd/proto.h"
#include <regex.h>
#include "wspd_db.h"
#include "libcli/security/security.h"
#include "lib/elastic_util.h"
#include "wsp_gss.h"

static const char scheme[] = "file://";

static json_t *get_json_mappings(void);

static const char *es_get_docid_for_entryid(TALLOC_CTX *ctx,
					    void *data,
					    uint32_t entryid);

/*
 * default conversion of a backend value to a wsp value
 * e.g. string -> string, number -> number etc.
 */
static HRESULT default_conv(TALLOC_CTX *ctx,
			    void *calling_ctx,
			    struct wsp_cbasestoragevariant *out_val,
			    int backend_type,
			    uint32_t vtypeout,
			    void *backend_val)
{
	HRESULT hres;

	switch (vtypeout) {
		case VT_LPWSTR:
			if (backend_type != BACKEND_STRING) {
				DBG_ERR("can't convert type %d to %s\n",
					backend_type,
					get_vtype_name(vtypeout));
				hres = HRESULT_FROM_NT(
						NT_STATUS_INVALID_PARAMETER);
				goto out;
			}
			set_variant_lpwstr(ctx, out_val, (const char *)backend_val);
			break;
		case VT_I4:
			if (backend_type != BACKEND_INTEGER) {
				DBG_ERR("can't convert type %d to %s\n",
					backend_type,
					get_vtype_name(vtypeout));
				hres = HRESULT_FROM_NT(
						NT_STATUS_INVALID_PARAMETER);
				goto out;
			}
			set_variant_i4(ctx, out_val, *(uint32_t *)(backend_val));
			break;
		case VT_UI8:
			if (backend_type != BACKEND_DOUBLE) {
				DBG_ERR("can't convert type %d to %s\n",
					backend_type,
					get_vtype_name(vtypeout));
			}
			out_val->vtype = VT_UI8;
			out_val->vvalue.vt_ui8 = *(uint64_t *)backend_val;
			break;
		case VT_VECTOR | VT_LPWSTR: {
			const char *tmp = (const char *)backend_val;

			if (backend_type != BACKEND_STRING) {
				DBG_ERR("can't convert type %d to VT_LPWSTR\n",
					backend_type);
				hres = HRESULT_FROM_NT(
						NT_STATUS_INVALID_PARAMETER);
				goto out;
			}
			set_variant_lpwstr_vector(ctx,
						  out_val,
						  &tmp,
						  1);
			break;
		}
		default:
			DBG_ERR("Don't yet support %s\n",
				get_vtype_name(vtypeout));
			hres = HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER);
			goto out;
	}
	hres = HRES_OK;
out:
	return hres;
}

/*
 * #TODO find out is there code in samba already doing this (seems like there
 * should be)
 * Note: only mangles path directory segments not files
 *       #TODO can't remember if this is a bug or what I found was needed
 */
static const char *mangle_path(TALLOC_CTX *ctx,
			       const char *relative_path,
			       struct share_params *params)
{
	/* step through each segment and assess if it needs mangling */
	TALLOC_CTX *frame = talloc_stackframe();
	const char *sep = "/";
	char *copy = NULL;
	char *curr = NULL;
	char *prev = NULL;
	const char *result = NULL;
	char *p = NULL;
	const char *end_of_string = NULL;
	const char *end_last_seg = NULL;
	struct segment_info {
		struct segment_info *prev, *next;
		const char *startpos;
		int num_chars;
	};
	struct segment_info *infos = NULL;
	struct segment_info *info = NULL;
	int max_size = 0;
	bool mangled = false;

	copy = talloc_strdup(frame, relative_path);
	if (copy == NULL) {
		DBG_ERR("out of memory\n");
		goto out;
	}

	curr = copy;
	end_of_string = copy + strlen(copy);

	/* see if the path starts with '/' */
	for (curr = strstr(curr, sep);
	     curr != NULL;
	     prev = curr, curr = strstr(curr + 1, sep))
	{
		int num_chars;
		bool needs_mangle = false;

		max_size++;
		if (prev == NULL) {
			continue;
		}

		num_chars = curr - prev - 1;
		if (num_chars == 0) {
			continue;
		}

		info = talloc_zero(frame, struct segment_info);
		if (info == NULL) {
			DBG_ERR("out of memory\n");
			goto out;
		}
		info->startpos = prev + 1;
		info->num_chars = num_chars;
		end_last_seg = info->startpos + num_chars;

		*curr = '\0';
		needs_mangle = mangle_must_mangle(prev + 1, params);
		if (needs_mangle) {
			char mname[13];

			name_to_8_3(prev + 1, mname, false, params);
			info->num_chars = strlen(mname);
			info->startpos = talloc_strdup(info, mname);
			if (info->startpos == NULL) {
				DBG_ERR("out of memory\n");
				goto out;
			}
			mangled = true;
		}
		*curr = '/';
		max_size += info->num_chars;
		DLIST_ADD_END(infos, info);
	}

	if (!mangled) {
		/*
		 * if no path seqments were mangled then just return the
		 * path we were passed
		 */
		result = relative_path;
		goto out;
	}
	/* some segment has been mangled, reconstruct path */
	max_size += (end_of_string - end_last_seg);
	p = talloc_zero_array(frame, char, max_size + 1);
	if (p == NULL) {
		DBG_ERR("out of memory\n");
		goto out;
	}
	result = p;
	/* build path from existing segments or mangled ones */
	for (info = infos; info; info = info->next) {
		*p = '/';
		p++;
		memcpy(p, info->startpos, info->num_chars);
		p += info->num_chars;
	}
	memcpy(p, end_last_seg, end_of_string - end_last_seg);
	result = talloc_move(ctx, &result);
out:
	TALLOC_FREE(frame);
	return result;
}

/*
 * WSP returns paths as file://NETBIOSNAME/SHARE/xyz
 * so this routine converts a file url (pointing at a local
 * share path) and returns the path (not including the 'file://'
 * scheme with the path to the share replaced by NETBIOSNAME/SHARE
 * in other words return
 * 'NETBIOSNAME/SHARE/xyz' for 'file:///local_share_path/xyz'
 * NOTE: path is mangled also (had problems with non mangled path
 *       crashing windows)
 */
static HRESULT get_relative_share_path(TALLOC_CTX *ctx,
				       const char *url,
				       const char *share_name,
				       const char *share_path,
				       const char **relative_share_path,
				       struct conn_wrap *conn_wrap)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct connection_struct *conn = NULL;
	char *s = NULL;
	char *local_share_path = NULL;
	const char *path = NULL;
	HRESULT hres;

	if (url == NULL) {
		hres = HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER);
		goto done;
	}

	conn = conn_wrap_connection(conn_wrap);

	s = strcasestr(url, scheme);
	/* make sure path really starts with scheme */
	if (s == NULL || s != url) {
		hres = HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER);
		goto done;
	}

	local_share_path = talloc_strdup(frame, s + strlen(scheme));
	if (local_share_path == NULL) {
		hres = HRES_E_OUTOFMEMORY;
		goto done;
	}

	/* make sure path really starts with share_path */
	s = strstr(local_share_path, share_path);
	if (s == NULL || s != local_share_path) {
		hres = HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER);
		goto done;
	}
	s = local_share_path + strlen(share_path);

	if (strlen(s) != 0 && s[strlen(s) - 1] == '/') {
		s[strlen(s) - 1] = '\0';
	}
	path = s;
	if (conn->params != NULL) {
		/* attempt to mangle the relative share path part */
		path = mangle_path(frame, path, conn->params);
		if (path == NULL) {
			hres = HRES_E_OUTOFMEMORY;
			goto done;
		}
	}

	*relative_share_path = talloc_asprintf(ctx,
					       "%s/%s%s",
					       lp_netbios_name(),
					       share_name,
					       path);
	if (*relative_share_path == NULL) {
		hres = HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER);
		goto done;
	}

	hres = HRES_OK;
done:
	TALLOC_FREE(frame);
	return hres;
}

/*
 * elastic to wsp conversion for a file path
 * The struct row_conv_data contains a pointer
 * to a cached version of url associated with
 * the result. It additionally caches the relative
 * share path (see get_relative_share_path above)
 * This saves us converting the file path multiple
 * times when more that one column needs the
 * converted url for this result.
 * * Remember: we synthesize some results from the
 *             url of the result, so multiple columns
 *             may need access to either the raw or
 *             relative_share_path version of the url
 */

static HRESULT convert_path(TALLOC_CTX *ctx,
			 void *calling_ctx,
			 struct wsp_cbasestoragevariant *out_val,
			 int backend_type,
			 uint32_t vtypeout,
			 void *backend_val)
{
	struct conv_call_ctx *conv_ctx = talloc_get_type_abort(
		calling_ctx, struct conv_call_ctx);
	struct row_conv_data *data = conv_ctx->row_conv_data;
	struct es_row_data *row_data = data->row_data;
	const char *es_url = NULL;
	const char *wsp_url = NULL;
	HRESULT hres;

	if (backend_type != BACKEND_STRING) {
		DBG_ERR("expected backend string type, got type %d\n",
			backend_type);
		hres = HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER);
		goto out;
	}

	if (data->row_url == NULL) {
		/*
		 * Own the cached url. It is read back by the remaining
		 * columns of this row, so its lifetime has to be that of
		 * data, not that of whatever the caller passed in.
		 */
		data->row_url = talloc_strdup(ctx,
					      (const char *)backend_val);
		if (data->row_url == NULL) {
			hres = HRES_E_OUTOFMEMORY;
			goto out;
		}
	}
	es_url = data->row_url;

	/*
	 * use the mangled url (with share name replacing share path) is we
	 * already have it
	 */
	if (data->row_relative_share_path == NULL) {
		hres = get_relative_share_path(data,
					       es_url,
					       row_data->share,
					       row_data->share_path,
					       &data->row_relative_share_path,
					       data->conn_wrap);
		if (!HRES_IS_OK(hres)) {
			DBG_ERR("error getting share path but %s\n",
				data->row_relative_share_path);
			goto out;
		}
	}

	wsp_url = talloc_asprintf(ctx,
				  "%s%s",
				  scheme,
				  data->row_relative_share_path);
	if (wsp_url == NULL) {
		hres = HRES_E_OUTOFMEMORY;
		goto out;
	}
	out_val->vtype = VT_LPWSTR;
	out_val->vvalue.vt_lpwstr.value = wsp_url;

	hres = HRES_OK;
out:
	return hres;
}

static HRESULT convert_real_path(TALLOC_CTX *ctx,
			 void *calling_ctx,
			 struct wsp_cbasestoragevariant *out_val,
			 int backend_type,
			 uint32_t vtypeout,
			 void *backend_val)
{
	TALLOC_CTX *frame = talloc_stackframe();
	char *es_url = NULL;
	HRESULT hres;

	es_url = talloc_asprintf(frame,
				 "file://%s",
				 (const char*)backend_val);
	if (es_url == NULL) {
		TALLOC_FREE(frame);
		return HRES_E_OUTOFMEMORY;
	}

	hres = convert_path(ctx,
			 calling_ctx,
			 out_val,
			 backend_type,
			 vtypeout,
			 (void *)es_url);
	TALLOC_FREE(frame);
	return hres;
}

/*
 * convert elasticsearch (unix) timestamp to
 * windows FILETIME
 */
static HRESULT convert_filetime(TALLOC_CTX *ctx,
				void *calling_ctx,
				struct wsp_cbasestoragevariant *out_val,
				int backend_type,
				uint32_t vtypeout,
				void *backend_val)
{
	HRESULT hres;
	/*
	 * elasticsearch time is a string with format
	 * [-]CCYY-MM-DDThh:mm:ss[Z|(+|-)hh:mm]
	 */
	const char *datetime = (const char*)backend_val;
	struct tm utc_time;
	time_t unixtime;
	NTTIME filetime;

	if (backend_type != BACKEND_STRING) {
		DBG_ERR("expected backend string type, got type %d\n",
			backend_type);
		hres = HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER);
		goto out;
	}

	if (strptime(datetime, "%FT%TZ", &utc_time) == NULL) {
		char *tmp = NULL;
		char *dot = NULL;
		/*
		 * it's possible the millsecs are tagged on after the time
		 * and before the timezone, we'll ignore them if that is
		 * the case.
		 */
		tmp = talloc_strdup(ctx, datetime);
		if (tmp == NULL) {
			DBG_ERR("Out of memory\n");
			return HRES_E_OUTOFMEMORY;
		}
		dot = strrchr(tmp, '.');
		if (dot == NULL) {
			DBG_ERR("failed to convert date-time %s\n", datetime);
			TALLOC_FREE(tmp);
			hres = HRESULT_FROM_NT(NT_STATUS_UNSUCCESSFUL);
			goto out;
		}
		*dot = 'Z';
		if (strptime(tmp, "%FT%TZ", &utc_time) == NULL) {
			DBG_ERR("failed to convert date-time %s\n",
				datetime);
			TALLOC_FREE(tmp);
			hres = HRESULT_FROM_NT(NT_STATUS_UNSUCCESSFUL);
			goto out;
		}
		TALLOC_FREE(tmp);
	}

	unixtime = timegm(&utc_time);

	unix_to_nt_time(&filetime, unixtime);
	out_val->vtype = VT_FILETIME;
	out_val->vvalue.vt_filetime = filetime;
	hres = HRES_OK;
out:
	return hres;
}


static HRESULT get_folderpath_from_url(TALLOC_CTX *ctx,
				       struct row_conv_data *data,
				       const char *url,
				       char **folderpath)
{
	struct es_row_data *row_data = data->row_data;
	char *result = NULL;
	char *slash = NULL;
	char *tmp = NULL;
	HRESULT hres;

	if (data == NULL) {
		return  HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER);
	}
	row_data = data->row_data;

	if (data->row_url == NULL) {
		data->row_url = talloc_strdup(data, url);
		if (data->row_url == NULL) {
			return HRES_E_OUTOFMEMORY;
		}
	}

	/* get the NETBIOS/SHARENAME/xyz path associate with this url */
	if (data->row_relative_share_path == NULL) {
		hres = get_relative_share_path(data,
					       url,
					       row_data->share,
					       row_data->share_path,
					       &data->row_relative_share_path,
					       data->conn_wrap);
		if (!HRES_IS_OK(hres)) {
			return hres;
		}
	}

	/* strip final '/' */

	tmp = talloc_strdup(talloc_tos(), data->row_relative_share_path);
	if (tmp == NULL) {
		return HRES_E_OUTOFMEMORY;
	}
	slash = strrchr(tmp, '/');
	if (slash) {
		*slash = '\0';
	}

	result = talloc_asprintf(ctx, "//%s", tmp);
	TALLOC_FREE(tmp);
	if (result == NULL) {
		return HRES_E_OUTOFMEMORY;
	}

	*folderpath = result;
	return HRES_OK;
}

/*
 * converts row results url to relative_share_path
 * url
 * e.g. file:///local_share_path/file.ext
 *        => \\NETBIOSNAME\relative_share_path
 */
static HRESULT convert_folderpath(TALLOC_CTX *ctx,
			       void *calling_ctx,
			       struct wsp_cbasestoragevariant *out_val,
			       int backend_type,
			       uint32_t vtypeout,
			       void *backend_val)
{
	struct conv_call_ctx *conv_ctx = talloc_get_type_abort(
		calling_ctx, struct conv_call_ctx);
	struct row_conv_data *data = conv_ctx->row_conv_data;
	char *result = NULL;
	char *url = NULL;
	HRESULT hres;

	if (backend_type != BACKEND_STRING) {
		DBG_ERR("expected backend string type, got type %d\n",
			backend_type);
		return HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER);
	}

	url = (char *)backend_val;

	hres = get_folderpath_from_url(ctx,
			data,
			url,
			&result);
	if (!HRES_IS_OK(hres)) {
		goto out;
	}

	string_replace(result, '/', '\\');

	out_val->vtype = VT_LPWSTR;
	out_val->vvalue.vt_lpwstr.value = result;
	hres = HRES_OK;
out:
	return hres;
}

static HRESULT convert_real_folderpath(TALLOC_CTX *ctx,
			       void *calling_ctx,
			       struct wsp_cbasestoragevariant *out_val,
			       int backend_type,
			       uint32_t vtypeout,
			       void *backend_val)
{
	TALLOC_CTX *frame = talloc_stackframe();
	char *es_url = NULL;
	HRESULT hres;

	es_url = talloc_asprintf(frame,
				 "file://%s",
				 (const char*)backend_val);
	if (es_url == NULL) {
		TALLOC_FREE(frame);
		return HRES_E_OUTOFMEMORY;
	}

	hres = convert_folderpath(ctx,
			 calling_ctx,
			 out_val,
			 backend_type,
			 vtypeout,
			 (void*)es_url);
	TALLOC_FREE(frame);
	return hres;
}
/*
 * converts row results url to relative_share_path
 * url pointing to parent folder followed by the
 * grandparent folder
 * e.g. file:///local_share_path/xyz/file.ext
 *        => xys (\\NETBIOSNAME\SHARE\relative_share_path)
 */
static HRESULT convert_folderpath_narrow(
			TALLOC_CTX *ctx,
			void *calling_ctx,
			struct wsp_cbasestoragevariant *out_val,
			int backend_type,
			uint32_t vtypeout,
			void *backend_val)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct conv_call_ctx *conv_ctx = talloc_get_type_abort(
		calling_ctx, struct conv_call_ctx);
	struct row_conv_data *data = conv_ctx->row_conv_data;
	const char *url = NULL;
	char *result = NULL;
	char *remainder = NULL;
	char *slash = NULL;
	char *tmp = NULL;
	HRESULT hres;

	if (backend_type != BACKEND_STRING) {
		DBG_ERR("expected backend string type, got type %d\n",
			backend_type);
		hres = HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER);
		goto out;
	}

	url = (char *)backend_val;

	hres = get_folderpath_from_url(frame, data, url, &tmp);
	if (!HRES_IS_OK(hres)) {
		goto out;
	}

	/* strip final '/' */
	/* split NETBIOS/relativepath and xyz portions */
	slash = strchr(tmp, '/');
	if (slash == NULL) {
		hres = HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER);
		goto out;
	}
	slash = strchr(slash + 1, '/');
	/* tmp points to NETBIOS/SHARENAME */
	if (slash != NULL) {
		char *last_slash = strrchr(slash, '/');

		if (last_slash) {
			slash = last_slash;
		}
		*slash = '\0';
		remainder = (slash + 1);
	} else {
		/*
		 * there is no subdirectory, make remainder point to
		 * empty string, e.g. just point at end of tmp
		 */
		remainder = tmp + strlen(tmp);
	}

	result = talloc_asprintf(ctx, "%s (%s)", remainder, tmp);
	if (result == NULL) {
		hres = HRES_E_OUTOFMEMORY;
		goto out;
	}

	string_replace(result, '/', '\\');

	out_val->vtype = VT_LPWSTR;
	out_val->vvalue.vt_lpwstr.value = result;
	hres = HRES_OK;
out:
	TALLOC_FREE(frame);
	return hres;
}

static HRESULT convert_real_folderpath_narrow(TALLOC_CTX *ctx,
				      void *calling_ctx,
				      struct wsp_cbasestoragevariant *out_val,
				      int backend_type,
				      uint32_t vtypeout,
				      void *backend_val)
{
	TALLOC_CTX *frame = talloc_stackframe();
	char *es_url = NULL;
	HRESULT hres;

	es_url = talloc_asprintf(frame,
				 "file://%s",
				 (const char *)backend_val);
	if (es_url == NULL) {
		TALLOC_FREE(frame);
		return HRES_E_OUTOFMEMORY;
	}

	hres = convert_folderpath_narrow(ctx,
			 calling_ctx,
			 out_val,
			 backend_type,
			 vtypeout,
			 (void *)es_url);
	TALLOC_FREE(frame);
	return hres;
}

static HRESULT convert_itemtypetext(TALLOC_CTX *ctx,
				 void *calling_ctx,
				 struct wsp_cbasestoragevariant *out_val,
				 int backend_type,
				 uint32_t vtypeout,
				 void *backend_val)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct conv_call_ctx *conv_ctx = talloc_get_type_abort(
		calling_ctx, struct conv_call_ctx);
	struct row_conv_data *data = conv_ctx->row_conv_data;
	HRESULT hres;
	char *ext = NULL;
	char *upper = NULL;
	json_t *mappings = NULL;
	json_t *types_map = NULL;
	json_t *val = NULL;

	if (data->is_folder_result) {
		out_val->vvalue.vt_lpwstr.value =
			talloc_strdup(ctx, "File Folder");
		if (out_val->vvalue.vt_lpwstr.value == NULL) {
			hres = HRES_E_OUTOFMEMORY;
			goto out;
		}
		out_val->vtype = VT_LPWSTR;
		TALLOC_FREE(frame);
		return HRES_OK;
	}

	if (backend_type != BACKEND_STRING) {
		DBG_ERR("expected backend string type, got type %d\n",
			backend_type);
		hres = HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER);
		goto out;
	}

	if (backend_val == NULL) {
		DBG_ERR("couldn't get itemtypetext from NULL backend value\n");
		hres = HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER);
		goto out;
	}

	ext = strrchr((char *)(backend_val), '.');
	if (ext == NULL || strlen(ext) < 2) {
		hres = HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER);
		goto out;
	}
	ext = strlower_talloc(frame, ext + 1);
	if (ext == NULL) {
		hres = HRES_E_OUTOFMEMORY;
		goto out;
	}

	mappings = get_json_mappings();
	if (mappings == NULL) {
		hres = HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER);
		goto out;
	}

	types_map = json_object_get(mappings, "type_mappings");

	out_val->vtype = VT_LPWSTR;
	val = json_object_get(types_map, ext);
	if (val != NULL) {
		const char *sval = json_string_value(val);
		int type = json_typeof(val);

		DBG_DEBUG("type is %s (%d)\n", sval, type);

		out_val->vvalue.vt_lpwstr.value = talloc_strdup(ctx, sval);
		if (out_val->vvalue.vt_lpwstr.value == NULL) {
			hres = HRES_E_OUTOFMEMORY;
			goto out;
		}
	} else {
		/* no match, just use "EXT File" as description */
		upper = talloc_strdup_upper(ctx, ext);
		if (upper == NULL) {
			hres = HRES_E_OUTOFMEMORY;
			goto out;
		}
		out_val->vvalue.vt_lpwstr.value =
			talloc_asprintf(ctx, "%s File", upper);
		if (out_val->vvalue.vt_lpwstr.value == NULL) {
			hres = HRES_E_OUTOFMEMORY;
			goto out;
		}
	}

	hres = HRES_OK;
out:
	TALLOC_FREE(frame);
	return hres;
}

static HRESULT convert_itemtype(TALLOC_CTX *ctx,
				void *calling_ctx,
				struct wsp_cbasestoragevariant *out_val,
				int backend_type,
				uint32_t vtypeout,
				void *backend_val)
{
	struct conv_call_ctx *conv_ctx = talloc_get_type_abort(
		calling_ctx, struct conv_call_ctx);
	struct row_conv_data *data = conv_ctx->row_conv_data;
	char *ext = NULL;

	if (data->is_folder_result) {
		out_val->vtype = VT_LPWSTR;
		out_val->vvalue.vt_lpwstr.value = talloc_strdup(
			ctx, "Directory");
		if (out_val->vvalue.vt_lpwstr.value == NULL) {
			return HRES_E_OUTOFMEMORY;
		}
		return HRES_OK;
	}

	if (backend_type != BACKEND_STRING) {
		DBG_ERR("expected backend string type, got type %d\n",
			backend_type);
		return HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER);
	}

	if (backend_val == NULL) {
		DBG_ERR("couldn't get itemtype from NULL backend value\n");
		return HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER);
	}

	ext = strrchr((char*)(backend_val), '.');
	if (ext == NULL) {
		return HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER);
	}
	ext = talloc_asprintf(ctx, ".%s", ext + 1);
	if (ext == NULL) {
		return HRES_E_OUTOFMEMORY;
	}

	out_val->vtype = VT_LPWSTR;
	out_val->vvalue.vt_lpwstr.value = ext;
	return HRES_OK;
}

static HRESULT convert_kind(TALLOC_CTX *ctx,
			    void *calling_ctx,
			    struct wsp_cbasestoragevariant *out_val,
			    int backend_type,
			    uint32_t vtypeout,
			    void *backend_val)
{
	TALLOC_CTX *frame = talloc_stackframe();
	const char *val = NULL;
	regex_t regex;
	json_t *mappings = NULL;
	json_t *kind_map = NULL;
	const char *key = NULL;
	json_t *value = NULL;
	char *l_mime = NULL;
	HRESULT hres;

	if (backend_type != BACKEND_STRING) {
		DBG_ERR("expected backend string type, got type %d\n",
			backend_type);
		hres = HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER);
		goto out;
	}

	mappings = get_json_mappings();
	if (mappings == NULL) {
		hres = HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER);
		goto out;
	}

	kind_map =  json_object_get(mappings, "kind_mappings");
	if (kind_map == NULL) {
		hres = HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER);
		goto out;
	}

	val = (const char *)backend_val;
	l_mime = strlower_talloc(frame, val);
	if (l_mime == NULL) {
		hres = HRES_E_OUTOFMEMORY;
		goto out;
	}
	json_object_foreach(kind_map, key, value) {
		const char *media_types = json_string_value(value);
		char **list = NULL;
		const char *item = NULL;

		list = str_list_make(frame, media_types, " ");

		for (;list != NULL && *list != NULL; list++) {
			struct vt_lpwstr *data = NULL;
			char *pattern = NULL;
			int res;

			item = *list;
			pattern = talloc_asprintf(frame, "^%s", item);
			if (pattern == NULL) {
				hres = HRES_E_OUTOFMEMORY;
				goto out;
			}

			res = regcomp(&regex, pattern, 0);
			if (res != 0) {
				DBG_ERR("Skipping %s create regrex "
					"pattern from it\n",
					pattern);
				hres = HRES_E_UNEXPECTED;
				goto out;
			}

			TALLOC_FREE(pattern);

			res = regexec(&regex, l_mime, 0, NULL, 0);
			regfree(&regex);
			if (res != 0) {
				continue;
			}
			data = talloc_zero_array(ctx, struct vt_lpwstr, 1);
			if (data == NULL) {
				hres = HRES_E_OUTOFMEMORY;
				goto out;
			}
			data[0].value = talloc_strdup(ctx, key);
			if (data[0].value == NULL) {
				hres = HRES_E_OUTOFMEMORY;
				goto out;
			}
			out_val->vtype = VT_VECTOR | VT_LPWSTR;
			out_val->vvalue.vt_lpwstr_v.vvector_elements = 1;
			out_val->vvalue.vt_lpwstr_v.vvector_data = data;
			hres = HRES_OK;
			goto out;
		}
	}
	hres = HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER);
out:
	TALLOC_FREE(frame);
	return hres;
}

/*
 * According to learn.microsoft.com
 * this is bitwise combination of the following
 * Archive		32
 * Compressed		2048
 * Device		64
 * Directory		16
 * Encrypted		16384
 * Hidden		2
 * IntegrityStream	32768
 * Normal  		128
 * NoScrubData		131072
 * NotContentIndexed	8192
 * Offline		4096
 * ReadOnly		1
 * ReparsePoint		1024
 * SparseFile		512
 * System		4
 * Temporary		256
 *
 */
static HRESULT convert_fileattrs(TALLOC_CTX *ctx,
				 void *calling_ctx,
				 struct wsp_cbasestoragevariant *out_val,
				 int backend_type,
				 uint32_t vtypeout,
				 void *backend_val)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct conv_call_ctx *conv_ctx = talloc_get_type_abort(
		calling_ctx, struct conv_call_ctx);
	struct connection_struct *conn = NULL;
	struct smb_filename *smb_fname = NULL;
	struct row_conv_data *data = conv_ctx->row_conv_data;
	const char *path = NULL;
	const char *es_row_url = NULL;
	uint32_t fileattr = 0;
	HRESULT hres;
	NTSTATUS status;

	conn = conn_wrap_connection(data->conn_wrap);

	if (backend_type != BACKEND_STRING) {
		DBG_ERR("expected backend string type, got type %d\n",
			backend_type);
		hres = HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER);
		goto out;
	}

	es_row_url = (const char*)backend_val;
	if (es_row_url == NULL) {
		DBG_ERR("no url to get fileattributes from\n");
		hres = HRESULT_FROM_NT(NT_STATUS_UNSUCCESSFUL);
		goto out;
	}
	path = es_row_url + strlen("file://");

	status = conn_wrap_chdir(data->conn_wrap, frame);
	if (NT_STATUS_IS_OK(status)) {
		DBG_ERR("vfs_ChDir_shareroot failed\n");
		hres = HRESULT_FROM_NT(status);
		goto out;
	}

	status = synthetic_pathref(frame,
                                   conn->cwd_fsp,
                                   path,
                                   NULL,
                                   NULL,
                                   0,
                                   0,
                                   &smb_fname);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("synthetic_pathref [%s]: %s\n",
			  smb_fname_str_dbg(smb_fname),
			  nt_errstr(status));
		hres = HRESULT_FROM_NT(status);
		goto out;
	}

	fileattr = fdos_mode(smb_fname->fsp);
	TALLOC_FREE(smb_fname);

	out_val->vtype = VT_UI4;
	out_val->vvalue.vt_ui4 = fileattr;
	hres = HRES_OK;
out:
	TALLOC_FREE(frame);
	return hres;
}

static HRESULT convert_real_fileattrs(TALLOC_CTX *ctx,
				  void *calling_ctx,
				  struct wsp_cbasestoragevariant *out_val,
				  int backend_type,
				  uint32_t vtypeout,
				  void *backend_val)
{
	TALLOC_CTX *frame = talloc_stackframe();
	char *es_url = NULL;
	HRESULT hres;

	es_url = talloc_asprintf(frame,
				 "file://%s",
				 (const char*)backend_val);
	if (es_url == NULL) {
		TALLOC_FREE(frame);
		return HRES_E_OUTOFMEMORY;
	}

	hres = convert_fileattrs(ctx,
			 calling_ctx,
			 out_val,
			 backend_type,
			 vtypeout,
			 (void*)es_url);
	TALLOC_FREE(frame);
	return hres;
}

static uint32_t gen_rowid(struct row_conv_data *private_data)
{
	uint32_t new_index;
	struct es_row_data *row_data = private_data->row_data;

	(*row_data->rowid_generator)++;
	new_index = (*row_data->rowid_generator);
	return new_index;
}

/*
 * A simple counter maintained to create an index for
 * each row returned from a query. We don't synthesize
 * this from any existing result or data from elasticsearch
 * but instead simply increase a counter.
 */
static HRESULT convert_rowid(TALLOC_CTX *ctx,
			     void *calling_ctx,
			     struct wsp_cbasestoragevariant *out_val,
			     int backend_type,
			     uint32_t vtypeout,
			     void *backend_val)
{
	struct conv_call_ctx *conv_ctx = talloc_get_type_abort(
		calling_ctx, struct conv_call_ctx);
	struct row_conv_data *row_conv_data = conv_ctx->row_conv_data;

	out_val->vtype = VT_I4;
	out_val->vvalue.vt_i4 = gen_rowid(row_conv_data);
	return HRES_OK;
}

static HRESULT convert_entryid(TALLOC_CTX *ctx,
			       void *calling_ctx,
			       struct wsp_cbasestoragevariant *out_val,
			       int backend_type,
			       uint32_t vtypeout,
			       void *backend_val)
{
	struct conv_call_ctx *conv_ctx = talloc_get_type_abort(
		calling_ctx, struct conv_call_ctx);
	struct es_row_data *row_data = conv_ctx->row_conv_data->row_data;
	struct connection_struct *conn = NULL;
	const char *index_name = NULL;
	const char *val = NULL;
	uint32_t entryid;
	HRESULT hres;

	conn = conn_wrap_connection(conv_ctx->row_conv_data->conn_wrap);

	index_name = lp_parm_substituted_string(calling_ctx,
                                        loadparm_s3_global_substitution(),
                                        conn->params->service,
                                        "elasticsearch",
                                        "index",
                                        "_all");

	if (backend_type != BACKEND_STRING) {
		DBG_ERR("expected backend string type, got type %d\n",
			backend_type);
		hres = HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER);
		goto out;
	}

	val = (const char *)backend_val;
	entryid = get_or_create_entry_id(row_data->id_cache, index_name, val);
	if (entryid == 0) {
		DBG_ERR("failed to convert %s to entry id\n", val);
		hres = HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER);
		goto out;
	}
	out_val->vtype = VT_I4;
	out_val->vvalue.vt_i4 = entryid;
	hres = HRES_OK;
out:
	return hres;
}

static const char *get_media_type_for_kind(TALLOC_CTX *ctx,
					   const char *kind,
					   struct elastic_json_mapping *json_cfg)
{
	TALLOC_CTX *frame = talloc_stackframe();
	const char *key = NULL;
	json_t *value = NULL;
	const char *result = NULL;
	char *l_kind = NULL;

	l_kind = strlower_talloc(frame, kind);
	if (l_kind == NULL) {
		DBG_ERR("Out of memory\n");
		goto out;
	}
	json_object_foreach(json_cfg->kind_map, key, value) {
		char *tmp = NULL;
		bool equal;

		tmp = strlower_talloc(l_kind, key);
		if (tmp == NULL) {
			DBG_ERR("Out of memory\n");
			goto out;
		}
		equal = strequal(l_kind, tmp);
		TALLOC_FREE(tmp);
		if (equal) {
			result = json_string_value(value);
			break;
		}
	}
out:
	TALLOC_FREE(frame);
	return result;
}
static HRESULT get_es_value_for_kind(TALLOC_CTX *ctx,
				     void *calling_ctx,
				     struct wsp_crestriction *restric,
				     bool escape,
				     const char **output)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct es_query_ctx *data = talloc_get_type_abort(
		calling_ctx, struct es_query_ctx);
	const char *prop_val = NULL;
	HRESULT hres;

	if (restric->ultype != RTPROPERTY) {
		DBG_ERR("scope_filter_helper failed for restriction type %d\n",
			restric->ultype);
		hres = HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER);
		goto done;
	}

	prop_val = variant_as_string(frame,
			&restric->restriction.cpropertyrestriction.prval,
			false);
	if (prop_val == NULL) {
		hres = HRES_E_OUTOFMEMORY;
		goto done;
	}

	prop_val = get_media_type_for_kind(frame, prop_val, data->json_config);
	if (prop_val == NULL) {
		/* force query fail */
		prop_val = talloc_strdup(frame, "unknown/unknown");
		if (prop_val == NULL) {
			hres = HRES_E_OUTOFMEMORY;
			goto done;
		}
	}
	if (escape) {
		if (strlen(prop_val) == 0) {
			/*
			 * #TODO there must be a better way to handle
			 * this, mime/unknown is a dummy placeholder to
			 * force elasticsearch to evaluate to no results
			 */
			prop_val = talloc_strdup(frame, "mime/unknown");
			if (prop_val == NULL) {
				hres = HRES_E_OUTOFMEMORY;
				goto done;
			}
		}
		prop_val = es_escape_str(frame, prop_val, NULL, "* ");
		if (prop_val == NULL) {
			hres = HRES_E_OUTOFMEMORY;
			goto done;
		}
	}
	*output = talloc_move(ctx, &prop_val);
	hres = HRES_OK;
done:
	TALLOC_FREE(frame);
	return hres;
}

static HRESULT get_share_path(TALLOC_CTX *ctx,
			      const char *share,
			      char **share_path)
{
        int snum;
        char *service = NULL;
        char *path = NULL;

        const struct loadparm_substitution *lp_sub =
                loadparm_s3_global_substitution();

        if (share_path == NULL || share == NULL) {
		return HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER);
        }
        snum = find_service(ctx, share, &service);
        if ((snum == -1) || (service == NULL)) {
		return HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER);
        }
	TALLOC_FREE(service);
        path = lp_path(ctx, lp_sub, snum);
        if (path == NULL) {
		return HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER);
        }
        *share_path = path;
        return HRES_OK;
}

static HRESULT get_share(TALLOC_CTX *ctx,
			 const char *win_url,
			 const char **shareout)
{
	TALLOC_CTX *frame = talloc_stackframe();
	char *share = NULL;
	char *s = NULL;
	HRESULT hres;

	if (win_url == NULL) {
		hres = HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER);
		goto out;
	}

	s = strcasestr(win_url, scheme);
	if (s == NULL) {
		hres = HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER);
		goto out;
	}

	s = s + strlen(scheme);

	share = talloc_strdup(frame, s);
	if (share == NULL) {
		hres = HRES_E_OUTOFMEMORY;
		goto out;
	}

	s = strchr(share, '/');
	if (s == NULL) {
		hres = HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER);
		goto out;
	};

	share = talloc_strdup(ctx, s + 1);
	if (share == NULL) {
		hres = HRES_E_OUTOFMEMORY;
		goto out;
	}
	s = strchr(share, '/');
	if (s != NULL) {
		*s = '\0';
	}
	*shareout = share;
	hres = HRES_OK;
out:
	TALLOC_FREE(frame);
	return hres;
}

/* need to replace file://NETBIOS/SHARENAME with file:///local-path */
static HRESULT replace_share_in_url(TALLOC_CTX *ctx,
				    const char* path,
                                    const char **local_path)
{
	TALLOC_CTX *frame = talloc_stackframe();
        const char *result = NULL;
        const char *share = NULL;
        char *share_path = NULL;
        const char *tmp = NULL;
        HRESULT hres;

        hres = get_share(frame, path, &share);
        if (!HRES_IS_OK(hres)) {
		goto out;
        }

        hres = get_share_path(frame, share, &share_path);
        if (!HRES_IS_OK(hres)) {
		goto out;
        }

        tmp = strcasestr(path, share);
        if (tmp == NULL) {
		hres = HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER);
		goto out;
	}
	result = talloc_asprintf(ctx, "file://%s%s",
				 share_path,
				 tmp + strlen(share));
	if (result == NULL) {
		hres = HRES_E_OUTOFMEMORY;
		goto out;
	}
        *local_path = result;
        hres = HRES_OK;
out:
	TALLOC_FREE(frame);
        return hres;
}

static HRESULT get_es_value_for_wsppath(TALLOC_CTX *ctx,
					void *calling_ctx,
					struct wsp_crestriction *restric,
					bool escape,
					const char **output)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct es_query_ctx *data = talloc_get_type_abort(
		calling_ctx, struct es_query_ctx);
        const char *path = NULL;
        const char *local_path = NULL;
        HRESULT hres;

        if (restric->ultype != RTPROPERTY) {
                DBG_ERR("conversion failed for restriction type %d\n",
                        restric->ultype);
                hres = HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER);
                goto done;
        }

        path = variant_as_string(frame,
			&restric->restriction.cpropertyrestriction.prval,
			false);

	/* make sure we cache the share we are using for scope */
	if (!data->share_scope) {
		hres = get_share(data, path, &data->share_scope);
		if (!HRES_IS_OK(hres)) {
			goto done;
		}
	}
        hres = replace_share_in_url(frame, path, &local_path);
        if (!HRES_IS_OK(hres)) {
                goto done;
        }

        if (strlen(local_path) > strlen(scheme)) {
                local_path = local_path +  strlen(scheme);
        }

	path = talloc_asprintf(ctx,"\"%s\"", local_path);
        if (path == NULL) {
                hres = HRES_E_OUTOFMEMORY;
		goto done;
        }

        *output = path;
        hres = HRES_OK;
done:
	TALLOC_FREE(frame);
        return hres;
}

static HRESULT get_url_for_entryid(TALLOC_CTX *ctx,
                void *calling_ctx,
                struct wsp_crestriction *restric,
                bool escape,
                const char **output)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct es_query_ctx *data = talloc_get_type_abort(
		calling_ctx, struct es_query_ctx);
        const char *prop_val = NULL;
	const char *urn = NULL;
        HRESULT hres;

        if (restric->ultype != RTPROPERTY) {
                DBG_ERR("conversion failed for restriction type %d\n",
                        restric->ultype);
                hres = HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER);
                goto done;
        }

        prop_val = variant_as_string(frame,
			&restric->restriction.cpropertyrestriction.prval,
			false);
	if (prop_val == NULL) {
		DBG_ERR("No url provided\n");
                hres = HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER);
                goto done;
	}

	urn = es_get_docid_for_entryid(ctx, data, atoi(prop_val));
	if (urn == NULL) {
		DBG_ERR("No url cached for id %d\n", atoi(prop_val));
		/*
		 * to mimic a search in windows (searching for a non
		 * existing EntryID, insert a dummy docid (that won't resolve)
		 * as the translated EntryId
		 */
		urn = talloc_strdup(ctx, "nodocid");
	}
	*output = urn;
	hres = HRES_OK;
done:
	TALLOC_FREE(frame);
        return hres;
}

/*
 * list of names and associated backend value to
 * wsp value functions.
 * For example, when we wish to return the System.ItemURL
 * property we would synthesis that from the elasticsearch
 * file.url property, the conversion would involve
 * converting the system file url into a url matching
 * FILE://NETBIOSNAME/SHARE/xyz where xyz is the relative path
 * from the associated share mount, additionally the relative path
 * will be mangled.
 * The list below is a set of predefined builtin functions for some standard
 * mapping of elasticsearch property to wsp property values
 */

static struct property_conv_data {
	const char *name;
	backend_to_wsp_fn conv_fn;
} backend_to_wsp[] = {
	{"builtin_url_to_winpath", convert_path},
	{"builtin_real_to_winpath", convert_real_path},
	{"builtin_date_to_filetime", convert_filetime},
	{"builtin_real_to_item_folder", convert_real_folderpath},
	{"builtin_real_to_item_folder_narrow", convert_real_folderpath_narrow},
	{"builtin_filename_to_itemtypetext", convert_itemtypetext},
	{"builtin_filename_to_itemtype", convert_itemtype},
	{"builtin_mimetype_to_kind", convert_kind},
	{"builtin_real_to_fileattrs", convert_real_fileattrs},
	{"builtin_generate_rowid", convert_rowid},
	{"builtin_get_entryid_for_url", convert_entryid},
	{"builtin_default_conv", default_conv},
};

static bool find_builtin_elastic_to_wsp_conv(
		TALLOC_CTX *ctx,
		const char *fn_name,
		struct es_detail *prop_detail)
{
	int i;

	if (fn_name == NULL || strlen(fn_name) == 0) {
		return false;
	}

	for (i = 0; i < ARRAY_SIZE(backend_to_wsp); i++) {
		char *tmp_name = NULL;

		if (!strequal(fn_name, backend_to_wsp[i].name)) {
			continue;
		}
		tmp_name = talloc_strdup(ctx, fn_name);
		if (tmp_name == NULL) {
			DBG_ERR("out of memory\n");
			return false;
		}
		prop_detail->elastic_to_wsp_fn_name = tmp_name;
		prop_detail->elastic_to_wsp_fn =
			backend_to_wsp[i].conv_fn;
		prop_detail->elastic_to_wsp_call_ctx = NULL;
		return true;
	}
	return false;
}

/*
 * WSP -> elastic val conversions
 * convert WSP values into elasticsearc/opensearch values
 * these conversion typically happen when building the backend
 * query from the incoming binary restrictions from the client
 */
static struct wsp_to_elasticval {
	const char* wsp_to_es_fn_name;
	wsp_to_backend_val_fn conv_fn;
} wsp_to_elasticval_map[] = {
	{"builtin_kind_to_mimetype", get_es_value_for_kind},
	{"builtin_wspscope_to_unixpath", get_es_value_for_wsppath},
	{"builtin_get_url_for_entryid", get_url_for_entryid}
};

static bool find_builtin_wsp_to_elastic_conv(
		TALLOC_CTX *ctx,
		const char* fn_name,
		struct es_detail *prop_detail)
{
	int i;

	if (fn_name == NULL || strlen(fn_name) == 0) {
		return false;
	}

	for (i = 0; i < ARRAY_SIZE(wsp_to_elasticval_map); i++) {
		char *tmp_name = NULL;

		if (!strequal(fn_name,
			      wsp_to_elasticval_map[i].wsp_to_es_fn_name)) {
			continue;
		}

		tmp_name = talloc_strdup(ctx, fn_name);
		if (tmp_name == NULL) {
			DBG_ERR("out of memory\n");
			return false;
		}
		prop_detail->wsp_to_elastic_fn_name = tmp_name;
		prop_detail->wsp_to_elastic_fn =
			wsp_to_elasticval_map[i].conv_fn;
		return true;
	}
	return false;
}

/* replace existing or add new col conv function */
static bool add_property_conv(struct column_mapper *mapper,
		const char *conv_name,
		backend_to_wsp_fn conv_fn,
		void *calling_ctx)
{
	struct col_conv_list_item *item = NULL;

	for (item = mapper->prop_conv_list; item != NULL; item = item->next) {
		if (strequal(item->col_conv_name, conv_name)) {
			break;
		}
	}
	if (item == NULL) {
		item = talloc_zero(mapper, struct col_conv_list_item);
		if (item == NULL) {
			DBG_ERR("out of memory\n");
			return false;
		}
		DLIST_ADD_END(mapper->prop_conv_list, item);
	}

	item->col_conv_name = conv_name;
	item->conv_fn = conv_fn;
	item->calling_ctx = calling_ctx;

	return true;
}

static void init_builtin_conv_functions(struct elastic_json_mapping *json_cfg)
{
	int i;
	bool found;

	for (i = 0; i < json_cfg->num_props; i++) {
		const char *elastic_to_wsp_conv_fn =
			json_cfg->prop_to_es_map[i].elastic_to_wsp_fn_name;
		const char *wsp_to_convert_fn =
			json_cfg->prop_to_es_map[i].wsp_to_elastic_fn_name;

		if (elastic_to_wsp_conv_fn != NULL) {
			found = find_builtin_elastic_to_wsp_conv(
					json_cfg,
					elastic_to_wsp_conv_fn,
					&json_cfg->prop_to_es_map[i]);
			if (!found) {
				DBG_ERR("## handler for defined "
					"elastic_to_wsp fn %s "
					"not found\n",
					elastic_to_wsp_conv_fn);
			}
		}

		if (wsp_to_convert_fn != NULL) {
			found = find_builtin_wsp_to_elastic_conv(
					json_cfg,
					wsp_to_convert_fn,
					&json_cfg->prop_to_es_map[i]);
			if (!found) {
				DBG_ERR("## handler for defined "
					"wsp_to_elastic fn %s "
					"not found\n",
					wsp_to_convert_fn);
			}
		}
	}
}

static struct column_mapper *init_convert_map_builtin(
				TALLOC_CTX *ctx,
				struct elastic_json_mapping *json_cfg)
{
	struct column_mapper *mapper = NULL;
	int i;

	mapper = talloc_zero(ctx, struct column_mapper);
	if (mapper == NULL) {
		DBG_ERR("out of memory\n");
		return mapper;
	}

	for (i = 0; i < json_cfg->num_props; i++) {
		add_property_conv(mapper,
			json_cfg->prop_to_es_map[i].elastic_to_wsp_fn_name,
			json_cfg->prop_to_es_map[i].elastic_to_wsp_fn,
			json_cfg->prop_to_es_map[i].elastic_to_wsp_call_ctx);
	}

	/* add default conv functions */
	return mapper;
}

void initialise_elastic_conv(void)
{
	register_backend_impl(WSP_BACKEND_ELASTIC,
			es_wsp_conv_ops(),
			NULL);
}

static json_t *get_json_mappings(void)
{
	static json_t *mappings = NULL;
	char *default_path = NULL;
	const char *path = NULL;
	json_error_t json_error;

	if (mappings != NULL) {
		return mappings;
	}

	default_path = talloc_asprintf(
		NULL,
		"%s/wsp/elasticsearch_mappings.json",
		get_dyn_SAMBA_DATADIR());
	if (default_path == NULL) {
		DBG_ERR("Can't determine default path for mappings\n");
		return NULL;
	}

	path = lp_parm_const_string(GLOBAL_SECTION_SNUM,
				    "elasticsearch",
				    "wsp_mappings",
				    default_path);
	mappings = json_load_file(path, 0, &json_error);
	if (mappings == NULL) {
		DBG_ERR("No elasticesearch mapping %s %s, "
			"can't build query\n",
			path ? path : "",
			json_error.text ? json_error.text : "");
	}
	TALLOC_FREE(default_path);

	return mappings;
}

struct es_query_ctx;

static bool parse_attrs(json_t *attr_map,
			struct es_detail *prop_to_es_map)
{
	int attrs;
	const char *key = NULL;
	json_t *value = NULL;
	int i;
	int ret;

	attrs = json_object_size(attr_map);
	DBG_DEBUG("attempting to parse %d attribute/properties\n", attrs);
	i = 0;
	json_object_foreach(attr_map, key, value) {
		char *type = NULL;
		char *elastic_id = NULL;
		char *elastic_to_convert_fn = NULL;
		char *wsp_to_convert_fn = NULL;
		char *tmp_name = NULL;

		ret = json_unpack(attr_map,
				"{s: {s: s}}",
				key,
				"type",
				&type);
		if (ret != 0) {
			break;
		}
		ret = json_unpack(attr_map,
				"{s: {s: s}}",
				key,
				"attribute",
				&elastic_id);
		if (ret != 0) {
			break;
		}
		ret = json_unpack(attr_map,
				"{s: {s: s}}",
				key,
				"elastic_to_wsp",
				&elastic_to_convert_fn);
		if (ret != 0) {
			break;
		}

		ret = json_unpack(attr_map,
				"{s: {s: s}}",
				key,
				"wsp_to_elastic",
				&wsp_to_convert_fn);

		tmp_name = talloc_strdup(prop_to_es_map, key);
		if (tmp_name == NULL) {
			DBG_ERR("Out of memory\n");
			return false;
		}

		prop_to_es_map[i].wsp_id = tmp_name;

		if (strlen(type) != 0) {
			tmp_name = talloc_strdup(prop_to_es_map,
						 type);
			if (tmp_name == NULL) {
				DBG_ERR("Out of memory\n");
				return false;
			}
			prop_to_es_map[i].type = tmp_name;
		}

		if (strlen(elastic_id) != 0) {
			tmp_name = talloc_strdup(prop_to_es_map,
						 elastic_id);
			if (tmp_name == NULL) {
				DBG_ERR("Out of memory\n");
				return false;
			}
			prop_to_es_map[i].elastic_id = tmp_name;
		}

		if (wsp_to_convert_fn) {
			tmp_name = talloc_strdup(prop_to_es_map,
						 wsp_to_convert_fn);
			if (tmp_name == NULL) {
				DBG_ERR("Out of memory\n");
				return false;
			}
			prop_to_es_map[i].wsp_to_elastic_fn_name = tmp_name;
		}

		/*
		 * if a convert function isn't defined then
		 * use a default conversion
		 */
		if (elastic_to_convert_fn == NULL) {
			tmp_name = talloc_strdup(prop_to_es_map,
						 "default_conv");
		} else {
			tmp_name = talloc_strdup(prop_to_es_map,
						 elastic_to_convert_fn);
		}
		if (tmp_name == NULL) {
			DBG_ERR("Out of memory\n");
			return false;
		}

		prop_to_es_map[i].elastic_to_wsp_fn_name = tmp_name;

		ret = 0;
		i++;
	}
	if (ret !=0) {
		return false;
	}
	return true;
}

static struct elastic_json_mapping *read_json_mapping(void)
{
	struct es_detail *prop_to_es_map = NULL;
	static struct elastic_json_mapping *json_cfg = NULL;
	json_t *mappings = NULL;
	json_t *attr_map = NULL;
	int attrs;
	bool ok;

	if (json_cfg != NULL) {
		return json_cfg;
	}

	json_cfg = talloc_zero(NULL, struct elastic_json_mapping);
	if (json_cfg == NULL) {
		return NULL;
	}

	mappings = get_json_mappings();

	attr_map = json_object_get(mappings, "attribute_mappings");
	if (attr_map == NULL) {
		DBG_ERR("Failed to read attribute mappings\n");
		TALLOC_FREE(json_cfg);
		return NULL;
	}

	json_cfg->kind_map = json_object_get(mappings, "kind_mappings");
	if (json_cfg->kind_map == NULL) {
		DBG_ERR("Failed to read kind mappings\n");
		TALLOC_FREE(json_cfg);
		return NULL;
	}

	attrs = json_object_size(attr_map);

	if (prop_to_es_map == NULL) {
		prop_to_es_map = talloc_zero_array(json_cfg,
				struct es_detail,
				attrs);
		if (prop_to_es_map == NULL) {
			DBG_ERR("out of memory\n");
			TALLOC_FREE(json_cfg);
			return NULL;
		}

		ok = parse_attrs(attr_map, prop_to_es_map);
		if (!ok) {
			TALLOC_FREE(json_cfg);
			return NULL;
		}
	}
	json_cfg->prop_to_es_map = prop_to_es_map;
	json_cfg->num_props = attrs;
	json_cfg->es_conv_ops = es_wsp_conv_ops();
	init_builtin_conv_functions(json_cfg);
	return json_cfg;
}

struct es_query_ctx *create_wsp_to_es_data(TALLOC_CTX *ctx)
{
	struct es_query_ctx *data = NULL;

	data = talloc_zero(ctx, struct es_query_ctx);
	if (data == NULL) {
		return NULL;
	}

	data->json_config = read_json_mapping();
	if (data->json_config == NULL) {
		TALLOC_FREE(data);
		return NULL;
	}
	return data;
}

/*
 * populate 'mapper'
 * 'mapper' contains the information to map results from
 * elasticsearch to the wsp columns requested as part of the
 * WSP query request
 * + columns are the columns requested by the query,
 * + backend_cols are the actual backend (elastic) columns or properties
 *   that are requested to be returned. Note: the number of
 *   backend_cols is almost certainly less than the number of 'WSP' columns
 *   requested in 'columns' due to the fact many properties won't exist in the
 *   backend so they will either be NULL or will need to be synthesized from
 *   an existing property. Also Note: backend_cols are unique, that is if
 *   a certain backend column is needed to synthesize more than one WSP column
 *   then we request the backend column once (so it will only appear
 *   once in the backend_cols array
 * This method calculates and returns mapper (the results mapping information)
 *   mapper contains the information needed to convert backend columns to
 *   WSP columns, each entry in mapper represents one of the requested
 *   WSP columns and contains the index into the backend columns to
 *   be returned from the backend that contains the value
 *   that will be used to convert or synthesize the WSP column value to be
 *   returned. It also will contain the conversion function if required
 *   that will be used to convert/synthesize the value.
 */
static bool build_mapper_impl(TALLOC_CTX *ctx,
		struct elastic_json_mapping *json_cfg,
		struct wsp_ctablecolumn *columns,
		uint32_t ncols,
		struct backend_selected_cols *backend_cols,
		struct binding_result_mapper *mapper)
{
	struct column_mapper *col_conversions = NULL;
	struct prop_data *prop_data = NULL;
	int i, j;

	col_conversions = init_convert_map_builtin(ctx, json_cfg);
	if (col_conversions == NULL) {
		DBG_ERR("Failed to initialise default conversions\n");
		return false;
	}

	prop_data = talloc_zero(ctx, struct prop_data);
	if (prop_data == NULL) {
		return false;
	}

	prop_data->num = json_cfg->num_props;
	prop_data->detail = talloc_zero_array(prop_data,
				struct prop_detail,
				prop_data->num);
	if (prop_data == NULL) {
		return false;
	}
	for (i = 0; i < prop_data->num; i++) {
		prop_data->detail[i].wsp_prop =
			json_cfg->prop_to_es_map[i].wsp_id;
		prop_data->detail[i].backend_prop =
			json_cfg->prop_to_es_map[i].elastic_id;
		prop_data->detail[i].conv_fn =
			json_cfg->prop_to_es_map[i].elastic_to_wsp_fn_name;
	}

	mapper->map_data = talloc_zero_array(mapper, struct map_data, ncols);
	if (mapper->map_data == NULL) {
		DBG_ERR("Out of memory\n");
		return false;
	}
	mapper->ncols = ncols;

	/*
	 * walk through the bindings and find if any returned backend cols
	 * match
	 *
	 */

	for (i = 0; i < ncols; i++) {
		struct map_data *md = &mapper->map_data[i];
		const char *wsp_id = prop_from_fullprop(
			ctx, &columns[i].propspec);
		const struct full_propset_info *prop_info =
			get_prop_info(wsp_id);
		const char *backend_prop = get_backend_prop_name(
			wsp_id, prop_data);
		const char *convert_fn = get_backend_conv_fn_name(
			wsp_id, prop_data);

		md->vtype = VT_NULL;
		if (backend_prop == NULL) {
			continue;
		}
		if (convert_fn == NULL) {
			continue;
		}

		for (j = 0; j < backend_cols->cols; j++) {
			const char *id = backend_cols->backend_ids[j];

			if (!strequal(backend_prop, id)) {
				continue;
			}
			md->col_with_value = j;
			md->convert_fn = get_property_conv(
				col_conversions, convert_fn);
			md->calling_ctx = get_property_calling_ctx(
				col_conversions, convert_fn);
			/* store the wsp prop type here */
			md->vtype = prop_info->vtype;

			DBG_DEBUG("mapped [%d] '%s' to returned col %d '%s'\n",
				  i, wsp_id, j, backend_cols->backend_ids[j]);
			break;
		}
	}
	return true;
}

static bool build_es_mapper(TALLOC_CTX *ctx,
		struct wsp_ctablecolumn *columns,
		uint32_t ncols,
		struct backend_selected_cols *selected_cols,
		struct binding_result_mapper *mapper)
{
	/* map of name => wsp_to_backend conversion functions */
	struct elastic_json_mapping *json_cfg = NULL;

	json_cfg = read_json_mapping();
	if (json_cfg == NULL) {
		DBG_ERR("Failed to create needed setup info for conversions\n");
		return false;
	}

	return build_mapper_impl(ctx,
		json_cfg,
		columns,
		ncols,
		selected_cols,
		mapper);
}

static bool dummy_lookup_whereid(TALLOC_CTX *ctx,
		struct wspd_client_state *state,
                uint32_t where_id,
                const char **filter_out,
                const char **share_out)
{
	return false;
}

static const char *es_get_docid_for_entryid(TALLOC_CTX *ctx,
					    void *data,
					    uint32_t entryid)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct es_query_ctx *esdata = talloc_get_type_abort(
		data, struct es_query_ctx);
	const char *result = NULL;
	char *service = NULL;
	char *index_name = NULL;
	int snum;

	if (esdata->id_cache == NULL) {
		DBG_ERR("no id cache\n");
		goto out;
	}

	snum = find_service(frame,
			    esdata->share_scope,
			    &service);
	if (snum == -1 || service == NULL) {
		DBG_ERR("failed to get service num for share %s\n",
			esdata->share_scope);
		goto out;
	}
	index_name = lp_parm_substituted_string(ctx,
						loadparm_s3_global_substitution(),
						snum,
						"elasticsearch",
						"index",
						"_all");
	result = get_path_for_id(esdata->id_cache,
				 index_name,
				 entryid);
out:
	TALLOC_FREE(frame);
	return result;
}

static struct es_detail *get_es_detail(const char* wsp_id,
			struct elastic_json_mapping *json_cfg)
{
	int i;

	for (i = 0; i < json_cfg->num_props; i++) {
		if (strequal(json_cfg->prop_to_es_map[i].wsp_id, wsp_id)) {
			return &json_cfg->prop_to_es_map[i];
		}
	}
	return NULL;
}

static bool has_col(struct backend_selected_cols *cols,
		const char* id)
{
	int i;

	for (i = 0; i < cols->cols; i++) {
		if (strequal(cols->backend_ids[i], id)) {
			return true;
		}
	}
	return false;
}

/*
 * we populate es_selected_cols->backend_ids with the elasticsearch
 * columns that can be used to convert to or synthesize the WSP
 * columns actually requested by the query
 * es_selected_cols->backend_ids should have unique entries, e.g.
 * if a particular elasticsearch column can be used to generate
 * (e.g. convert or synthesize) multiple requested WSP (wsp_select_cols)
 * the elasticsearch column should only appear once. The mapper
 * created separately from conv_ops->bld_mapper will take care of
 * mapping to the different WSP columns from an elasticsearch column
 */
static HRESULT populate_backend_selected_cols(
		TALLOC_CTX *ctx,
		struct wsp_ccolumnset *wsp_select_cols,
		struct wsp_cpidmapper *pidmapper,
		struct es_query_ctx *data,
		struct backend_selected_cols *es_selected_cols)
{
	int i;

	es_selected_cols->backend_ids = talloc_zero_array(
			ctx,
			const char *,
			wsp_select_cols->count);
	if (es_selected_cols->backend_ids == NULL) {
		DBG_ERR("out of mem\n");
		return HRES_E_OUTOFMEMORY;
	}

	for (i = 0; i < wsp_select_cols->count; i++) {
		int pid_index = wsp_select_cols->indexes[i];
		struct wsp_cfullpropspec *prop_spec =
				&pidmapper->apropspec[pid_index];
		char *prop = prop_from_fullprop(ctx, prop_spec);
		struct es_detail *detail = get_es_detail(
			prop, data->json_config);
		char *new_str = NULL;

		/*
		 * we can have duplicates here but we should
		 * ensure unique retrieved props
		 */

		if (detail == NULL || detail->elastic_id == 0) {
			continue;
		}
		if (has_col(es_selected_cols, detail->elastic_id)) {
			continue;
		}

		new_str = talloc_strdup(ctx, detail->elastic_id);
		if (new_str == NULL) {
			DBG_ERR("out of mem\n");
			TALLOC_FREE(es_selected_cols->backend_ids);
			return HRES_E_OUTOFMEMORY;
		}
		es_selected_cols->backend_ids[es_selected_cols->cols] =
			new_str;
		es_selected_cols->cols++;
	}
	es_selected_cols->backend_ids = talloc_realloc(
		ctx,
		es_selected_cols->backend_ids,
		const char *,
		es_selected_cols->cols);
	if (es_selected_cols->backend_ids == NULL) {
		DBG_ERR("out of mem\n");
		return HRES_E_OUTOFMEMORY;
	}
	return HRES_OK;
}

static bool extract_expression_sides(struct wsp_crestriction *restriction,
			struct wsp_crestriction **left,
			struct wsp_crestriction **right)
{
	struct wsp_cnoderestriction *cnodes = NULL;

	if (!is_operator(restriction)) {
		return false;
	}
	if (restriction->ultype == RTNOT) {
		/* NOT only has lhs */
		*left = restriction->restriction.restriction.restriction;
		return true;
	}
	cnodes = &restriction->restriction.cnoderestriction;
	if  (cnodes->cnode == 0) {
		/* invalid binary tree */
		DBG_ERR("Invalid binary expression tree\n");
		return false;
	}
	*left = &cnodes->panode[0];
	if (cnodes->cnode > 1) {
		*right = &cnodes->panode[1];
	}
	return true;
}

static bool is_empty(json_t *jobject)
{
	json_t *jbool = json_object_get(jobject, "bool");
	bool result;

	if (json_object_get(jbool, "must")) {
		if (json_array_size(json_object_get(jbool, "must")) == 0) {
			result =  true;
			goto out;
		}
	} else if (json_object_get(jbool, "should")) {
		if (json_array_size(json_object_get(jbool, "should")) == 0) {
			result =  true;
			goto out;
		}
	} else if (json_object_get(jbool, "should not")) {
		if (json_array_size(json_object_get(jbool, "should not")) == 0) {
			result =  true;
			goto out;
		}
	}
	result =  false;
out:
	return result;
}

static const char *op_as_es_string(struct wsp_crestriction *restriction)
{
	const char *op = NULL;

	if (is_operator(restriction)) {
		switch(restriction->ultype) {
			case RTAND:
				op = " AND ";
				break;
			case RTOR:
				op = " OR ";
				break;
			case RTNOT:
				op = " NOT ";
				break;
		}
	} else if (restriction->ultype == RTPROPERTY) {
		struct wsp_cpropertyrestriction *prop_restr =
			&restriction->restriction.cpropertyrestriction;

		switch (prop_restr->relop & 0XF) {
			case PREQ:
				op = "%s:(%s)";
				break;
			case PRNE:
				op = "%s:(NOT %s)";
				break;
			case PRGE:
				op = "%s:>=%s";
				break;
			case PRLE:
				op = "%s<=%s";
				break;
			case PRLT:
				op = "%s:<%s";
				break;
			case PRGT:
				op = "%s>%s";
				break;
			default:
				break;
		}
	}
	return op;
}

static bool op_as_es_bool_string(struct wsp_crestriction *restriction,
		json_t **jquery)
{
	json_t *op_val = json_object();

	if (is_operator(restriction)) {
		switch (restriction->ultype) {
			case RTAND:
				json_object_set_new(op_val,
						    "must",
						    json_array());
				break;
			case RTOR:
				json_object_set_new(op_val,
						    "should",
						    json_array());
				break;
			case RTNOT:
				json_object_set_new(op_val,
						    "should not",
						    json_array());
				break;
		}
	}
	*jquery = op_val;
	return true;
}

static HRESULT rtproperty_to_es_query(TALLOC_CTX *ctx,
				struct wsp_crestriction *restriction,
				void *priv_data,
				json_t **pjquery)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct wsp_cfullpropspec *prop_spec = get_full_prop(restriction);
	const char *prop = prop_from_fullprop(ctx, prop_spec);
	struct es_detail *detail = NULL;
	const char *escaped_attr = NULL;
	struct es_query_ctx *data = talloc_get_type_abort(
		priv_data, struct es_query_ctx);
	const char *value = NULL;
	const char *esval = NULL;
	const char *format = NULL;
	const char *query_value = NULL;
	bool use_fscrawler_folder_idx = false;
	int snum;
	char *service = NULL;
	json_t *jquery = NULL;
	HRESULT hres;

	format = op_as_es_string(restriction);
	if (format == NULL) {
		hres = HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER);
		goto out;
	}

	detail = get_es_detail(prop, data->json_config);
	if (detail == NULL) {
		DBG_WARNING("can't handle wsp property %s\n", prop);
		hres = HRES_OK;
		goto out;
	}

	if (strequal("Scope", prop) &&
	    restriction->ultype == RTPROPERTY)
	{
		const char *path = variant_as_string(frame,
			&restriction->restriction.cpropertyrestriction.prval,
			false);

		if (data->share_scope == NULL) {
			hres = get_share(data,
					 path,
					 &data->share_scope);
			if (!HRES_IS_OK(hres)) {
				goto out;
			}
		}
	}

	/* do we have a defined conversion for wsp value? */
	if (detail->wsp_to_elastic_fn) {
		hres = detail->wsp_to_elastic_fn(frame,
					data,
					restriction,
					true,
					&value);
		if (!HRES_IS_OK(hres)) {
			goto out;
		}
		esval = value;
	} else {
		/* use raw wsp value as string */
		struct wsp_cpropertyrestriction *cprop =
			&restriction->restriction.cpropertyrestriction;

		value = variant_as_string(frame, &cprop->prval, true);
		if (value == NULL || strlen(value) == 0) {
			hres = HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER);
			goto out;
		}
		esval = es_escape_str(ctx, value, NULL, "*\\\"");
	}
	if (esval == NULL) {
		hres = HRES_E_OUTOFMEMORY;
		goto out;
	}

	escaped_attr = es_escape_str(ctx, detail->elastic_id, NULL, NULL);
	if (escaped_attr == NULL) {
		escaped_attr = "";
	}

	/*
	 * we could split out generated elastic json based
	 * on e.g. PREQ could be term (or match)
	 * or.. PRRE could be a regrexp query
	 * However.... for these simple RTProperty restrictions
	 * query_string seems to tick all the boxes (and handle everything
	 * we need)
	 */

	query_value = talloc_asprintf(frame, format, escaped_attr, esval);
	if (query_value == NULL) {
		hres = HRES_E_OUTOFMEMORY;
		goto out;
	}

	if (data->share_scope) {
		snum = find_service(frame,
				    data->share_scope,
				    &service);
		if (snum == -1 || service == NULL) {
			DBG_ERR("failed to get service num for "
				"share %s\n",
				data->share_scope);
			hres = HRES_E_OUTOFMEMORY;
			goto out;
		}
		TALLOC_FREE(service);

		use_fscrawler_folder_idx = lp_parm_bool(
					snum,
					"elasticsearch",
					"wsp use fscrawler folders",
					false);
	}

	if (strequal("Scope", prop) && use_fscrawler_folder_idx) {
		query_value = talloc_asprintf(query_value,
					      "%s OR path.real:(%s)",
					      query_value,
					      esval);
	}

	jquery = json_pack("{s:{s:s}}",
			   "query_string", "query", query_value);
	if (jquery == NULL) {
		hres = HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER);
		goto out;
	}
	*pjquery = jquery;
	hres = HRES_OK;
out:
	TALLOC_FREE(frame);
	return hres;
}

static HRESULT rtcontent_to_string(TALLOC_CTX *ctx,
				    struct wsp_crestriction *restriction,
				    void *priv_data,
				    json_t **p_jquery)
{
	TALLOC_CTX *frame = talloc_stackframe();
	HRESULT hres;
	struct wsp_cfullpropspec *prop_spec = get_full_prop(restriction);
	const char *prop = prop_from_fullprop(ctx, prop_spec);
	struct es_detail *detail = NULL;
	const char *escaped_attr = NULL;
	struct wsp_ccontentrestriction *ccont = NULL;
	struct es_query_ctx *data = talloc_get_type_abort(
		priv_data, struct es_query_ctx);
	char *esval = NULL;
	const char *match = NULL;
	json_t *jresult = NULL;
	bool all = false;

	if (restriction->ultype != RTCONTENT) {
		hres = HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER);
		goto out;
	}

	if (strequal("All", prop)) {
		all = true;
	}

	ccont =	&restriction->restriction.ccontentrestriction;

	detail = get_es_detail(prop, data->json_config);
	if (detail == NULL) {
		DBG_WARNING("can't handle wsp property %s\n", prop);
		/* don't flag an error, allow further queries to be built */
		hres = HRES_OK;
		goto out;
	}


	escaped_attr = es_escape_str(frame, detail->elastic_id, NULL, NULL);
	if (escaped_attr == NULL) {
		escaped_attr = "";
	}

	esval = es_escape_str(frame, ccont->pwcsphrase, NULL, "*\\\"");

	hres = HRES_OK;
	switch (ccont->ulgeneratemethod) {
		case 0: /*exact*/
			match = "phrase";
			break;
		case 1: /*prefix*/
			match = "phrase_prefix";
			break;
		/*
		 * match inflections = ordinary match ?
		 */
		case 2:
			match =	"phrase";
			break;
		default:
			hres = HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER);
	}
	if (!HRES_IS_OK(hres)) {
		goto out;
	}

	if (all) {
		jresult = json_pack("{s:{s:[ss]ssss}}",
			    "query_string",
			    "fields",
			    escaped_attr,
			    "path.real.fulltext",
			    "type",
			    match,
			    "query",
			    esval);
	} else {
		jresult = json_pack("{s:{s:[s]ssss}}",
			    "query_string",
			    "fields",
			    escaped_attr,
			    "type",
			    match,
			    "query",
			    esval);
	}
	if (jresult == NULL) {
		hres = HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER);
		goto out;
	}
	*p_jquery = jresult;
out:
	TALLOC_FREE(frame);
	return hres;
}

static HRESULT rtnatlang_to_string(TALLOC_CTX *ctx,
				struct wsp_crestriction *restriction,
				void *priv_data,
				json_t **p_jquery)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct wsp_cfullpropspec *prop_spec = get_full_prop(restriction);
	const char *prop = NULL;
	struct wsp_cnatlanguagerestriction *cnat = NULL;
	struct es_query_ctx *data = talloc_get_type_abort(
		priv_data, struct es_query_ctx);
	const char *es_attr = NULL;
	const char *value = NULL;
	struct es_detail *detail = NULL;
	json_t *jresult = json_object();
	HRESULT hres;

	if (restriction->ultype != RTNATLANGUAGE) {
		DBG_ERR("Unexpected restriction type 0x%d\n",
			restriction->ultype);
		hres = HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER);
		goto done;
	}

	prop = prop_from_fullprop(frame, prop_spec);
	if (prop == NULL) {
		hres = HRES_E_OUTOFMEMORY;
		goto done;
	}

	detail = get_es_detail(prop, data->json_config);
	if (detail == NULL) {
		DBG_WARNING("can't handle wsp property %s\n", prop);
		/* don't flag an error, allow further queries to be built */
		hres = HRES_OK;
		goto done;
	}

	cnat = &restriction->restriction.cnatlanguagerestriction;
	es_attr = es_escape_str(frame, detail->elastic_id, NULL, NULL);
	value = es_escape_str(frame, cnat->pwcsphrase, NULL, "*\\\"");
	if (es_attr == NULL || value == NULL) {
		hres = HRES_E_OUTOFMEMORY;
		goto done;
	}

	jresult = json_pack("{s:{s:[s]ssss}}",
			    "query_string",
			    "fields",
			    es_attr,
			    "type",
			    "phrase",
			    "query",
			    value);
	*p_jquery = jresult;
	hres = HRES_OK;
done:
	TALLOC_FREE(frame);
	return hres;
}

static HRESULT rtreusewhere_to_string(TALLOC_CTX *ctx,
		struct wsp_crestriction *restriction,
		void *priv_data,
		json_t **p_jwhere)
{
	TALLOC_CTX *frame = talloc_stackframe();
	bool ok;
	const char *where_filter = NULL;
	const char *share_scope = NULL;
	const char *result = NULL;
	int where_id = restriction->restriction.reusewhere.whereid;
	struct es_query_ctx *data = talloc_get_type_abort(
		priv_data, struct es_query_ctx);
	json_t *jwhere = NULL;
	json_error_t jerr = {};
	HRESULT hres;

	DBG_DEBUG("SHARE reusewhereid %d\n", where_id);

	/*
	* Try get a previously built whereid string,
	* It's quite possible that a whereid points to a
	* restrictions set associated with a whereid that no
	* longer exists (e.g. the associated query has been
	* released). That's why we don't search for the
	* restriction array, instead we expect the
	* restriction string to be stored.
	* Note: the documentation is ambiguous about this,
	* it states the whereid refers to an open queries
	* restriction set, that's true but it fails to point
	* out that the restriction set (of the open query)
	* itself could have been built using a whereid that
	* is now 'released' thus we won't find the associated
	* restriction set of that 'nested' whereid
	*/
	ok = data->json_config->es_conv_ops->bld_lookup_whereid(
						frame,
						data->client_state,
						where_id,
						&where_filter,
						&share_scope);
	if (ok &&
	    strlen(where_filter) != 0 &&
	    strlen(share_scope) != 0)
	{
		result = where_filter;
		/*
		 * share_scope is owned by frame, but data->share_scope is
		 * read after this returns: later restriction nodes use it
		 * for find_service(), and build_es_query() hands it to the
		 * caller. Take a copy owned by data.
		 */
		data->share_scope = talloc_strdup(data, share_scope);
		if (data->share_scope == NULL) {
			hres = HRES_E_OUTOFMEMORY;
			goto out;
		}

		DBG_NOTICE("detected a where id RTREUSEWHERE id=%d"
			   " result = %s, share = %s\n",
			   where_id, where_filter, share_scope);
		jwhere = json_loads(result, 0, &jerr);
		if (jwhere == NULL) {
			DBG_ERR("can't create json object from "
				"where_filter %s\n error: %s\n",
				result, jerr.text);
			hres = HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER);
			goto out;
		}
	} else {
		jwhere = json_object();
		/*
		* this assumes the reason we have
		* no whereid string is because there is no
		* index, it's a pretty valid assumption
		* but I think getting the status from
		* maybe lockup_where_id() might be better
		*/
		DBG_ERR("no whereid => this share is not indexed\n");
		json_object_set_new(jwhere, "WHEREID", json_integer(where_id));
		*p_jwhere = jwhere;
		/*
		 * if glob_data == NULL then we are more than likely being
		 * called from wsp_to and we don't want to propagate the
		 * status for this case
		 */
		if (data->client_state != NULL) {
			hres = HRES_ERROR(WIN_UPDATE_ERR);
			goto out;
		}
	}
	*p_jwhere = jwhere;
	hres = HRES_OK;
out:
	TALLOC_FREE(frame);
	return hres;
}

typedef HRESULT (*restriction_callback)(TALLOC_CTX *ctx,
				struct wsp_crestriction *restriction,
				void *priv_data,
				json_t **jquery);

static HRESULT prefix_elastic_bool(TALLOC_CTX *ctx,
			restriction_callback restriction_cb,
			struct wsp_crestriction *restriction,
			void *priv_data,
			json_t **jquery);

static HRESULT restriction_elastic_bool_cb(TALLOC_CTX *ctx,
				  struct wsp_crestriction *restriction,
				  void *priv_data,
				  json_t **jquery)
{
	json_t *jres = NULL;
	HRESULT hres = HRES_OK;

	if (is_operator(restriction)) {
		op_as_es_bool_string(restriction,&jres);
	} else {
		switch(restriction->ultype) {
			case RTPROPERTY: {
				return rtproperty_to_es_query(ctx,
							   restriction,
							   priv_data,
							   jquery);
				break;
			}
			case RTCONTENT: {
				hres = rtcontent_to_string(ctx,
							   restriction,
							   priv_data,
							   &jres);
				break;
			}
			case RTNATLANGUAGE: {
				hres = rtnatlang_to_string(ctx,
							restriction,
							priv_data,
							&jres);
				break;
			}
			case RTCOERCE_ABSOLUTE: {
				struct wsp_crestriction *child_restrict =
                                        restriction->restriction.ccoercionrestriction_abs.childres;

				hres = prefix_elastic_bool(ctx,
						restriction_elastic_bool_cb,
						child_restrict,
						priv_data,
						&jres);
				break;
			}
			case RTREUSEWHERE:
				hres = rtreusewhere_to_string(ctx,
							restriction,
							priv_data,
							&jres);
				break;
			default:
				DBG_INFO("Ignored restriction with type %d\n",
				restriction->ultype);
			break;
		}
	}
	*jquery = jres;
	return hres;
}

static HRESULT find_share_restrictions_cb(TALLOC_CTX *ctx,
				  struct wsp_crestriction *restriction,
				  void *priv_data)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct es_query_ctx *data = talloc_get_type_abort(
		priv_data, struct es_query_ctx);
	HRESULT hres;

	if (is_operator(restriction)) {
		hres = HRES_OK;
		goto out;
	}

	if (restriction->ultype == RTPROPERTY) {
		struct wsp_cfullpropspec *prop_spec = get_full_prop(restriction);
		const char *prop = NULL;
		const char *path = NULL;
		struct wsp_cpropertyrestriction *pres = NULL;

		prop = prop_from_fullprop(frame, prop_spec);
		if (!strequal("Scope", prop)) {
			hres = HRES_OK;
			goto out;
		}

		pres = &restriction->restriction.cpropertyrestriction;
		path = variant_as_string(frame, &pres->prval, false);
		hres = get_share(data, path, &data->share_scope);
		if (!HRES_IS_OK(hres)) {
			DBG_ERR("share NOT populated by Scope!!! %s\n",
				hresult_errstr(hres));
		}
		goto out;
	} else if (restriction->ultype == RTREUSEWHERE) {
		int32_t where_id = restriction->restriction.reusewhere.whereid;
		const char *where_filter = NULL;
		bool ok;

		ok = data->json_config->es_conv_ops->bld_lookup_whereid(
						frame,
						data->client_state,
						where_id,
						&where_filter,
						&data->share_scope);
		if (!ok) {
			DBG_ERR("failed to populate share from whereid %d!!\n",
				where_id);
			hres = HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER);
			goto out;
		}
		data->share_scope = talloc_move(data, &data->share_scope);
	}
	hres = HRES_OK;
out:
	TALLOC_FREE(frame);
	return hres;
}

static HRESULT find_share_from_restrictions(TALLOC_CTX *ctx,
				    struct wsp_crestriction *restriction,
				    void *priv_data)
{
	struct wsp_crestriction *left = NULL;
	struct wsp_crestriction *right = NULL;
	HRESULT hres;

	if (restriction == NULL) {
		return HRES_OK;
	}

	if (is_operator(restriction)) {
		if (!extract_expression_sides(restriction,
					      &left,
					      &right)) {
			return HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER);
		}
	}
	/* print */
	hres = find_share_restrictions_cb(ctx,
					  restriction,
					  priv_data);
	if (!HRES_IS_OK(hres)) {
		return hres;
	}

	/* infix (left subtree) */
	if (left != NULL) {
		hres = find_share_from_restrictions(ctx,
						    left,
						    priv_data);
		if (!HRES_IS_OK(hres)) {
			return hres;
		}
	}

	/* infix (right subtree) */
	if (right != NULL) {
		hres = find_share_from_restrictions(ctx,
						    right,
						    priv_data);
		if (!HRES_IS_OK(hres)) {
			return hres;
		}
	}
	return hres;
}

static HRESULT prefix_elastic_bool(TALLOC_CTX *ctx,
				    restriction_callback restriction_cb,
				    struct wsp_crestriction *restriction,
				    void *priv_data,
				    json_t **jquery)
{
	struct wsp_crestriction *left = NULL;
	struct wsp_crestriction *right = NULL;
	HRESULT hres = HRES_OK;
	json_t *jtoken = NULL;
	json_t *jleft = NULL;
	json_t *jright = NULL;
	json_t *jbool = NULL;
	json_t *jop = NULL;

	if (restriction == NULL) {
		return HRES_OK;
	}

	if (is_operator(restriction)) {
		if (!extract_expression_sides(restriction,
					      &left,
					      &right)) {
			return HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER);
		}
	}
	/* print */
	hres = restriction_cb(ctx,
				restriction,
				priv_data,
				&jtoken);
	if (!HRES_IS_OK(hres)) {
		return hres;
	}

	/* infix (left subtree) */
	if (left != NULL) {
		hres = prefix_elastic_bool(ctx,
					     restriction_cb,
					     left,
					     priv_data,
					     &jleft);
		if (!HRES_IS_OK(hres)) {
			return hres;
		}
	}

	/* infix (right subtree) */
	if (right != NULL) {
		hres = prefix_elastic_bool(ctx,
					     restriction_cb,
					     right,
					     priv_data,
					     &jright);
		if (!HRES_IS_OK(hres)) {
			return hres;
		}
	}

	/*
	 * form the query and additionally drop any unhandled parts of
	 * expression
	 */
	if (!is_operator(restriction)) {
		*jquery = jtoken;
		return HRES_OK;
	}

	jop = json_object_get(jtoken, "must");
	if (jop == NULL) {
		jop = json_object_get(jtoken, "should");
	}
	if (jop == NULL) {
		jop = json_object_get(jtoken, "should not");
	}
	if (jop == NULL) {
		DBG_ERR("couldn't find operator\n");
		if (jleft != NULL) {
			json_decref(jleft);
		}
		if (jright != NULL) {
			json_decref(jright);
		}
		if (jtoken != NULL) {
			json_decref(jtoken);
		}
		return HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER);
	}

	jbool = json_object();
	/*
	 * an operator expands out like
	 * { "bool" : {
	 *      "must" :
	 *      [
	 *        {converted restriction[1]}
	 *        ,
	 *        {converted restriction[N]}
	 *      ]
	 *    }
	 * }
	 */
	if (jleft == NULL && jright == NULL) {
		json_object_set_new(jbool, "bool", jtoken);
		*jquery = jbool;
		return HRES_OK;
	}

	if (jleft != NULL) {
		if (!is_empty(jleft)) {
			json_array_append_new(jop, jleft);
		} else {
			json_decref(jleft);
		}
	}
	if (jright != NULL) {
		if (!is_empty(jright)) {
			json_array_append_new(jop, jright);
		} else {
			json_decref(jright);
		}
	}
	json_object_set_new(jbool, "bool", jtoken);
	*jquery = jbool;
	return HRES_OK;
}

static HRESULT get_sort_details(TALLOC_CTX *ctx,
				 struct es_query_ctx *data,
				 struct wsp_cpidmapper *pidmapper,
				 struct wsp_csortset *sorting,
				 json_t *jsort)
{
	uint32_t i;
	uint32_t sort_index= 0;
	const char ** sort_by = NULL;
	struct wsp_csort *order = NULL;

	if (pidmapper == NULL || sorting == NULL) {
		return HRES_OK;
	}
	if (sorting->count == 0) {
		DBG_DEBUG("function called with a sorting->count of "
			  "zero, no sorting set");
		return HRES_OK;
	}

	sort_by = talloc_zero_array(ctx, const char *, sorting->count);
	if (sort_by == NULL) {
		return HRES_E_OUTOFMEMORY;
	}

	order = sorting->sortarray;
	for (i = 0; i < sorting->count; i++) {
		uint32_t pid_index = order[i].pidcolumn;
		struct wsp_cfullpropspec *prop_spec =
			&pidmapper->apropspec[pid_index];
		char *prop = prop_from_fullprop(ctx, prop_spec);
		struct es_detail *detail = get_es_detail(
			prop, data->json_config);
		const char *elastic_id = detail ? detail->elastic_id : NULL;

		/* search for a match to the sort term */
		if (elastic_id != NULL) {
			uint32_t j;
			json_t *j_prop = NULL;

			if (order[i].dworder != QUERY_SORTASCEND &&
				order[i].dworder != QUERY_DESCEND) {
				DBG_ERR("Unknown sort order %d\n",
					order[i].dworder);
				return HRESULT_FROM_NT(
						NT_STATUS_INVALID_PARAMETER);
			}
			if (order[i].dworder == QUERY_SORTASCEND) {
				j_prop = json_pack("{s:s}",
						elastic_id,
						"asc");
			} else {
				j_prop = json_pack("{s:s}",
						   elastic_id,
						   "desc");
			}
			/* don't try and order by the same col again */
			if (sort_index != 0) {
				for (j = 0; j < sort_index; j++) {
					if (strequal(elastic_id,
						     sort_by[j])) {
						DBG_INFO(
							"Already "
							"sorting by "
							"%s\n",
							elastic_id);
						break;
					} else {
						sort_by[sort_index++] =
							elastic_id;
						json_array_append(
							jsort,
							j_prop);
					}
				}
			} else {
				sort_by[sort_index++] =
                                               elastic_id;
				json_array_append(jsort, j_prop);
			}
			json_decref(j_prop);
		}
	}
	TALLOC_FREE(sort_by);
	return HRES_OK;
}

static HRESULT build_es_query(TALLOC_CTX *ctx,
			struct wspd_client_state *client_state,
			struct wsp_ccolumnset *select_cols,
			struct wsp_crestrictionarray *restrictarray,
			struct wsp_cpidmapper *pidmapper,
			struct wsp_csortset *sorting,
			struct backend_selected_cols *selected_cols,
			bool convert_props,
			const char **share_scope,
			const char **query_str,
			const char **where_id_str)
{
	const char * query = NULL;
	const char * where = NULL;
	HRESULT hres;
	struct es_query_ctx *data = NULL;

	if (convert_props == false) {
		/*
		 * convert_props is only relevant for wsp-to where
		 * there is an option (if the backend supports it) to
		 * output a 'raw' representation of the restriction set.
		 * currently this isn't supported for the elasticsearch
		 * backend.
		 */
		DBG_ERR("Bad option, properties always need to be converted\n");
		return HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER);
	}
	data = create_wsp_to_es_data(ctx);
	if (data == NULL) {
		DBG_ERR("out of memory\n");
		return HRES_E_OUTOFMEMORY;
	}

	data->client_state = client_state;
	if (data->client_state) {
		data->id_cache = data->client_state->id_cache;
	}

	hres = populate_backend_selected_cols(ctx,
			select_cols,
			pidmapper,
			data,
			selected_cols);
	if (!HRES_IS_OK(hres)) {
		return hres;
	}
	if (restrictarray->count != 0) {
		char *temp = NULL;
		json_t *jquery = json_object();
		json_t *jsort = json_array();
		json_t *jval = NULL;

		hres = get_sort_details(ctx, data, pidmapper, sorting, jsort);
		if (!HRES_IS_OK(hres)) {
			return hres;
		}

		/*
		 * some queries can involve property restrictions with EntryId
		 * and a Scope retriction, The EntryId requires the share
		 * information determined from the Scope restriction but the
		 * EntryId restriction can be encountered before the the Scope
		 * one, the following call parses the restriction array but
		 * will process all restrictions ignoring errors (like the fact
		 * that the EntryId restriction cannot by resolved)
		 * This should ensure the share info (if required) is setup
		 * for the second pass at creating the query
		 */
		find_share_from_restrictions(ctx,
				&restrictarray->restrictions[0],
				data);

		hres = prefix_elastic_bool(ctx,
				restriction_elastic_bool_cb,
				&restrictarray->restrictions[0],
				data,
				&jval);
		if (!HRES_IS_OK(hres)) {
			return hres;
		}

		json_object_set_new(jquery, "query", jval);
		temp = json_dumps(jval, JSON_INDENT(2));
		where = talloc_strdup(ctx, temp);
		free(temp);
		if (json_array_size(jsort)) {
			json_object_set(jquery, "sort", jsort);
		}
		temp = json_dumps(jquery, JSON_INDENT(2));
		query = talloc_strdup(ctx, temp);
		free(temp);
		json_decref(jsort);
		json_decref(jquery);
		if (query == NULL) {
			return HRES_E_OUTOFMEMORY;
		}
	}

	*query_str = query;
	*share_scope = data->share_scope;
	*where_id_str = where;
	return HRES_OK;
}

const char *get_propvalueforworkid_query(TALLOC_CTX *ctx,
                        struct memcache *id_cache,
			const char* index_name,
                        uint32_t workid,
                        struct wsp_cfullpropspec *propspec,
                        struct binding_result_mapper *mapper,
			struct backend_selected_cols *backend_cols)
{
	TALLOC_CTX *frame = talloc_stackframe();
	char *prop = NULL;
	const char *query = NULL;
	struct es_detail *detail = NULL;
	struct wsp_ctablecolumn columns[1] = {};
	struct elastic_json_mapping *json_map = NULL;
	const char *id_str = NULL;

	id_str = get_path_for_id(id_cache, index_name, workid);
	prop = prop_from_fullprop(frame, propspec);

	json_map = read_json_mapping();
	if (json_map == NULL) {
		DBG_WARNING("Can't process property %s\n", prop);
		goto out;
	}

	detail = get_es_detail(prop, json_map);
	if (detail == NULL) {
		DBG_WARNING("Can't process property %s\n", prop);
		goto out;
	}

	columns[0].propspec = *propspec;

	backend_cols->backend_ids = talloc_zero_array(ctx, const char *, 1);
	if (backend_cols->backend_ids == NULL) {
		DBG_ERR("out of memory\n");
		goto out;
	}

	backend_cols->cols = 1;
	backend_cols->backend_ids[0] = detail->elastic_id;

	query = talloc_asprintf(ctx,
				"{\"_source\": [\"%s\"],"
				"\"query\": { \"bool\": { \"must\": [ { "
				"\"query_string\": { \"query\": "
				"\"_id:(%s)\" } } ] } } }",
				detail->elastic_id,
				id_str);
	if (!build_es_mapper(ctx, columns, 1, backend_cols, mapper)) {
		DBG_ERR("Failed to build result converter\n");
	}
out:
	TALLOC_FREE(frame);
	return query;
}

struct query_conv_ops *es_wsp_conv_ops(void)
{
	static struct query_conv_ops ops = {
		.bld_mapper = build_es_mapper,
		.bld_query = build_es_query,
		.bld_lookup_whereid = dummy_lookup_whereid,
	};
	return &ops;
}

bool can_access_url(struct conn_wrap *conn_wrap,
		    const char *path)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct connection_struct *conn = NULL;
        struct smb_filename *smb_fname = NULL;
	NTSTATUS status;

	conn = conn_wrap_connection(conn_wrap);

        if (!become_authenticated_pipe_user(conn->session_info)) {
                DBG_ERR("can't become authenticated user:\n");
                smb_panic("can't become authenticated user");
        }

        /*
         * We've changed identity to the authenticated pipe user, so
         * any function exit below must ensure we switch back
         */

	status = conn_wrap_chdir(conn_wrap, frame);
        if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("chdir to [%s] failed: %s\n",
			conn->connectpath,
			nt_errstr(status));
		TALLOC_FREE(frame);
		unbecome_authenticated_pipe_user();
                return false;
	}

        status = synthetic_pathref(talloc_tos(),
                                   conn->cwd_fsp,
                                   path,
                                   NULL,
                                   NULL,
                                   0,
                                   0,
                                   &smb_fname);
        if (!NT_STATUS_IS_OK(status)) {
                DBG_DEBUG("synthetic_pathref [%s]: %s\n",
                          smb_fname_str_dbg(smb_fname),
                          nt_errstr(status));
		TALLOC_FREE(frame);
		unbecome_authenticated_pipe_user();
                return false;
        }

        status = smbd_check_access_rights_fsp(conn->cwd_fsp,
                                              smb_fname->fsp,
                                              false,
                                              FILE_READ_DATA);
	TALLOC_FREE(frame);
	unbecome_authenticated_pipe_user();
        if (!NT_STATUS_IS_OK(status)) {
                return false;
        }

	return true;
}
