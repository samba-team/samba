/* 
   Unix SMB/CIFS implementation.
   kerberos authorization data (PAC) utility library
   Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2003   
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"

#ifdef HAVE_KRB5

static DATA_BLOB unwrap_pac(DATA_BLOB *auth_data)
{
	DATA_BLOB pac_contents;
	ASN1_DATA data;
	int data_type;

	asn1_load(&data, *auth_data);
	asn1_start_tag(&data, ASN1_SEQUENCE(0));
	asn1_start_tag(&data, ASN1_SEQUENCE(0));
	asn1_start_tag(&data, ASN1_CONTEXT(0));
	asn1_read_Integer(&data, &data_type);
	asn1_end_tag(&data);
	asn1_start_tag(&data, ASN1_CONTEXT(1));
	asn1_read_OctetString(&data, &pac_contents);
	asn1_end_tag(&data);
	asn1_end_tag(&data);
	asn1_end_tag(&data);
	asn1_free(&data);
	return pac_contents;
}

static BOOL pac_io_unknown_type_10(const char *desc, UNKNOWN_TYPE_10 *type_10,
				   prs_struct *ps, int depth)
{
	if (NULL == type_10)
		return False;

	prs_debug(ps, depth, desc, "pac_io_unknown_type_10");
	depth++;

	if (!smb_io_time("unknown_time", &type_10->unknown_time, ps, depth))
		return False;

	if (!prs_uint16("len", ps, depth, &type_10->len))
		return False;

	if (UNMARSHALLING(ps) && type_10->len) {
		type_10->username = (uint16 *) prs_alloc_mem(ps, type_10->len);
		if (!type_10->username) {
			DEBUG(3, ("No memory available\n"));
			return False;
		}
	}

	if (!prs_uint16s(True, "name", ps, depth, type_10->username, 
			 (type_10->len / sizeof(uint16))))
		return False;

	return True;

}


static BOOL pac_io_krb_sids(const char *desc, KRB_SID_AND_ATTRS *sid_and_attr,
			    prs_struct *ps, int depth)
{
	if (NULL == sid_and_attr)
		return False;

	prs_debug(ps, depth, desc, "pac_io_krb_sids");
	depth++;

	if (UNMARSHALLING(ps)) {
		sid_and_attr->sid = 
			(DOM_SID2 * ) prs_alloc_mem(ps, sizeof(DOM_SID2));
		if (!sid_and_attr->sid) {
			DEBUG(3, ("No memory available\n"));
			return False;
		}
	}

	if(!smb_io_dom_sid2("sid", sid_and_attr->sid, ps, depth))
		return False;

	return True;
}


static BOOL pac_io_krb_attrs(const char *desc, KRB_SID_AND_ATTRS *sid_and_attr,
			     prs_struct *ps, int depth)
{
	if (NULL == sid_and_attr)
		return False;

	prs_debug(ps, depth, desc, "pac_io_krb_attrs");
	depth++;

	if (!prs_uint32("sid_ptr", ps, depth, &sid_and_attr->sid_ptr))
		return False;
	if (!prs_uint32("attrs", ps, depth, &sid_and_attr->attrs))
		return False;

	return True;
}

static BOOL pac_io_krb_sid_and_attr_array(const char *desc, 
					  KRB_SID_AND_ATTR_ARRAY *array,
					  uint32 num,
					  prs_struct *ps, int depth)
{
	int i;

	if (NULL == array)
		return False;

	prs_debug(ps, depth, desc, "pac_io_krb_sid_and_attr_array");
	depth++;


	if (!prs_uint32("count", ps, depth, &array->count))
		return False;

	if (UNMARSHALLING(ps)) {
		array->krb_sid_and_attrs = (KRB_SID_AND_ATTRS *)
			prs_alloc_mem(ps, sizeof(KRB_SID_AND_ATTRS) * num);
		if (!array->krb_sid_and_attrs) {
			DEBUG(3, ("No memory available\n"));
			return False;
		}
	}

	for (i=0; i<num; i++) {
		if (!pac_io_krb_attrs(desc, 
				      &array->krb_sid_and_attrs[i],
				      ps, depth))
			return False;

	}
	for (i=0; i<num; i++) {
		if (!pac_io_krb_sids(desc, 
				     &array->krb_sid_and_attrs[i],
				     ps, depth))
			return False;

	}

	return True;

}

static BOOL pac_io_group_membership(const char *desc, 
				    GROUP_MEMBERSHIP *membership,
				    prs_struct *ps, int depth)
{
	if (NULL == membership)
		return False;

	prs_debug(ps, depth, desc, "pac_io_group_membership");
	depth++;

	if (!prs_uint32("rid", ps, depth, &membership->rid))
		return False;
	if (!prs_uint32("attrs", ps, depth, &membership->attrs))
		return False;

	return True;
}


static BOOL pac_io_group_membership_array(const char *desc, 
					  GROUP_MEMBERSHIP_ARRAY *array,
					  uint32 num,
					  prs_struct *ps, int depth)
{
	int i;

	if (NULL == array)
		return False;

	prs_debug(ps, depth, desc, "pac_io_group_membership_array");
	depth++;


	if (!prs_uint32("count", ps, depth, &array->count))
		return False;

	if (UNMARSHALLING(ps)) {
		array->group_membership = (GROUP_MEMBERSHIP *)
			prs_alloc_mem(ps, sizeof(GROUP_MEMBERSHIP) * num);
		if (!array->group_membership) {
			DEBUG(3, ("No memory available\n"));
			return False;
		}
	}

	for (i=0; i<num; i++) {
		if (!pac_io_group_membership(desc, 
					     &array->group_membership[i],
					     ps, depth))
			return False;

	}

	return True;

}

static BOOL pac_io_pac_logon_info(const char *desc, PAC_LOGON_INFO *info, 
				  prs_struct *ps, int depth)
{
	uint32 garbage;
	if (NULL == info)
		return False;

	prs_debug(ps, depth, desc, "pac_io_pac_logon_info");
	depth++;

	if (!prs_uint32("unknown", ps, depth, &garbage))
		return False;
	if (!prs_uint32("unknown", ps, depth, &garbage))
		return False;
	if (!prs_uint32("bufferlen", ps, depth, &garbage))
		return False;
	if (!prs_uint32("bufferlenhi", ps, depth, &garbage))
		return False;
	if (!prs_uint32("pointer", ps, depth, &garbage))
		return False;

	if (!smb_io_time("logon_time", &info->logon_time, ps, depth))
		return False;
	if (!smb_io_time("logoff_time", &info->logoff_time, ps, depth))
		return False;
	if (!smb_io_time("kickoff_time", &info->kickoff_time, ps, depth))
		return False;
	if (!smb_io_time("pass_last_set_time", &info->pass_last_set_time, 
			 ps, depth))
		return False;
	if (!smb_io_time("pass_can_change_time", &info->pass_can_change_time, 
			 ps, depth))
		return False;
	if (!smb_io_time("pass_must_change_time", &info->pass_must_change_time,
			 ps, depth))
		return False;

	if (!smb_io_unihdr("hdr_user_name", &info->hdr_user_name, ps, depth))
		return False;
	if (!smb_io_unihdr("hdr_full_name", &info->hdr_full_name, ps, depth))
		return False;
	if (!smb_io_unihdr("hdr_logon_script", &info->hdr_logon_script, 
			   ps, depth))
		return False;
	if (!smb_io_unihdr("hdr_profile_path", &info->hdr_profile_path, 
			   ps, depth))
		return False;
	if (!smb_io_unihdr("hdr_home_dir", &info->hdr_home_dir, ps, depth))
		return False;
	if (!smb_io_unihdr("hdr_dir_drive", &info->hdr_dir_drive, ps, depth))
		return False;

	if (!prs_uint16("logon_count", ps, depth, &info->logon_count))
		return False;
	if (!prs_uint16("reserved12", ps, depth, &info->reserved12))
		return False;
	if (!prs_uint32("user_rid", ps, depth, &info->user_rid))
		return False;
	if (!prs_uint32("group_rid", ps, depth, &info->group_rid))
		return False;
	if (!prs_uint32("group_count", ps, depth, &info->group_count))
		return False;
	/* I haven't seen this contain anything yet, but when it does
	   we will have to make sure we decode the contents in the middle
	   all the unistr2s ... */
	if (!prs_uint32("group_mem_ptr", ps, depth, 
			&info->group_membership_ptr))
		return False;
	if (!prs_uint32("user_flags", ps, depth, &info->user_flags))
		return False;

	if (!prs_uint32("reserved13.0", ps, depth, &info->reserved13[0]))
		return False;
	if (!prs_uint32("reserved13.1", ps, depth, &info->reserved13[1]))
		return False;
	if (!prs_uint32("reserved13.2", ps, depth, &info->reserved13[2]))
		return False;
	if (!prs_uint32("reserved13.3", ps, depth, &info->reserved13[3]))
		return False;
	
	if (!smb_io_unihdr("hdr_dom_controller", 
			   &info->hdr_dom_controller, ps, depth))
		return False;
	if (!smb_io_unihdr("hdr_dom_name", &info->hdr_dom_name, ps, depth))
		return False;

	/* this should be followed, but just get ptr for now */
	if (!prs_uint32("ptr_dom_sid", ps, depth, &info->ptr_dom_sid))
		return False;

	if (!prs_uint32("reserved16.0", ps, depth, &info->reserved16[0]))
		return False;
	if (!prs_uint32("reserved16.1", ps, depth, &info->reserved16[1]))
		return False;

	/* might be acb_info */
	if (!prs_uint32("reserved17", ps, depth, &info->reserved17))
		return False;


	if (!prs_uint32("reserved18.0", ps, depth, &info->reserved18[0]))
		return False;
	if (!prs_uint32("reserved18.1", ps, depth, &info->reserved18[1]))
		return False;
	if (!prs_uint32("reserved18.2", ps, depth, &info->reserved18[2]))
		return False;
	if (!prs_uint32("reserved18.3", ps, depth, &info->reserved18[3]))
		return False;
	if (!prs_uint32("reserved18.4", ps, depth, &info->reserved18[4]))
		return False;
	if (!prs_uint32("reserved18.5", ps, depth, &info->reserved18[5]))
		return False;
	if (!prs_uint32("reserved18.6", ps, depth, &info->reserved18[6]))
		return False;

	if (!prs_uint32("sid_count", ps, depth, &info->sid_count))
		return False;
	if (!prs_uint32("ptr_extra_sids", ps, depth, &info->ptr_extra_sids))
		return False;
	if (!prs_uint32("ptr_res_group_dom_sid", ps, depth, 
			&info->ptr_res_group_dom_sid))
		return False;
	if (!prs_uint32("res_group_count", ps, depth, &info->res_group_count))
		return False;
	if (!prs_uint32("ptr_res_groups", ps, depth, &info->ptr_res_groups))
		return False;

	if(!smb_io_unistr2("uni_user_name", &info->uni_user_name, 
			   info->hdr_user_name.buffer, ps, depth))
		return False;
	if(!smb_io_unistr2("uni_full_name", &info->uni_full_name, 
			   info->hdr_full_name.buffer, ps, depth))
		return False;
	if(!smb_io_unistr2("uni_logon_script", &info->uni_logon_script, 
			   info->hdr_logon_script.buffer, ps, depth))
		return False;
	if(!smb_io_unistr2("uni_profile_path", &info->uni_profile_path,
			   info->hdr_profile_path.buffer, ps, depth))
		return False;
	if(!smb_io_unistr2("uni_home_dir", &info->uni_home_dir,
			   info->hdr_home_dir.buffer, ps, depth))
		return False;
	if(!smb_io_unistr2("uni_dir_drive", &info->uni_dir_drive,
			   info->hdr_dir_drive.buffer, ps, depth))
		return False;

	if (info->group_membership_ptr) {
		if (!pac_io_group_membership_array("group membership",
						   &info->groups,
						   info->group_count,
						   ps, depth))
			return False;
	}


	if(!smb_io_unistr2("uni_dom_controller", &info->uni_dom_controller,
			   info->hdr_dom_controller.buffer, ps, depth))
		return False;
	if(!smb_io_unistr2("uni_dom_name", &info->uni_dom_name, 
			   info->hdr_dom_name.buffer, ps, depth))
		return False;

	if(info->ptr_dom_sid)
		if(!smb_io_dom_sid2("dom_sid", &info->dom_sid, ps, depth))
			return False;

	
	if (info->sid_count && info->ptr_extra_sids)
		if (!pac_io_krb_sid_and_attr_array("extra_sids", 
						   &info->extra_sids,
						   info->sid_count,
						   ps, depth))
			return False;

	if (info->ptr_res_group_dom_sid)
		if (!smb_io_dom_sid2("res_group_dom_sid", 
				     &info->res_group_dom_sid, ps, depth))
			return False;

	if (info->ptr_res_groups)
		if (!pac_io_group_membership_array("res group membership",
						   &info->res_groups,
						   info->res_group_count,
						   ps, depth))
			return False;

	return True;
}


static BOOL pac_io_pac_signature_data(const char *desc, 
				      PAC_SIGNATURE_DATA *data, uint32 length,
				      prs_struct *ps, int depth)
{
	uint32 siglen = length - sizeof(uint32);
	if (NULL == data)
		return False;

	prs_debug(ps, depth, desc, "pac_io_pac_signature_data");
	depth++;

	if (!prs_uint32("type", ps, depth, &data->type))
		return False;
	if (UNMARSHALLING(ps)) {
		data->signature = (unsigned char *)prs_alloc_mem(ps, siglen);
		if (!data->signature) {
			DEBUG(3, ("No memory available\n"));
			return False;
		}
	}
	if (!prs_uint8s(False, "signature", ps, depth, data->signature,siglen))
		return False;

	return True;
}

static BOOL pac_io_pac_info_hdr_ctr(const char *desc, PAC_INFO_HDR *hdr,
				    prs_struct *ps, int depth)
{
	if (NULL == hdr)
		return False;

	prs_debug(ps, depth, desc, "pac_io_pac_info_hdr_ctr");
	depth++;

	if (!prs_align(ps))
		return False;

	if (hdr->offset != prs_offset(ps)) {
		DEBUG(5, ("offset in header(x%x) and data(x%x) do not match\n",
			  hdr->offset, prs_offset(ps)));
		prs_set_offset(ps, hdr->offset);
	}

	if (UNMARSHALLING(ps) && hdr->size > 0) {
		hdr->ctr = (PAC_INFO_CTR *) 
			prs_alloc_mem(ps, sizeof(PAC_INFO_CTR));
		if (!hdr->ctr) {
			DEBUG(3, ("No memory available\n"));
			return False;
		}
	}

	switch(hdr->type) {
	case PAC_TYPE_LOGON_INFO:
		DEBUG(5, ("PAC_TYPE_LOGON_INFO\n"));
		if (UNMARSHALLING(ps))
			hdr->ctr->pac.logon_info = (PAC_LOGON_INFO *)
				prs_alloc_mem(ps, sizeof(PAC_LOGON_INFO));
		if (!hdr->ctr->pac.logon_info) {
			DEBUG(3, ("No memory available\n"));
			return False;
		}
		if (!pac_io_pac_logon_info(desc, hdr->ctr->pac.logon_info,
					   ps, depth))
			return False;
		break;

	case PAC_TYPE_SERVER_CHECKSUM:
		DEBUG(5, ("PAC_TYPE_SERVER_CHECKSUM\n"));
		if (UNMARSHALLING(ps))
			hdr->ctr->pac.srv_cksum = (PAC_SIGNATURE_DATA *)
				prs_alloc_mem(ps, sizeof(PAC_SIGNATURE_DATA));
		if (!hdr->ctr->pac.srv_cksum) {
			DEBUG(3, ("No memory available\n"));
			return False;
		}
		if (!pac_io_pac_signature_data(desc, hdr->ctr->pac.srv_cksum,
					       hdr->size, ps, depth))
			return False;
		break;

	case PAC_TYPE_PRIVSVR_CHECKSUM:
		DEBUG(5, ("PAC_TYPE_PRIVSVR_CHECKSUM\n"));
		if (UNMARSHALLING(ps))
			hdr->ctr->pac.privsrv_cksum = (PAC_SIGNATURE_DATA *)
				prs_alloc_mem(ps, sizeof(PAC_SIGNATURE_DATA));
		if (!hdr->ctr->pac.privsrv_cksum) {
			DEBUG(3, ("No memory available\n"));
			return False;
		}
		if (!pac_io_pac_signature_data(desc, 
					       hdr->ctr->pac.privsrv_cksum,
					       hdr->size, ps, depth))
			return False;
		break;

	case PAC_TYPE_UNKNOWN_10:
		DEBUG(5, ("PAC_TYPE_UNKNOWN_10\n"));
		if (UNMARSHALLING(ps))
			hdr->ctr->pac.type_10 = (UNKNOWN_TYPE_10 *)
				prs_alloc_mem(ps, sizeof(UNKNOWN_TYPE_10));
		if (!hdr->ctr->pac.type_10) {
			DEBUG(3, ("No memory available\n"));
			return False;
		}
		if (!pac_io_unknown_type_10(desc, hdr->ctr->pac.type_10,
					    ps, depth))
			return False;
		break;

	default:
		/* dont' know, so we need to skip it */
		DEBUG(3, ("unknown PAC type %d\n", hdr->type));
		prs_set_offset(ps, prs_offset(ps) + hdr->size);
	}

	return True;
}

static BOOL pac_io_pac_info_hdr(const char *desc, PAC_INFO_HDR *hdr, 
				prs_struct *ps, int depth)
{
	if (NULL == hdr)
		return False;

	prs_debug(ps, depth, desc, "pac_io_pac_info_hdr");
	depth++;

	if (!prs_align(ps))
		return False;
	if (!prs_uint32("type", ps, depth, &hdr->type))
		return False;
	if (!prs_uint32("size", ps, depth, &hdr->size))
		return False;
	if (!prs_uint32("offset", ps, depth, &hdr->offset))
		return False;
	if (!prs_uint32("offsethi", ps, depth, &hdr->offsethi))
		return False;

	return True;
}

static BOOL pac_io_pac_data(const char *desc, PAC_DATA *data, 
			    prs_struct *ps, int depth)
{
	int i;

	if (NULL == data)
		return False;

	prs_debug(ps, depth, desc, "pac_io_pac_data");
	depth++;

	if (!prs_align(ps))
		return False;
	if (!prs_uint32("num_buffers", ps, depth, &data->num_buffers))
		return False;
	if (!prs_uint32("version", ps, depth, &data->version))
		return False;

	if (UNMARSHALLING(ps) && data->num_buffers > 0) {
		if ((data->pac_info_hdr_ptr = (PAC_INFO_HDR *) 
		     prs_alloc_mem(ps, sizeof(PAC_INFO_HDR) * 
				   data->num_buffers)) == NULL) {
			return False;
		}
	}

	for (i=0; i<data->num_buffers; i++) {
		if (!pac_io_pac_info_hdr(desc, &data->pac_info_hdr_ptr[i], ps, 
					 depth))
			return False;
	}

	for (i=0; i<data->num_buffers; i++) {
		if (!pac_io_pac_info_hdr_ctr(desc, &data->pac_info_hdr_ptr[i],
					     ps, depth))
			return False;
	}

	return True;
}

PAC_DATA *decode_pac_data(DATA_BLOB *auth_data, TALLOC_CTX *ctx)
{
	DATA_BLOB pac_data_blob = unwrap_pac(auth_data);
	prs_struct ps;
	PAC_DATA *pac_data;

	DEBUG(5,("dump_pac_data\n"));
	prs_init(&ps, pac_data_blob.length, ctx, UNMARSHALL);
	prs_copy_data_in(&ps, (char *)pac_data_blob.data, pac_data_blob.length);
	prs_set_offset(&ps, 0);

	data_blob_free(&pac_data_blob);

	pac_data = (PAC_DATA *) talloc_zero(ctx, sizeof(PAC_DATA));
	pac_io_pac_data("pac data", pac_data, &ps, 0);

	prs_mem_free(&ps);

	return pac_data;
}

#endif
