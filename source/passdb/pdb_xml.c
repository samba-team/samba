
/*
 * XML password backend for samba
 * Copyright (C) Jelmer Vernooij 2002
 * Some parts based on the libxml gjobread example by Daniel Veillard
 * 
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 675
 * Mass Ave, Cambridge, MA 02139, USA.
 */

/* FIXME: 
 * - Support stdin input by using '-'
 * - Be faster. Don't rewrite the whole file when adding a user, but store it in the memory and save it when exiting. Requires changes to samba source.
 * - Gives the ability to read/write to standard input/output
 * - Do locking!
 * - Better names!
 */


#define XML_URL "http://samba.org/~jelmer/sambapdb.dtd"

#include "includes.h"

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

static int xmlsam_debug_level = DBGC_ALL;

#undef DBGC_CLASS
#define DBGC_CLASS xmlsam_debug_level

static char * iota(int a) {
	static char tmp[10];

	snprintf(tmp, 9, "%d", a);
	return tmp;
}

static BOOL parsePass(xmlDocPtr doc, xmlNsPtr ns, xmlNodePtr cur, SAM_ACCOUNT * u)
{
	pstring temp;

	cur = cur->xmlChildrenNode;
	while (cur != NULL) {
		if (strcmp(cur->name, "crypt"))
			DEBUG(0, ("Unknown element %s\n", cur->name));
		else {
			if (!strcmp(xmlGetProp(cur, "type"), "nt")
				&&
				pdb_gethexpwd(xmlNodeListGetString
							  (doc, cur->xmlChildrenNode, 1), temp))
				pdb_set_nt_passwd(u, temp, PDB_SET);
			else if (!strcmp(xmlGetProp(cur, "type"), "lanman")
					 &&
					 pdb_gethexpwd(xmlNodeListGetString
								   (doc, cur->xmlChildrenNode, 1), temp))
				pdb_set_lanman_passwd(u, temp, PDB_SET);
			else
				DEBUG(0,
					  ("Unknown crypt type: %s\n",
					   xmlGetProp(cur, "type")));
		}
		cur = cur->next;
	}
	return True;
}

static BOOL parseUser(xmlDocPtr doc, xmlNsPtr ns, xmlNodePtr cur, SAM_ACCOUNT * u)
{
	char *tmp;
	DOM_SID sid;

	tmp = xmlGetProp(cur, "sid");
	if (tmp){
		string_to_sid(&sid, tmp);
		pdb_set_user_sid(u, &sid, PDB_SET);
	}
	pdb_set_username(u, xmlGetProp(cur, "name"), PDB_SET);
	/* We don't care what the top level element name is */
	cur = cur->xmlChildrenNode;
	while (cur != NULL) {
		if ((!strcmp(cur->name, "group")) && (cur->ns == ns)) {
			tmp = xmlGetProp(cur, "sid");
			if (tmp){
				string_to_sid(&sid, tmp);
				pdb_set_group_sid(u, &sid, PDB_SET);
			}
		}

		else if ((!strcmp(cur->name, "domain")) && (cur->ns == ns))
			pdb_set_domain(u,
						   xmlNodeListGetString(doc, cur->xmlChildrenNode,
												1), PDB_SET);

		else if (!strcmp(cur->name, "fullname") && cur->ns == ns)
			pdb_set_fullname(u,
							 xmlNodeListGetString(doc,
												  cur->xmlChildrenNode,
												  1), PDB_SET);

		else if (!strcmp(cur->name, "nt_username") && cur->ns == ns)
			pdb_set_nt_username(u,
								xmlNodeListGetString(doc,
													 cur->xmlChildrenNode,
													 1), PDB_SET);

		else if (!strcmp(cur->name, "logon_script") && cur->ns == ns)
			pdb_set_logon_script(u,
								 xmlNodeListGetString(doc,
													  cur->xmlChildrenNode,
													  1), PDB_SET);

		else if (!strcmp(cur->name, "profile_path") && cur->ns == ns)
			pdb_set_profile_path(u,
								 xmlNodeListGetString(doc,
													  cur->xmlChildrenNode,
													  1), PDB_SET);

		else if (!strcmp(cur->name, "logon_time") && cur->ns == ns)
			pdb_set_logon_time(u,
							   atol(xmlNodeListGetString
									(doc, cur->xmlChildrenNode, 1)), PDB_SET);

		else if (!strcmp(cur->name, "logoff_time") && cur->ns == ns)
			pdb_set_logoff_time(u,
								atol(xmlNodeListGetString
									 (doc, cur->xmlChildrenNode, 1)),
								PDB_SET);

		else if (!strcmp(cur->name, "kickoff_time") && cur->ns == ns)
			pdb_set_kickoff_time(u,
								 atol(xmlNodeListGetString
									  (doc, cur->xmlChildrenNode, 1)),
								 PDB_SET);

		else if (!strcmp(cur->name, "logon_divs") && cur->ns == ns)
			pdb_set_logon_divs(u,
							   atol(xmlNodeListGetString
									(doc, cur->xmlChildrenNode, 1)), PDB_SET);

		else if (!strcmp(cur->name, "hours_len") && cur->ns == ns)
			pdb_set_hours_len(u,
							  atol(xmlNodeListGetString
								   (doc, cur->xmlChildrenNode, 1)), PDB_SET);

		else if (!strcmp(cur->name, "bad_password_count") && cur->ns == ns)
			pdb_set_bad_password_count(u,
							  atol(xmlNodeListGetString
								   (doc, cur->xmlChildrenNode, 1)), PDB_SET);

		else if (!strcmp(cur->name, "logon_count") && cur->ns == ns)
			pdb_set_logon_count(u,
							  atol(xmlNodeListGetString
								   (doc, cur->xmlChildrenNode, 1)), PDB_SET);

		else if (!strcmp(cur->name, "unknown_6") && cur->ns == ns)
			pdb_set_unknown_6(u,
							  atol(xmlNodeListGetString
								   (doc, cur->xmlChildrenNode, 1)), PDB_SET);

		else if (!strcmp(cur->name, "homedir") && cur->ns == ns)
			pdb_set_homedir(u,
							xmlNodeListGetString(doc, cur->xmlChildrenNode,
												 1), PDB_SET);

		else if (!strcmp(cur->name, "unknown_str") && cur->ns == ns)
			pdb_set_unknown_str(u,
								xmlNodeListGetString(doc,
													 cur->xmlChildrenNode,
													 1), PDB_SET);

		else if (!strcmp(cur->name, "dir_drive") && cur->ns == ns)
			pdb_set_dir_drive(u,
							  xmlNodeListGetString(doc,
												   cur->xmlChildrenNode,
												   1), PDB_SET);

		else if (!strcmp(cur->name, "munged_dial") && cur->ns == ns)
			pdb_set_munged_dial(u,
								xmlNodeListGetString(doc,
													 cur->xmlChildrenNode,
													 1), PDB_SET);

		else if (!strcmp(cur->name, "acct_desc") && cur->ns == ns)
			pdb_set_acct_desc(u,
							  xmlNodeListGetString(doc,
												   cur->xmlChildrenNode,
												   1), PDB_SET);

		else if (!strcmp(cur->name, "acct_ctrl") && cur->ns == ns)
			pdb_set_acct_ctrl(u,
							  atol(xmlNodeListGetString
								   (doc, cur->xmlChildrenNode, 1)), PDB_SET);

		else if (!strcmp(cur->name, "workstations") && cur->ns == ns)
			pdb_set_workstations(u,
								 xmlNodeListGetString(doc,
													  cur->xmlChildrenNode,
													  1), PDB_SET);

		else if ((!strcmp(cur->name, "password")) && (cur->ns == ns)) {
			tmp = xmlGetProp(cur, "last_set");
			if (tmp)
				pdb_set_pass_last_set_time(u, atol(tmp), PDB_SET);
			tmp = xmlGetProp(cur, "must_change");
			if (tmp)
				pdb_set_pass_must_change_time(u, atol(tmp), PDB_SET);
			tmp = xmlGetProp(cur, "can_change");
			if (tmp)
				pdb_set_pass_can_change_time(u, atol(tmp), PDB_SET);
			parsePass(doc, ns, cur, u);
		}

		else
			DEBUG(0, ("Unknown element %s\n", cur->name));
		cur = cur->next;
	}

	return True;
}

typedef struct pdb_xml {
	char *location;
	char written;
	xmlDocPtr doc;
	xmlNodePtr users;
	xmlNodePtr pwent;
	xmlNsPtr ns;
} pdb_xml;

static xmlNodePtr parseSambaXMLFile(struct pdb_xml *data)
{
	xmlNodePtr cur;

	data->doc = xmlParseFile(data->location);
	if (data->doc == NULL)
		return NULL;

	cur = xmlDocGetRootElement(data->doc);
	if (!cur) {
		DEBUG(0, ("empty document\n"));
		xmlFreeDoc(data->doc);
		return NULL;
	}
	data->ns = xmlSearchNsByHref(data->doc, cur, XML_URL);
	if (!data->ns) {
		DEBUG(0,
			  ("document of the wrong type, samba user namespace not found\n"));
		xmlFreeDoc(data->doc);
		return NULL;
	}
	if (strcmp(cur->name, "samba")) {
		DEBUG(0, ("document of the wrong type, root node != samba"));
		xmlFreeDoc(data->doc);
		return NULL;
	}

	cur = cur->xmlChildrenNode;
	while (cur && xmlIsBlankNode(cur)) {
		cur = cur->next;
	}
	if (!cur)
		return NULL;
	if ((strcmp(cur->name, "users")) || (cur->ns != data->ns)) {
		DEBUG(0, ("document of the wrong type, was '%s', users expected",
				  cur->name));
		DEBUG(0, ("xmlDocDump follows\n"));
		xmlDocDump(stderr, data->doc);
		DEBUG(0, ("xmlDocDump finished\n"));
		xmlFreeDoc(data->doc);
		return NULL;
	}
	data->users = cur;
	cur = cur->xmlChildrenNode;
	return cur;
}

static NTSTATUS xmlsam_setsampwent(struct pdb_methods *methods, BOOL update)
{
	pdb_xml *data;

	if (!methods) {
		DEBUG(0, ("Invalid methods\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}
	data = (pdb_xml *) methods->private_data;
	if (!data) {
		DEBUG(0, ("Invalid pdb_xml_data\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}
	data->pwent = parseSambaXMLFile(data);
	if (!data->pwent)
		return NT_STATUS_UNSUCCESSFUL;
	
	return NT_STATUS_OK;
}

/***************************************************************
  End enumeration of the passwd list.
 ****************************************************************/

static void xmlsam_endsampwent(struct pdb_methods *methods)
{
	pdb_xml *data;

	if (!methods) {
		DEBUG(0, ("Invalid methods\n"));
		return;
	}

	data = (pdb_xml *) methods->private_data;

	if (!data) {
		DEBUG(0, ("Invalid pdb_xml_data\n"));
		return;
	}

	xmlFreeDoc(data->doc);
	data->doc = NULL;
	data->pwent = NULL;
}

/*****************************************************************
  Get one SAM_ACCOUNT from the list (next in line)
 *****************************************************************/

static NTSTATUS xmlsam_getsampwent(struct pdb_methods *methods, SAM_ACCOUNT * user)
{
	pdb_xml *data;

	if (!methods) {
		DEBUG(0, ("Invalid methods\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}
	data = (pdb_xml *) methods->private_data;

	if (!data) {
		DEBUG(0, ("Invalid pdb_xml_data\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	while (data->pwent) {
		if ((!strcmp(data->pwent->name, "user")) &&
			(data->pwent->ns == data->ns)) {

			parseUser(data->doc, data->ns, data->pwent, user);
			data->pwent = data->pwent->next;
			return NT_STATUS_OK;
		}
		data->pwent = data->pwent->next;
	}
	return NT_STATUS_UNSUCCESSFUL;
}

/***************************************************************************
  Adds an existing SAM_ACCOUNT
 ****************************************************************************/

static NTSTATUS xmlsam_add_sam_account(struct pdb_methods *methods, SAM_ACCOUNT * u)
{
	pstring temp;
	fstring sid_str;
	xmlNodePtr cur, user, pass, root;
	pdb_xml *data;

	DEBUG(10, ("xmlsam_add_sam_account called!\n"));

	if (!methods) {
		DEBUG(0, ("Invalid methods\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	data = (pdb_xml *) methods->private_data;
	if (!data) {
		DEBUG(0, ("Invalid pdb_xml_data\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* Create a new document if we can't open the current one */
	if (!parseSambaXMLFile(data)) {
		DEBUG(0, ("Can't load current XML file, creating a new one\n"));
		data->doc = xmlNewDoc(XML_DEFAULT_VERSION);
		root = xmlNewDocNode(data->doc, NULL, "samba", NULL);
		cur = xmlDocSetRootElement(data->doc, root);
		data->ns = xmlNewNs(root, XML_URL, "samba");
		data->users = xmlNewChild(root, data->ns, "users", NULL);
	}

	user = xmlNewChild(data->users, data->ns, "user", NULL);
	xmlNewProp(user, "sid",
			   sid_to_string(sid_str, pdb_get_user_sid(u)));

	if (pdb_get_username(u) && strcmp(pdb_get_username(u), ""))
		xmlNewProp(user, "name", pdb_get_username(u));

	cur = xmlNewChild(user, data->ns, "group", NULL);
	
	xmlNewProp(cur, "sid",
			   sid_to_string(sid_str, pdb_get_group_sid(u)));

	if (pdb_get_init_flags(u, PDB_LOGONTIME) != PDB_DEFAULT)
		xmlNewChild(user, data->ns, "logon_time",
					iota(pdb_get_logon_time(u)));

	if (pdb_get_init_flags(u, PDB_LOGOFFTIME) != PDB_DEFAULT)
		xmlNewChild(user, data->ns, "logoff_time",
					iota(pdb_get_logoff_time(u)));

	if (pdb_get_init_flags(u, PDB_KICKOFFTIME) != PDB_DEFAULT)
		xmlNewChild(user, data->ns, "kickoff_time",
					iota(pdb_get_kickoff_time(u)));

	if (pdb_get_domain(u) && strcmp(pdb_get_domain(u), ""))
		xmlNewChild(user, data->ns, "domain", pdb_get_domain(u));

	if (pdb_get_nt_username(u) && strcmp(pdb_get_nt_username(u), ""))
		xmlNewChild(user, data->ns, "nt_username", pdb_get_nt_username(u));

	if (pdb_get_fullname(u) && strcmp(pdb_get_fullname(u), ""))
		xmlNewChild(user, data->ns, "fullname", pdb_get_fullname(u));

	if (pdb_get_homedir(u) && strcmp(pdb_get_homedir(u), ""))
		xmlNewChild(user, data->ns, "homedir", pdb_get_homedir(u));

	if (pdb_get_dir_drive(u) && strcmp(pdb_get_dir_drive(u), ""))
		xmlNewChild(user, data->ns, "dir_drive", pdb_get_dir_drive(u));

	if (pdb_get_logon_script(u) && strcmp(pdb_get_logon_script(u), ""))
		xmlNewChild(user, data->ns, "logon_script",
					pdb_get_logon_script(u));

	if (pdb_get_profile_path(u) && strcmp(pdb_get_profile_path(u), ""))
		xmlNewChild(user, data->ns, "profile_path",
					pdb_get_profile_path(u));

	if (pdb_get_acct_desc(u) && strcmp(pdb_get_acct_desc(u), ""))
		xmlNewChild(user, data->ns, "acct_desc", pdb_get_acct_desc(u));

	if (pdb_get_workstations(u) && strcmp(pdb_get_workstations(u), ""))
		xmlNewChild(user, data->ns, "workstations",
					pdb_get_workstations(u));

	if (pdb_get_unknown_str(u) && strcmp(pdb_get_unknown_str(u), ""))
		xmlNewChild(user, data->ns, "unknown_str", pdb_get_unknown_str(u));

	if (pdb_get_munged_dial(u) && strcmp(pdb_get_munged_dial(u), ""))
		xmlNewChild(user, data->ns, "munged_dial", pdb_get_munged_dial(u));


	/* Password stuff */
	pass = xmlNewChild(user, data->ns, "password", NULL);
	if (pdb_get_pass_last_set_time(u))
		xmlNewProp(pass, "last_set", iota(pdb_get_pass_last_set_time(u)));
	if (pdb_get_init_flags(u, PDB_CANCHANGETIME) != PDB_DEFAULT)
		xmlNewProp(pass, "can_change",
				   iota(pdb_get_pass_can_change_time(u)));

	if (pdb_get_init_flags(u, PDB_MUSTCHANGETIME) != PDB_DEFAULT)
		xmlNewProp(pass, "must_change",
				   iota(pdb_get_pass_must_change_time(u)));


	if (pdb_get_lanman_passwd(u)) {
		pdb_sethexpwd(temp, pdb_get_lanman_passwd(u),
					  pdb_get_acct_ctrl(u));
		cur = xmlNewChild(pass, data->ns, "crypt", temp);
		xmlNewProp(cur, "type", "lanman");
	}

	if (pdb_get_nt_passwd(u)) {
		pdb_sethexpwd(temp, pdb_get_nt_passwd(u), pdb_get_acct_ctrl(u));
		cur = xmlNewChild(pass, data->ns, "crypt", temp);
		xmlNewProp(cur, "type", "nt");
	}

	xmlNewChild(user, data->ns, "acct_ctrl", iota(pdb_get_acct_ctrl(u)));

	if (pdb_get_logon_divs(u))
		xmlNewChild(user, data->ns, "logon_divs",
					iota(pdb_get_logon_divs(u)));

	if (pdb_get_hours_len(u))
		xmlNewChild(user, data->ns, "hours_len",
					iota(pdb_get_hours_len(u)));

	xmlNewChild(user, data->ns, "bad_password_count", iota(pdb_get_bad_password_count(u)));
	xmlNewChild(user, data->ns, "logon_count", iota(pdb_get_logon_count(u)));
	xmlNewChild(user, data->ns, "unknown_6", iota(pdb_get_unknown_6(u)));
	xmlSaveFile(data->location, data->doc);

	return NT_STATUS_OK;
}

static NTSTATUS xmlsam_init(PDB_CONTEXT * pdb_context, PDB_METHODS ** pdb_method,
		 const char *location)
{
	NTSTATUS nt_status;
	pdb_xml *data;

	xmlsam_debug_level = debug_add_class("xmlsam");
	if (xmlsam_debug_level == -1) {
		xmlsam_debug_level = DBGC_ALL;
		DEBUG(0, ("xmlsam: Couldn't register custom debugging class!\n"));
	}

	if (!pdb_context) {
		DEBUG(0, ("invalid pdb_methods specified\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (!NT_STATUS_IS_OK
		(nt_status = make_pdb_methods(pdb_context->mem_ctx, pdb_method))) {
		return nt_status;
	}

	(*pdb_method)->name = "xmlsam";

	(*pdb_method)->setsampwent = xmlsam_setsampwent;
	(*pdb_method)->endsampwent = xmlsam_endsampwent;
	(*pdb_method)->getsampwent = xmlsam_getsampwent;
	(*pdb_method)->add_sam_account = xmlsam_add_sam_account;
	(*pdb_method)->getsampwnam = NULL;
	(*pdb_method)->getsampwsid = NULL;
	(*pdb_method)->update_sam_account = NULL;
	(*pdb_method)->delete_sam_account = NULL;
	(*pdb_method)->getgrsid = NULL;
	(*pdb_method)->getgrgid = NULL;
	(*pdb_method)->getgrnam = NULL;
	(*pdb_method)->add_group_mapping_entry = NULL;
	(*pdb_method)->update_group_mapping_entry = NULL;
	(*pdb_method)->delete_group_mapping_entry = NULL;
	(*pdb_method)->enum_group_mapping = NULL;

	data = talloc(pdb_context->mem_ctx, sizeof(pdb_xml));
	data->location = talloc_strdup(pdb_context->mem_ctx, (location ? location : "passdb.xml"));
	data->pwent = NULL;
	data->written = 0;
	(*pdb_method)->private_data = data;

	LIBXML_TEST_VERSION xmlKeepBlanksDefault(0);

	return NT_STATUS_OK;
}

NTSTATUS pdb_xml_init(void) 
{
	return smb_register_passdb(PASSDB_INTERFACE_VERSION, "xml", xmlsam_init);
}
