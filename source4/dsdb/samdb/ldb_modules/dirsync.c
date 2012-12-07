/*
   SAMDB control module

   Copyright (C) Matthieu Patou <mat@matws.net> 2011

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


#include "includes.h"
#include "ldb/include/ldb.h"
#include "ldb/include/ldb_errors.h"
#include "ldb/include/ldb_module.h"
#include "libcli/security/security.h"
#include "librpc/gen_ndr/drsblobs.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "librpc/ndr/libndr.h"
#include "dsdb/samdb/samdb.h"
#include "dsdb/samdb/ldb_modules/util.h"

#define LDAP_DIRSYNC_OBJECT_SECURITY		0x01
#define LDAP_DIRSYNC_ANCESTORS_FIRST_ORDER	0x800
#define LDAP_DIRSYNC_PUBLIC_DATA_ONLY		0x2000
#define LDAP_DIRSYNC_INCREMENTAL_VALUES		0x80000000


struct dirsync_context {
	struct ldb_module *module;
	struct ldb_request *req;

	/*
	 * We keep a track of the number of attributes that we
	 * add just for the need of the implementation
	 * it will be usefull to track then entries that needs not to
	 * be returned because there is no real change
	 */

	unsigned int nbDefaultAttrs;
	uint64_t highestUSN;
	uint64_t fromreqUSN;
	uint32_t cursor_size;
	bool noextended;
	bool linkIncrVal;
	bool localonly;
	bool partial;
	bool assystem;
	int functional_level;
	const struct GUID *our_invocation_id;
	const struct dsdb_schema *schema;
	struct ldb_dn *nc_root;
	struct drsuapi_DsReplicaCursor *cursors;
};


static int dirsync_filter_entry(struct ldb_request *req,
					struct ldb_message *msg,
					struct ldb_control **controls,
					struct dirsync_context *dsc,
					bool referral)
{
	struct ldb_context *ldb;
	uint64_t val;
	enum ndr_err_code ndr_err;
	uint32_t n;
	int i;
	unsigned int size, j;
	struct ldb_val *replMetaData = NULL;
	struct replPropertyMetaDataBlob rmd;
	const struct dsdb_attribute *attr;
	const char **listAttr = NULL;
	bool namereturned = false;
	bool nameasked = false;
	NTSTATUS status;
	/* Ajustment for the added attributes, it will reduce the number of
	 * expected to be here attributes*/
	unsigned int delta = 0;
	const char **myaccept = NULL;
	const char *emptyaccept[] = { NULL };
	const char *extendedaccept[] = { "GUID", "SID", "WKGUID", NULL };
	const char *rdn = NULL;
	struct ldb_message_element *el;
	struct ldb_message *newmsg;
	bool keep = false;
	/*
	 * Where we asked to do extended dn ?
	 * if so filter out everything bug GUID, SID, WKGUID,
	 * if not filter out everything (just keep the dn).
	 */
	if ( dsc->noextended == true ) {
		myaccept = emptyaccept;
	} else {
		myaccept = extendedaccept;
	}
	ldb = ldb_module_get_ctx(dsc->module);

	if (msg->num_elements == 0) {
		/*
			* Entry that we don't really have access to
			*/
		return LDB_SUCCESS;
	}
	ldb_dn_extended_filter(msg->dn, myaccept);

	/*
	* If the RDN starts with CN then the CN attribute is never returned
	*/
	rdn = ldb_dn_get_rdn_name(msg->dn);

	/*
	 * if objectGUID is asked and we are dealing for the referrals entries and
	 * the usn searched is 0 then we didn't count the objectGUID as an automatically
	 * returned attribute, do to so we increament delta.
	 */
	if (referral == true &&
			ldb_attr_in_list(req->op.search.attrs, "objectGUID") &&
			dsc->fromreqUSN == 0) {
		delta++;
	}


	/*
	 * In terms of big O notation this is not the best algorithm,
	 * but we try our best not to make the worse one.
	 * We are obliged to run through the n message's elements
	 * and through the p elements of the replPropertyMetaData.
	 *
	 * It turns out that we are crawling twice the message's elements
	 * the first crawl is to remove the non replicated and generated
	 * attributes. The second one is to remove attributes that haven't
	 * a USN > as the requested one.
	 *
	 * In the second crawl we are reading the list of elements in the
	 * replPropertyMetaData for each remaining replicated attribute.
	 * In order to keep the list small
	 *
	 * We have a O(n'*p') complexity, in worse case n' = n and p' = p
	 * but in most case n' = n/2 (at least half of returned attributes
	 * are not replicated or generated) and p' is small as we
	 * list only the attribute that have been modified since last interogation
	 *
	 */
	newmsg = talloc_zero(dsc->req, struct ldb_message);
	if (newmsg == NULL) {
		return ldb_oom(ldb);
	}
	for (i = msg->num_elements - 1; i >= 0; i--) {
		attr = dsdb_attribute_by_lDAPDisplayName(dsc->schema, msg->elements[i].name);
		if (ldb_attr_cmp(msg->elements[i].name, "uSNChanged") == 0) {
			/* Read the USN it will used at the end of the filtering
			 * to update the max USN in the cookie if we
			 * decide to keep this entry
			 */
			val = strtoull((const char*)msg->elements[i].values[0].data, NULL, 0);
			continue;
		}

		if (ldb_attr_cmp(msg->elements[i].name,
						"replPropertyMetaData") == 0) {
			replMetaData = (talloc_steal(dsc, &msg->elements[i].values[0]));
			continue;
		}
	}

	if (replMetaData == NULL) {
		bool guidfound = false;

		/*
		 * We are in the case of deleted object where we don't have the
		 * right to read it.
		 */
		if (!ldb_msg_find_attr_as_uint(msg, "isDeleted", 0)) {
			/*
			 * This is not a deleted item and we don't
			 * have the replPropertyMetaData.
			 * Do not return it
			 */
			return LDB_SUCCESS;
		}
		newmsg->dn = ldb_dn_new(newmsg, ldb, "");
		if (newmsg->dn == NULL) {
			return ldb_oom(ldb);
		}

		el = ldb_msg_find_element(msg, "objectGUID");
		if ( el != NULL) {
			guidfound = true;
		}
		/*
		 * We expect to find the GUID in the object,
		 * if it turns out not to be the case sometime
		 * well will uncomment the code bellow
		 */
		SMB_ASSERT(guidfound == true);
		/*
		if (guidfound == false) {
			struct GUID guid;
			struct ldb_val *new_val;
			DATA_BLOB guid_blob;

			tmp[0] = '\0';
			txt = strrchr(txt, ':');
			if (txt == NULL) {
				return ldb_module_done(dsc->req, NULL, NULL, LDB_ERR_OPERATIONS_ERROR);
			}
			txt++;

			status = GUID_from_string(txt, &guid);
			if (!NT_STATUS_IS_OK(status)) {
				return ldb_module_done(dsc->req, NULL, NULL, LDB_ERR_OPERATIONS_ERROR);
			}

			status = GUID_to_ndr_blob(&guid, msg, &guid_blob);
			if (!NT_STATUS_IS_OK(status)) {
				return ldb_module_done(dsc->req, NULL, NULL, LDB_ERR_OPERATIONS_ERROR);
			}

			new_val = talloc(msg, struct ldb_val);
			if (new_val == NULL) {
				return ldb_oom(ldb);
			}
			new_val->data = talloc_steal(new_val, guid_blob.data);
			new_val->length = guid_blob.length;
			if (ldb_msg_add_value(msg, "objectGUID", new_val, NULL) != 0) {
				return ldb_module_done(dsc->req, NULL, NULL, LDB_ERR_OPERATIONS_ERROR);
			}
		}
		*/
		ldb_msg_add(newmsg, el, LDB_FLAG_MOD_ADD);
		talloc_steal(newmsg->elements, el->name);
		talloc_steal(newmsg->elements, el->values);

		talloc_steal(newmsg->elements, msg);
		return ldb_module_send_entry(dsc->req, msg, controls);
	}

	ndr_err = ndr_pull_struct_blob(replMetaData, dsc, &rmd,
		(ndr_pull_flags_fn_t)ndr_pull_replPropertyMetaDataBlob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		ldb_set_errstring(ldb, "Unable to unmarshall replPropertyMetaData");
		return ldb_module_done(dsc->req, NULL, NULL, LDB_ERR_OPERATIONS_ERROR);
	}
	if (ldb_attr_in_list(req->op.search.attrs, "name") ||
			ldb_attr_in_list(req->op.search.attrs, "*")) {
		nameasked = true;
	}

	/*
		* If we don't have an USN and no updateness array then we skip the
		* test phase this is an optimisation for the case when you
		* first query the DC without a cookie.
		* As this query is most probably the one
		* that will return the biggest answer, skipping this part
		* will really save time.
		*/
	if (ldb_dn_compare(dsc->nc_root, msg->dn) == 0) {
		/* If we have name then we expect to have parentGUID,
		 * it will not be the case for the root of the NC
		 */
		delta++;
	}

	if (dsc->fromreqUSN > 0 || dsc->cursors != NULL) {
		j = 0;
		/*
		* Allocate an array of size(replMetaData) of char*
		* we know that it will be oversized but it's a short lived element
		*/
		listAttr = talloc_array(msg, const char*, rmd.ctr.ctr1.count + 1);
		if (listAttr == NULL) {
			return ldb_oom(ldb);
		}
		for (n=0; n < rmd.ctr.ctr1.count; n++) {
			struct replPropertyMetaData1 *omd = &rmd.ctr.ctr1.array[n];
			if (omd->local_usn > dsc->fromreqUSN) {
				const struct dsdb_attribute *a = dsdb_attribute_by_attributeID_id(dsc->schema,
										omd->attid);
				if (!dsc->localonly) {
					struct drsuapi_DsReplicaCursor *tab = dsc->cursors;
					uint32_t l;
					for (l=0; l < dsc->cursor_size; l++) {
						if (GUID_equal(&tab[l].source_dsa_invocation_id, &omd->originating_invocation_id) &&
								tab[l].highest_usn >= omd->originating_usn) {
							/*
							 * If we have in the uptodateness vector an entry
							 * with the same invocation id as the originating invocation
							 * and if the usn in the vector is greater or equal to
							 * the one in originating_usn, then it means that this entry
							 * has already been sent (from another DC) to the client
							 * no need to resend it one more time.
							 */
							goto skip;
						}
					}
					/* If we are here it's because we have a usn > (max(usn of vectors))*/
				}
				if (namereturned == false &&
						nameasked == true &&
						ldb_attr_cmp(a->lDAPDisplayName, "name") == 0) {
					namereturned = true;
					if (ldb_dn_compare(dsc->nc_root, msg->dn) == 0) {
						delta++;
					}
				}
				listAttr[j] = a->lDAPDisplayName;
				j++;
skip:
				continue;
			}
		}
		size = j;
	} else {
		size = 0;
		if (ldb_attr_in_list(req->op.search.attrs, "*") ||
				ldb_attr_in_list(req->op.search.attrs, "name")) {
			namereturned = true;
		}
	}


	/*
	 * Let's loop around the remaining elements
	 * to see which one are in the listAttr.
	 * If they are in this array it means that
	 * their localusn > usn from the request (in the cookie)
	 * if not we remove the attribute.
	 */
	for (i = msg->num_elements - 1; i >= 0; i--) {
		el = &(msg->elements[i]);
		attr = dsdb_attribute_by_lDAPDisplayName(dsc->schema,
				el->name);
		const char *ldapattrname = el->name;
		keep = false;

		if (attr->linkID & 1) {
			/*
			 * Attribute is a backlink so let's remove it
			 */
			continue;
		}

		if (ldb_attr_cmp(msg->elements[i].name,
						"replPropertyMetaData") == 0) {
			continue;
		}

		if ((attr->systemFlags & (DS_FLAG_ATTR_NOT_REPLICATED | DS_FLAG_ATTR_IS_CONSTRUCTED))) {
			if (ldb_attr_cmp(attr->lDAPDisplayName, "objectGUID") != 0 &&
					ldb_attr_cmp(attr->lDAPDisplayName, "parentGUID") != 0) {
				/*
				 * Attribute is constructed or not replicated, let's get rid of it
				 */
				continue;
			} else {
				/* Let's keep the attribute that we forced to be added
				 * even if they are not in the replicationMetaData
				 * or are just generated
				 */
				if (namereturned == false &&
					(ldb_attr_cmp(attr->lDAPDisplayName, "parentGUID") == 0)) {
					delta++;
					continue;
				}
				if (ldb_msg_add(newmsg, el, LDB_FLAG_MOD_ADD) != LDB_SUCCESS) {
					return ldb_error(ldb,
						LDB_ERR_OPERATIONS_ERROR,
						"Unable to add attribute");
				}
				talloc_steal(newmsg->elements, el->name);
				talloc_steal(newmsg->elements, el->values);
				continue;
			}
		}

		if (ldb_attr_cmp(msg->elements[i].name, rdn) == 0) {
			/*
			 * We have an attribute that is the same as the start of the RDN
			 * (ie. attribute CN with rdn CN=).
			 */
			continue;
		}

		if (ldb_attr_cmp(attr->lDAPDisplayName, "instanceType") == 0) {
			if (ldb_msg_add(newmsg, el, LDB_FLAG_MOD_ADD) != LDB_SUCCESS) {
				return ldb_error(ldb,
						LDB_ERR_OPERATIONS_ERROR,
						"Unable to add attribute");
			}
			talloc_steal(newmsg->elements, el->name);
			talloc_steal(newmsg->elements, el->values);
			continue;
		}
		/* For links, when our functional level > windows 2000
		 * we use the RMD_LOCAL_USN information to decide wether
		 * we return the attribute or not.
		 * For windows 2000 this information is in the replPropertyMetaData
		 * so it will be handled like any other replicated attribute
		 */

		if (dsc->functional_level > DS_DOMAIN_FUNCTION_2000 &&
				attr->linkID != 0 ) {
			int k;
			/*
			 * Elements for incremental changes on linked attributes
			 */
			struct ldb_message_element *el_incr_add = NULL;
			struct ldb_message_element *el_incr_del = NULL;
			/*
			 * Attribute is a forwardlink so let's remove it
			 */

			for (k = el->num_values -1; k >= 0; k--) {
				char *dn_ln;
				uint32_t flags = 0;
				uint32_t tmp_usn = 0;
				uint32_t tmp_usn2 = 0;
				struct GUID invocation_id = GUID_zero();
				struct dsdb_dn *dn = dsdb_dn_parse(msg, ldb, &el->values[k], attr->syntax->ldap_oid);
				struct ldb_dn *copydn;
				if (dn == NULL) {
					ldb_set_errstring(ldb, "Cannot parse DN");
					return ldb_module_done(dsc->req, NULL, NULL, LDB_ERR_OPERATIONS_ERROR);
				}

				copydn = ldb_dn_copy(msg, dn->dn);
				if (copydn == NULL) {
					ldb_oom(ldb);
				}

				status = dsdb_get_extended_dn_uint32(dn->dn, &tmp_usn, "RMD_LOCAL_USN");
				if (!NT_STATUS_IS_OK(status)) {
					talloc_free(dn);
					return ldb_module_done(dsc->req, NULL, NULL, LDB_ERR_OPERATIONS_ERROR);
				}
				status = dsdb_get_extended_dn_guid(dn->dn,  &invocation_id, "RMD_INVOCID");
				if (!NT_STATUS_IS_OK(status)) {
					talloc_free(dn);
					return ldb_module_done(dsc->req, NULL, NULL, LDB_ERR_OPERATIONS_ERROR);
				}

				status = dsdb_get_extended_dn_uint32(dn->dn, &flags, "RMD_FLAGS");
				if (!NT_STATUS_IS_OK(status)) {
					talloc_free(dn);
					return ldb_module_done(dsc->req, NULL, NULL, LDB_ERR_OPERATIONS_ERROR);
				}

				status = dsdb_get_extended_dn_uint32(dn->dn, &tmp_usn2, "RMD_ORIGINATING_USN");
				if (!NT_STATUS_IS_OK(status)) {
					talloc_free(dn);
					return ldb_module_done(dsc->req, NULL, NULL, LDB_ERR_OPERATIONS_ERROR);
				}

				ldb_dn_extended_filter(dn->dn, myaccept);
				dn_ln = ldb_dn_get_extended_linearized(dn, dn->dn, 1);
				if (dn_ln == NULL)
				{
					talloc_free(dn);
					ldb_set_errstring(ldb, "Cannot linearize dn");
					return ldb_module_done(dsc->req, NULL, NULL, LDB_ERR_OPERATIONS_ERROR);
				}

				talloc_free(el->values[k].data);
				el->values[k].data = (uint8_t*)talloc_steal(el->values, dn_ln);
				if (el->values[k].data == NULL) {
					talloc_free(dn);
					return ldb_module_done(dsc->req, NULL, NULL, LDB_ERR_OPERATIONS_ERROR);
				}
				el->values[k].length = strlen(dn_ln);


				if (tmp_usn > dsc->fromreqUSN) {
					if (!dsc->localonly) {
						struct drsuapi_DsReplicaCursor *tab = dsc->cursors;
						uint32_t l;

						for (l=0; l < dsc->cursor_size; l++) {
							if (GUID_equal(&tab[l].source_dsa_invocation_id, &invocation_id) &&
									tab[l].highest_usn >= tmp_usn2) {
								/*
								* If we have in the uptodateness vector an entry
								* with the same invocation id as the originating invocation
								* and if the usn in the vector is greater or equal to
								* the one in originating_usn, then it means that this entry
								* has already been sent (from another DC) to the client
								* no need to resend it one more time.
								*/
								goto skip_link;
							}
						}
						/* If we are here it's because we have a usn > (max(usn of vectors))*/
						keep = true;
					} else {
						keep = true;
					}
				/* If we are here it's because the link is more recent than either any
				 * originating usn or local usn
				 */

					if (dsc->linkIncrVal == true) {
						struct ldb_message_element *tmpel;
						if (flags & DSDB_RMD_FLAG_DELETED) {
							/* We have to check that the inactive link still point to an existing object */
							struct GUID guid;
							struct ldb_dn *tdn;
							int ret;

							status = dsdb_get_extended_dn_guid(copydn, &guid, "GUID");
							if (!NT_STATUS_IS_OK(status)) {
								DEBUG(0,(__location__ " Unable to extract GUID in linked attribute '%s' in '%s'\n",
									el->name, ldb_dn_get_linearized(copydn)));
								return ldb_operr(ldb);
							}
							ret = dsdb_module_dn_by_guid(dsc->module, newmsg, &guid, &tdn, req);
							if (ret == LDB_ERR_NO_SUCH_OBJECT) {
								DEBUG(2, (" Search of guid %s returned 0 objects, skipping it !\n",
											GUID_string(newmsg, &guid)));
								continue;
							} else if (ret != LDB_SUCCESS) {
								DEBUG(0, (__location__ " Search of guid %s failed with error code %d\n",
											GUID_string(newmsg, &guid),
											ret));
								continue;
							}
							tmpel = el_incr_del;
						} else {
							tmpel = el_incr_add;
						}

						if (tmpel == NULL) {
							tmpel = talloc_zero(newmsg, struct ldb_message_element);
							if (tmpel == NULL) {
								return ldb_oom(ldb);
							}
							tmpel->values = talloc_array(tmpel, struct ldb_val, 1);
							if (tmpel->values == NULL) {
								return ldb_oom(ldb);
							}
							if (flags & DSDB_RMD_FLAG_DELETED) {
								tmpel->name = talloc_asprintf(tmpel,
										"%s;range=0-0",
										el->name);
							}
							else {
								tmpel->name = talloc_asprintf(tmpel,
										"%s;range=1-1",
										el->name);
							}
							if (tmpel->name == NULL) {
								return ldb_oom(ldb);
							}
							tmpel->num_values = 1;
						} else {
							tmpel->num_values += 1;
							tmpel->values = talloc_realloc(tmpel,
												tmpel->values,
												struct ldb_val,
												tmpel->num_values);
							if (tmpel->values == NULL) {
								return ldb_oom(ldb);
							}
							tmpel = tmpel;
						}
						tmpel->values[tmpel->num_values -1].data =talloc_steal(tmpel->values, el->values[k].data);
						tmpel->values[tmpel->num_values -1].length = el->values[k].length;

						if (flags & DSDB_RMD_FLAG_DELETED) {
							el_incr_del = tmpel;
						} else {
							el_incr_add = tmpel;
						}
					}
				}

				if (dsc->linkIncrVal == false) {
					if (flags & DSDB_RMD_FLAG_DELETED) {
						if (k < (el->num_values - 1)) {
							memmove(el->values + k,
									el->values + (k + 1),
									((el->num_values - 1) - k)*sizeof(*el->values));
						}
						el->num_values--;
					}
				}
skip_link:
				talloc_free(dn);

			}
			if (keep == true) {
				if (dsc->linkIncrVal == false) {
					if (ldb_msg_add(newmsg, el, LDB_FLAG_MOD_ADD) != LDB_SUCCESS) {
						return ldb_error(ldb,
							LDB_ERR_OPERATIONS_ERROR,
							"Unable to add attribute");
					}
					talloc_steal(newmsg->elements, el->name);
					talloc_steal(newmsg->elements, el->values);
				} else {
					if (el_incr_del) {
						if (ldb_msg_add(newmsg, el_incr_del, LDB_FLAG_MOD_ADD))
							return ldb_error(ldb,
								LDB_ERR_OPERATIONS_ERROR,
								"Unable to add attribute");
					}
					if (el_incr_add) {
						if (ldb_msg_add(newmsg, el_incr_add, LDB_FLAG_MOD_ADD))
							return ldb_error(ldb,
								LDB_ERR_OPERATIONS_ERROR,
								"Unable to add attribute");
					}
				}
			}
			continue;
		}

		if (listAttr) {
			for (j=0; j<size; j++) {
			/*
				* We mark attribute that has already been seen well
				* as seen. So that after attribute that are still in
				* listAttr are attributes that has been modified after
				* the requested USN but not present in the attributes
				* returned by the ldb search.
				* That is to say attributes that have been removed
				*/
				if (listAttr[j] && ldb_attr_cmp(listAttr[j], ldapattrname) == 0) {
					listAttr[j] = NULL;
					keep = true;
					continue;
				}
			}
		} else {
			keep = true;
		}

		if (keep == true) {
			if (ldb_msg_add(newmsg, el, LDB_FLAG_MOD_ADD) != LDB_SUCCESS) {
				return ldb_error(ldb,
					LDB_ERR_OPERATIONS_ERROR,
					"Unable to add attribute");
			}
			talloc_steal(newmsg->elements, el->name);
			talloc_steal(newmsg->elements, el->values);
			continue;
		}
	}
	talloc_steal(newmsg->elements, msg);

	/*
	 * Here we run through the list of attributes returned
	 * in the propertyMetaData.
	 * Entries of this list have usn > requested_usn,
	 * entries that are also present in the message have been
	 * replaced by NULL, so at this moment the list contains
	 * only elements that have a usn > requested_usn and that
	 * haven't been seen. It's attributes that were removed.
	 * We add them to the message like empty elements.
	 */
	for (j=0; j<size; j++) {
		if (listAttr[j] && (
				ldb_attr_in_list(req->op.search.attrs, "*") ||
				ldb_attr_in_list(req->op.search.attrs, listAttr[j])) &&
				(ldb_attr_cmp(listAttr[j], rdn) != 0) &&
				(ldb_attr_cmp(listAttr[j], "instanceType") != 0)) {
			ldb_msg_add_empty(newmsg, listAttr[j], LDB_FLAG_MOD_DELETE, NULL);
		}
	}
	talloc_free(listAttr);

	if ((newmsg->num_elements - ( dsc->nbDefaultAttrs - delta)) > 0) {
		/*
		 * After cleaning attributes there is still some attributes that were not added just
		 * for the purpose of the control (objectGUID, instanceType, ...)
		 */

		newmsg->dn = talloc_steal(newmsg, msg->dn);
		if (val > dsc->highestUSN) {
			dsc->highestUSN = val;
		}
		return ldb_module_send_entry(dsc->req, newmsg, controls);
	} else {
		talloc_free(newmsg);
		return LDB_SUCCESS;
	}
}


static int dirsync_create_vector(struct ldb_request *req,
					struct ldb_reply *ares,
					struct dirsync_context *dsc,
					struct ldapControlDirSyncCookie *cookie,
					struct ldb_context *ldb)
{
	struct ldb_result *resVector;
	const char* attrVector[] = {"replUpToDateVector", NULL };
	uint64_t highest_usn;
	uint32_t count = 1;
	int ret;
	struct drsuapi_DsReplicaCursor *tab;

	ret = ldb_sequence_number(ldb, LDB_SEQ_HIGHEST_SEQ, &highest_usn);
	if (ret != LDB_SUCCESS) {
		return ldb_error(ldb, LDB_ERR_OPERATIONS_ERROR, "Unable to get highest USN from current NC");
	}

	/* If we have a full answer then the highest USN
	 * is not the highest USN from the result set but the
	 * highest of the naming context, unless the sequence is not updated yet.
	 */
	if (highest_usn > dsc->highestUSN) {
		dsc->highestUSN = highest_usn;
	}


	ret = dsdb_module_search_dn(dsc->module, dsc, &resVector,
			dsc->nc_root,
			attrVector,
			DSDB_FLAG_NEXT_MODULE, req);
	if (ret != LDB_SUCCESS) {
		return ldb_error(ldb, LDB_ERR_OPERATIONS_ERROR,
				 "Unable to get replUpToDateVector for current NC");
	}

	if (resVector->count != 0) {
		DATA_BLOB blob;
		uint32_t i;
		struct ldb_message_element *el = ldb_msg_find_element(resVector->msgs[0], "replUpToDateVector");
		if (el) {
			enum ndr_err_code ndr_err;
			struct replUpToDateVectorBlob utd;
			blob.data = el->values[0].data;
			blob.length = el->values[0].length;
			ndr_err = ndr_pull_struct_blob(&blob, dsc, &utd,
						(ndr_pull_flags_fn_t)ndr_pull_replUpToDateVectorBlob);

			if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
				return ldb_error(ldb, LDB_ERR_OPERATIONS_ERROR,
						"Unable to pull replUpToDateVectorBlob structure");
			}


			count += utd.ctr.ctr2.count;
			tab = talloc_array(cookie, struct drsuapi_DsReplicaCursor, count);
			if (tab == NULL) {
				return ldb_oom(ldb);
			}
			for (i=1; i < count; i++) {
				memset(&tab[i], 0, sizeof(struct drsuapi_DsReplicaCursor));
				tab[i].highest_usn = utd.ctr.ctr2.cursors[i-1].highest_usn;
				tab[i].source_dsa_invocation_id = utd.ctr.ctr2.cursors[i-1].source_dsa_invocation_id;
			}
		} else {
			tab = talloc_array(cookie, struct drsuapi_DsReplicaCursor, count);
			if (tab == NULL) {
				return ldb_oom(ldb);
			}
		}
	} else {
		/*
		 * No replUpToDateVector ? it happens quite often (1 DC,
		 * other DCs didn't update ...
		 */
		tab = talloc_array(cookie, struct drsuapi_DsReplicaCursor, count);
		if (tab == NULL) {
			return ldb_oom(ldb);
		}
	}
	/* Our vector is always the first */
	tab[0].highest_usn = dsc->highestUSN;
	tab[0].source_dsa_invocation_id = *(dsc->our_invocation_id);


	/* We have to add the updateness vector that we have*/
	/* Version is always 1 in dirsync cookies */
	cookie->blob.extra.uptodateness_vector.version = 1;
	cookie->blob.extra.uptodateness_vector.reserved = 0;
	cookie->blob.extra.uptodateness_vector.ctr.ctr1.count = count;
	cookie->blob.extra.uptodateness_vector.ctr.ctr1.reserved = 0;
	cookie->blob.extra.uptodateness_vector.ctr.ctr1.cursors = tab;

	return LDB_SUCCESS;
}

static int dirsync_search_callback(struct ldb_request *req, struct ldb_reply *ares)
{
	int ret;
	struct dirsync_context *dsc;
	struct ldb_result *res, *res2;
	struct ldb_dirsync_control *control;
	struct ldapControlDirSyncCookie *cookie;
	struct ldb_context *ldb;
	struct ldb_dn *dn;
	struct ldb_val *val;
	DATA_BLOB *blob;
	NTTIME now;
	const char *attrs[] = { "objectGUID", NULL };
	enum ndr_err_code ndr_err;
	char *tmp;
	uint32_t flags;

	dsc = talloc_get_type_abort(req->context, struct dirsync_context);
	ldb = ldb_module_get_ctx(dsc->module);
	if (!ares) {
		return ldb_module_done(dsc->req, NULL, NULL,
				       LDB_ERR_OPERATIONS_ERROR);
	}
	if (ares->error != LDB_SUCCESS) {
		return ldb_module_done(dsc->req, ares->controls,
				       ares->response, ares->error);
	}

	switch (ares->type) {
	case LDB_REPLY_ENTRY:
		return dirsync_filter_entry(req, ares->message, ares->controls, dsc, false);

	case LDB_REPLY_REFERRAL:
		/* Skip the ldap(s):// so up to 8 chars,
		 * we don't care to be precise as the goal is to be in
		 * the name of DC, then we search the next '/'
		 * as it will be the last char before the DN of the referal
		 */
		if (strncmp(ares->referral, "ldap://", 7) == 0) {
			tmp = ares->referral + 7;
		} else if (strncmp(ares->referral, "ldaps://", 8) == 0) {
			tmp = ares->referral + 8;
		} else {
			return ldb_operr(ldb);
		}

		tmp = strchr(tmp, '/');
		tmp++;

		dn = ldb_dn_new(dsc, ldb, tmp);
		if (dn == NULL) {
			return ldb_oom(ldb);
		}

		flags = DSDB_FLAG_NEXT_MODULE |
			DSDB_SEARCH_SHOW_DELETED |
			DSDB_SEARCH_SHOW_EXTENDED_DN;

		if (dsc->assystem) {
			flags = flags | DSDB_FLAG_AS_SYSTEM;
		}

		ret = dsdb_module_search_tree(dsc->module, dsc, &res,
					dn, LDB_SCOPE_BASE,
					req->op.search.tree,
					req->op.search.attrs,
					flags, req);

		if (ret != LDB_SUCCESS) {
			talloc_free(dn);
			return ret;
		}

		if (res->count > 1) {
			char *ldbmsg = talloc_asprintf(dn, "LDB returned more than result for dn: %s", tmp);
			if (ldbmsg) {
				ldb_set_errstring(ldb, ldbmsg);
			}
			talloc_free(dn);
			return ldb_module_done(dsc->req, NULL, NULL, LDB_ERR_OPERATIONS_ERROR);
		} else if (res->count == 0) {
			/* if nothing is returned then it means that we don't
			* have access to it.
			*/
			return LDB_SUCCESS;
		}

		talloc_free(dn);
		/*
		 * Fetch the objectGUID of the root of current NC
		 */
		ret = dsdb_module_search_dn(dsc->module, dsc, &res2,
					req->op.search.base,
					attrs,
					DSDB_FLAG_NEXT_MODULE, req);

		if (ret != LDB_SUCCESS) {
			return ret;
		}
		if (res2->msgs[0]->num_elements != 1) {
			ldb_set_errstring(ldb,
					  "More than 1 attribute returned while looking for objectGUID");
			return ldb_module_done(dsc->req, NULL, NULL, LDB_ERR_OPERATIONS_ERROR);
		}

		val = res2->msgs[0]->elements[0].values;
		ret = ldb_msg_add_value(res->msgs[0], "parentGUID", val, NULL);
		/*
		 * It *very* important to steal otherwise as val is in a subcontext
		 * related to res2, when the value will be one more time stolen
		 * it's elements[x].values that will be stolen, so it's important to
		 * recreate the context hierrachy as if it was done from a ldb_request
		 */
		talloc_steal(res->msgs[0]->elements[0].values, val);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
		return dirsync_filter_entry(req, res->msgs[0], res->controls, dsc, true);

	case LDB_REPLY_DONE:
		/*
		 * Let's add our own control
		 */

		control = talloc_zero(ares->controls, struct ldb_dirsync_control);
		if (control == NULL) {
			return ldb_oom(ldb);
		}

		/*
		 * When outputing flags is used to say more results.
		 * For the moment we didn't honnor the size info */

		control->flags = 0;

		/*
		 * max_attribute is unused cf. 3.1.1.3.4.1.3 LDAP_SERVER_DIRSYNC_OID in MS-ADTS
		 */

		control->max_attributes = 0;
		cookie = talloc_zero(control, struct ldapControlDirSyncCookie);
		if (cookie == NULL) {
			return ldb_oom(ldb);
		}

		if (!dsc->partial) {
			ret = dirsync_create_vector(req, ares, dsc, cookie, ldb);
			if (ret != LDB_SUCCESS) {
				return ldb_module_done(dsc->req, NULL, NULL, ret);
			}
		}

		unix_to_nt_time(&now, time(NULL));
		cookie->blob.time = now;
		cookie->blob.highwatermark.highest_usn = dsc->highestUSN;
		cookie->blob.highwatermark.tmp_highest_usn = dsc->highestUSN;
		cookie->blob.guid1 = *(dsc->our_invocation_id);

		blob = talloc_zero(control, DATA_BLOB);
		if (blob == NULL) {
			return ldb_oom(ldb);
		}

		ndr_err = ndr_push_struct_blob(blob, blob, cookie,
						(ndr_push_flags_fn_t)ndr_push_ldapControlDirSyncCookie);

		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			ldb_set_errstring(ldb, "Can't marshall ldapControlDirSyncCookie struct");
			return ldb_module_done(dsc->req, NULL, NULL, LDB_ERR_OPERATIONS_ERROR);
		}
		control->cookie = (char *)blob->data;
		control->cookie_len = blob->length;
		ldb_reply_add_control(ares, LDB_CONTROL_DIRSYNC_OID, true, control);

		return ldb_module_done(dsc->req, ares->controls,
				       ares->response, LDB_SUCCESS);

	}
	return LDB_SUCCESS;
}

static int dirsync_ldb_search(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_control *control;
	struct ldb_result *acl_res;
	struct ldb_dirsync_control *dirsync_ctl;
	struct ldb_request *down_req;
	struct dirsync_context *dsc;
	struct ldb_context *ldb;
	struct ldb_parse_tree *new_tree = req->op.search.tree;
	uint32_t flags = 0;
	enum ndr_err_code ndr_err;
	DATA_BLOB blob;
	const char **attrs;
	int ret;


	if (ldb_dn_is_special(req->op.search.base)) {
		return ldb_next_request(module, req);
	}

	/*
	 * check if there's an extended dn control
	 */
	control = ldb_request_get_control(req, LDB_CONTROL_DIRSYNC_OID);
	if (control == NULL) {
		/* not found go on */
		return ldb_next_request(module, req);
	}

	ldb = ldb_module_get_ctx(module);
	/*
	 * This control must always be critical otherwise we return PROTOCOL error
	 */
	if (!control->critical) {
		return ldb_operr(ldb);
	}

	dsc = talloc_zero(req, struct dirsync_context);
	if (dsc == NULL) {
		return ldb_oom(ldb);
	}
	dsc->module = module;
	dsc->req = req;
	dsc->nbDefaultAttrs = 0;


	dirsync_ctl = talloc_get_type(control->data, struct ldb_dirsync_control);
	if (dirsync_ctl == NULL) {
		return ldb_error(ldb, LDB_ERR_PROTOCOL_ERROR, "No data in dirsync control");
	}

	ret = dsdb_find_nc_root(ldb, dsc, req->op.search.base, &dsc->nc_root);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	if (ldb_dn_compare(dsc->nc_root, req->op.search.base) != 0) {
		if (dirsync_ctl->flags & LDAP_DIRSYNC_OBJECT_SECURITY) {
			return ldb_error(ldb, LDB_ERR_UNWILLING_TO_PERFORM,
				 "DN is not one of the naming context");
		}
		else {
			return ldb_error(ldb, LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS,
				 "dN is not one of the naming context");
		}
	}

	if (!(dirsync_ctl->flags & LDAP_DIRSYNC_OBJECT_SECURITY)) {
		struct dom_sid *sid;
		struct security_descriptor *sd = NULL;
		const char *acl_attrs[] = { "nTSecurityDescriptor", "objectSid", NULL };
		/*
		 * If we don't have the flag and if we have the "replicate directory change" granted
		 * then we upgrade ourself to system to not be blocked by the acl
		 */
		/* FIXME we won't check the replicate directory change filtered attribute set
		 * it should be done so that if attr is not empty then we check that the user
		 * has also this right
		 */

		/*
		 * First change to system to get the SD of the root of current NC
		 * if we don't the acl_read will forbid us the right to read it ...
		 */
		ret = dsdb_module_search_dn(module, dsc, &acl_res,
					req->op.search.base,
					acl_attrs,
					DSDB_FLAG_NEXT_MODULE|DSDB_FLAG_AS_SYSTEM, req);

		if (ret != LDB_SUCCESS) {
			return ret;
		}

		sid = samdb_result_dom_sid(dsc, acl_res->msgs[0], "objectSid");
		/* sid can be null ... */
		ret = dsdb_get_sd_from_ldb_message(ldb_module_get_ctx(module), acl_res, acl_res->msgs[0], &sd);

		if (ret != LDB_SUCCESS) {
			return ret;
		}
		ret = acl_check_extended_right(dsc, sd, acl_user_token(module), GUID_DRS_GET_CHANGES, SEC_ADS_CONTROL_ACCESS, sid);

		if (ret == LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS) {
			return ret;
		}
		dsc->assystem = true;
		ret = ldb_request_add_control(req, LDB_CONTROL_AS_SYSTEM_OID, false, NULL);

		if (ret != LDB_SUCCESS) {
			return ret;
		}
		talloc_free(acl_res);
	} else {
		flags |= DSDB_ACL_CHECKS_DIRSYNC_FLAG;

		if (ret != LDB_SUCCESS) {
			return ret;
		}

	}

	dsc->functional_level = dsdb_functional_level(ldb);

	if (req->op.search.attrs) {
		attrs = ldb_attr_list_copy(dsc, req->op.search.attrs);
		if (attrs == NULL) {
			return ldb_oom(ldb);
		}
		/*
		* Check if we have only "dn" as attribute, if so then
		* treat as if "*" was requested
		*/
		if (attrs && attrs[0]) {
			if (ldb_attr_cmp(attrs[0], "dn") == 0 && !attrs[1]) {
				attrs = talloc_array(dsc, const char*, 2);
				if (attrs == NULL) {
					return ldb_oom(ldb);
				}
				attrs[0] = "*";
				attrs[1] = NULL;
			}
		}
		/*
		 * When returning all the attributes return also the SD as
		 * Windws do so.
		 */
		if (ldb_attr_in_list(attrs, "*")) {
			struct ldb_sd_flags_control *sdctr = talloc_zero(dsc, struct ldb_sd_flags_control);
			sdctr->secinfo_flags = 0xF;
			ret = ldb_request_add_control(req, LDB_CONTROL_SD_FLAGS_OID, false, sdctr);
			if (ret != LDB_SUCCESS) {
				return ret;
			}
			attrs = ldb_attr_list_copy_add(dsc, attrs, "parentGUID");
			if (attrs == NULL) {
				return ldb_oom(ldb);
			}
			attrs = ldb_attr_list_copy_add(dsc, attrs, "replPropertyMetaData");
			if (attrs == NULL) {
				return ldb_oom(ldb);
			}
			/*
			* When no attributes are asked we in anycase expect at least 3 attributes:
			* * instanceType
			* * objectGUID
			* * parentGUID
			*/

			dsc->nbDefaultAttrs = 3;
		} else {
			/*
			 * We will need this two attributes in the callback
			 */
			attrs = ldb_attr_list_copy_add(dsc, attrs, "usnChanged");
			if (attrs == NULL) {
				return ldb_operr(ldb);
			}
			attrs = ldb_attr_list_copy_add(dsc, attrs, "replPropertyMetaData");
			if (attrs == NULL) {
				return ldb_operr(ldb);
			}

			if (!ldb_attr_in_list(attrs, "instanceType")) {
				attrs = ldb_attr_list_copy_add(dsc, attrs, "instanceType");
				if (attrs == NULL) {
					return ldb_operr(ldb);
				}
				dsc->nbDefaultAttrs++;
			}

			if (!ldb_attr_in_list(attrs, "objectGUID")) {
				attrs = ldb_attr_list_copy_add(dsc, attrs, "objectGUID");
				if (attrs == NULL) {
					return ldb_operr(ldb);
				}
			}
			/*
			 * Always increment the number of asked attributes as we don't care if objectGUID was asked
			 * or not for counting the number of "real" attributes returned.
			 */
			dsc->nbDefaultAttrs++;

			if (!ldb_attr_in_list(attrs, "parentGUID")) {
				attrs = ldb_attr_list_copy_add(dsc, attrs, "parentGUID");
				if (attrs == NULL) {
					return ldb_operr(ldb);
				}
			}
			dsc->nbDefaultAttrs++;

		}
	} else {
		struct ldb_sd_flags_control *sdctr = talloc_zero(dsc, struct ldb_sd_flags_control);
		sdctr->secinfo_flags = 0xF;
		ret = ldb_request_add_control(req, LDB_CONTROL_SD_FLAGS_OID, false, sdctr);
		attrs = talloc_array(dsc, const char*, 4);
		if (attrs == NULL) {
			return ldb_operr(ldb);
		}
		attrs[0] = "*";
		attrs[1] = "parentGUID";
		attrs[2] = "replPropertyMetaData";
		attrs[3] = NULL;
		if (ret != LDB_SUCCESS) {
			return ret;
		}
		/*
		 * When no attributes are asked we in anycase expect at least 3 attributes:
		 * * instanceType
		 * * objectGUID
		 * * parentGUID
		 */

		dsc->nbDefaultAttrs = 3;
	}

	if (!ldb_request_get_control(req, LDB_CONTROL_EXTENDED_DN_OID)) {
		ret = ldb_request_add_control(req, LDB_CONTROL_EXTENDED_DN_OID, false, NULL);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
		dsc->noextended = true;
	}

	if (ldb_request_get_control(req, LDB_CONTROL_REVEAL_INTERNALS) == NULL) {
		ret = ldb_request_add_control(req, LDB_CONTROL_REVEAL_INTERNALS, false, NULL);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	if (ldb_request_get_control(req, LDB_CONTROL_SHOW_RECYCLED_OID) == NULL) {
		ret = ldb_request_add_control(req, LDB_CONTROL_SHOW_RECYCLED_OID, false, NULL);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	if (ldb_request_get_control(req, LDB_CONTROL_SHOW_DELETED_OID) == NULL) {
		ret = ldb_request_add_control(req, LDB_CONTROL_SHOW_DELETED_OID, false, NULL);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	if (dirsync_ctl->flags & LDAP_DIRSYNC_INCREMENTAL_VALUES) {
		dsc->linkIncrVal = true;
	} else {
		dsc->linkIncrVal = false;
	}

	dsc->our_invocation_id = samdb_ntds_invocation_id(ldb);
	if (dsc->our_invocation_id == NULL) {
		return ldb_operr(ldb);
	}

	if (dirsync_ctl->cookie_len > 0) {
		struct ldapControlDirSyncCookie cookie;

		blob.data = (uint8_t *)dirsync_ctl->cookie;
		blob.length = dirsync_ctl->cookie_len;
		ndr_err = ndr_pull_struct_blob(&blob, dsc, &cookie,
						(ndr_pull_flags_fn_t)ndr_pull_ldapControlDirSyncCookie);

		/* If we can't unmarshall the cookie into the correct structure we return
		* unsupported critical extension
		*/
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			return ldb_error(ldb, LDB_ERR_UNSUPPORTED_CRITICAL_EXTENSION,
					 "Unable to unmarshall cookie as a ldapControlDirSyncCookie structure");
		}

		/*
		* Let's search for the max usn withing the cookie
		*/
		if (GUID_equal(&(cookie.blob.guid1), dsc->our_invocation_id)) {
			/*
			 * Ok, it's our invocation ID so we can treat the demand
			 * Let's take the highest usn from (tmp)highest_usn
			 */
			dsc->fromreqUSN = cookie.blob.highwatermark.tmp_highest_usn;
			dsc->localonly = true;

			if (cookie.blob.highwatermark.highest_usn > cookie.blob.highwatermark.tmp_highest_usn) {
				dsc->fromreqUSN = cookie.blob.highwatermark.highest_usn;
			}
		} else {
			dsc->localonly = false;
		}
		if (cookie.blob.extra_length > 0 &&
				cookie.blob.extra.uptodateness_vector.ctr.ctr1.count > 0) {
			struct drsuapi_DsReplicaCursor cursor;
			uint32_t p;
			for (p=0; p < cookie.blob.extra.uptodateness_vector.ctr.ctr1.count; p++) {
				cursor = cookie.blob.extra.uptodateness_vector.ctr.ctr1.cursors[p];
				if (GUID_equal( &(cursor.source_dsa_invocation_id), dsc->our_invocation_id)) {
					if (cursor.highest_usn > dsc->fromreqUSN) {
						dsc->fromreqUSN = cursor.highest_usn;
					}
				}
			}
			dsc->cursors = talloc_steal(dsc,
					cookie.blob.extra.uptodateness_vector.ctr.ctr1.cursors);
			if (dsc->cursors == NULL) {
				return ldb_oom(ldb);
			}
			dsc->cursor_size = p;
		}
	}

	DEBUG(4, ("Dirsync: searching with min usn > %llu\n",
				(long long unsigned int)dsc->fromreqUSN));
	if (dsc->fromreqUSN > 0) {
		/* FIXME it would be better to use PRId64 */
		char *expression = talloc_asprintf(dsc, "(&%s(uSNChanged>=%llu))",
				                        ldb_filter_from_tree(dsc,
				                             req->op.search.tree),
				                        (long long unsigned int)(dsc->fromreqUSN + 1));

		if (expression == NULL) {
			return ldb_oom(ldb);
		}
		new_tree = ldb_parse_tree(req, expression);
		if (new_tree == NULL) {
			return ldb_error(ldb, LDB_ERR_OPERATIONS_ERROR,
					"Problem while parsing tree");
		}

	}
	/*
	 * Remove our control from the list of controls
	 */
	if (!ldb_save_controls(control, req, NULL)) {
		return ldb_operr(ldb);
	}
	dsc->schema = dsdb_get_schema(ldb, dsc);
	/*
	 * At the begining we make the hypothesis that we will return a complete
	 * result set
	 */

	dsc->partial = false;

	/*
	 * 3.1.1.3.4.1.3 of MS-ADTS.pdf specify that if the scope is not subtree
	 * we treat the search as if subtree was specified
	 */

	ret = ldb_build_search_req_ex(&down_req, ldb, dsc,
				      req->op.search.base,
				      LDB_SCOPE_SUBTREE,
				      new_tree,
				      attrs,
				      req->controls,
				      dsc, dirsync_search_callback,
				      req);
	ldb_req_set_custom_flags(down_req, flags);
	LDB_REQ_SET_LOCATION(down_req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	/* perform the search */
	return ldb_next_request(module, down_req);
}

static int dirsync_ldb_init(struct ldb_module *module)
{
	int ret;

	ret = ldb_mod_register_control(module, LDB_CONTROL_DIRSYNC_OID);
	if (ret != LDB_SUCCESS) {
		ldb_debug(ldb_module_get_ctx(module), LDB_DEBUG_ERROR,
			"dirsync: Unable to register control with rootdse!\n");
		return ldb_operr(ldb_module_get_ctx(module));
	}

	return ldb_next_init(module);
}

static const struct ldb_module_ops ldb_dirsync_ldb_module_ops = {
	.name		   = "dirsync",
	.search            = dirsync_ldb_search,
	.init_context	   = dirsync_ldb_init,
};

/*
  initialise the module
 */
_PUBLIC_ int ldb_dirsync_module_init(const char *version)
{
	int ret;
	LDB_MODULE_CHECK_VERSION(version);
	ret = ldb_register_module(&ldb_dirsync_ldb_module_ops);
	return ret;
}
