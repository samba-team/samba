/*
 *  Unix SMB/CIFS implementation.
 *  LDAP backend for printing db's
 *  Copyright (C) Volker Lendecke          2004
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "includes.h"

struct prldap_state {
	BOOL initialized;
	struct smbldap_state *smbldap_state;
	TALLOC_CTX *mem_ctx;
};

static struct prldap_state ldap_conn;

static BOOL init_ldap_conn(void)
{
	NTSTATUS result;

	if (ldap_conn.initialized)
		return True;

	ldap_conn.mem_ctx = talloc_init("prldap ldap_conn");

	if (ldap_conn.mem_ctx == NULL) {
		DEBUG(0, ("out of memory\n"));
		return False;
	}

	result = smbldap_init(ldap_conn.mem_ctx, "ldap://localhost/",
			      &ldap_conn.smbldap_state);

	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(3, ("Could not open LDAP connection\n"));
		talloc_destroy(ldap_conn.mem_ctx);
		return False;
	}

	{
		LDAPMessage *msg = NULL;
		int rc = smbldap_search(ldap_conn.smbldap_state, "",
					LDAP_SCOPE_BASE, "(objectclass=*)",
					NULL, 0, &msg);
		if (rc == LDAP_SUCCESS)
			ldap_msgfree(msg);
	}

	ldap_conn.initialized = True;
	return True;
}

static BOOL pack_devicemode_alloc(NT_DEVICEMODE *nt_devmode,
				  char **buf, int *buflen)
{
	*buflen = pack_devicemode(nt_devmode, NULL, 0);

	*buf = malloc(*buflen);

	if (*buf == NULL)
		return False;

	if (pack_devicemode(nt_devmode, *buf, *buflen) != *buflen) {
		DEBUG(0, ("devicemode encoded twice gives different "
			  "lengths\n"));
		return False;
	}

	return True;
}

#define ADD_TO_ARRAY_TALLOC(mem_ctx, elem, array, num) \
do { \
       *(array) = talloc_realloc(mem_ctx, (*(array)), \
                                 ((*(num)+1) * sizeof(**(array)))); \
       if ((*(array)) != NULL) { \
       (*(array))[*(num)] = (elem); \
       (*(num)) += 1; } \
} while (0)

struct ldap_attribute {
	const char *name;
	int num_values;
	DATA_BLOB *values;
};

struct ldap_entry {
	TALLOC_CTX *mem_ctx;
	BOOL has_error;
	const char *dn;
	const char *filter;
	const char *suffix;
	int num_attribs;
	struct ldap_attribute *attribs;
};

static char *ldaperr(LDAP *ld)
{
	static fstring error;
	char *ldap_error = NULL;
	if (ldap_get_option(ld, LDAP_OPT_ERROR_STRING, &ldap_error) != 0) {
		fstrcpy(error, "ldap_get_option failed");
		return error;
	}
	if (ldap_error == NULL) {
		fstrcpy(error, "no ldap_error");
		return error;
	}
	fstrcpy(error, ldap_error);
	ldap_memfree(ldap_error);
	return error;
}

static struct ldap_entry *ldap_entry_init(void)
{
	struct ldap_entry *result;
	TALLOC_CTX *mem_ctx;

	mem_ctx = talloc_init("ldap_entry");
	if (mem_ctx == NULL)
		return NULL;

	result = talloc(mem_ctx, sizeof(struct ldap_entry));
	if (result == NULL) {
		talloc_destroy(mem_ctx);
		return NULL;
	}

	ZERO_STRUCTP(result);

	result->mem_ctx = mem_ctx;

	return result;
}

static void ldapmsg2entry(LDAP *ld, LDAPMessage *msg,
			  struct ldap_entry *result)
{
	char *dn;
	BerElement *be;

	char *attrname;

	dn = ldap_get_dn(ld, msg);
	if (dn == NULL) {
		DEBUG(10, ("Could not get dn: %s\n", ldaperr(ld)));
		return;
	}

	result->dn = talloc_strdup(result->mem_ctx, dn);
	ldap_memfree(dn);

	attrname = ldap_first_attribute(ld, msg, &be);

	while (attrname != NULL) {
		struct ldap_attribute attribute;
		struct berval **values;
		int i;

		values = ldap_get_values_len(ld, msg, attrname);
		if (values == NULL)
			goto next_attr;

		attribute.num_values = ldap_count_values_len(values);
		if (attribute.num_values == 0) {
			ldap_value_free_len(values);
			goto next_attr;
		}

		attribute.name = talloc_strdup(result->mem_ctx, attrname);
		if (attribute.name == NULL)
			return;

		attribute.values = talloc(result->mem_ctx,
					  attribute.num_values *
					  sizeof(DATA_BLOB));
		if (attribute.values == NULL)
			return;

		for (i=0; i<attribute.num_values; i++) {
			attribute.values[i] =
				data_blob_talloc(result->mem_ctx,
						 values[i]->bv_val,
						 values[i]->bv_len);
			if (attribute.values[i].data == NULL)
				return;
		}

		ldap_value_free_len(values);

		ADD_TO_ARRAY_TALLOC(result->mem_ctx, attribute,
				    &result->attribs, &result->num_attribs);

		result->has_error |= (result->attribs == NULL);

	next_attr:
		ldap_memfree(attrname);
		attrname = ldap_next_attribute(ld, msg, be);
	}

	if (be != NULL)
		ber_free(be, 0);

	return;
}

static struct ldap_attribute *ldap_entry_find_attrib(struct ldap_entry *entry,
						     const char *attrname)
{
	int i;

	for (i=0; i<entry->num_attribs; i++) {
		if (strcmp(entry->attribs[i].name, attrname) == 0)
			return &(entry->attribs[i]);
	}
	return NULL;
}

static void ldap_entry_bin(struct ldap_entry *entry, const char *attrname,
			   const void *val, int len)
{
	struct ldap_attribute *attribute;
	DATA_BLOB value;

	if (entry->has_error)
		return;

	if (len == 0)
		return;

	attribute = ldap_entry_find_attrib(entry, attrname);

	if (attribute == NULL) {
		struct ldap_attribute new_attrib;
		new_attrib.name = talloc_strdup(entry->mem_ctx, attrname);
		new_attrib.num_values = 0;
		new_attrib.values = NULL;
		ADD_TO_ARRAY_TALLOC(entry->mem_ctx, new_attrib,
				    &entry->attribs, &entry->num_attribs);

		if (entry->attribs == NULL) {
			entry->has_error = True;
			return;
		}

		attribute = &(entry->attribs[entry->num_attribs-1]);
	}

	value = data_blob_talloc(entry->mem_ctx, val, len);

	ADD_TO_ARRAY_TALLOC(entry->mem_ctx, value, &attribute->values,
			    &attribute->num_values);

	entry->has_error = (attribute->values == NULL);
		
	return;
}

static void ldap_entry_string(struct ldap_entry *entry,
			      const char *attrname, const char *value)
{
	ldap_entry_bin(entry, attrname, value, strlen(value));
}

static void ldap_entry_int(struct ldap_entry *entry,
			   const char *attrname, int value)
{
	fstring str;
	fstr_sprintf(str, "%d", value);
	ldap_entry_string(entry, attrname, str);
}

static void blob_to_fstring(DATA_BLOB src, fstring dst)
{
	dst[0] = '\0';

	if (src.length >= sizeof(fstring))
		return;

	memcpy(dst, src.data, src.length);
	dst[src.length] = '\0';
}

static DATA_BLOB ldap_fetch_bin(struct ldap_entry *entry,
				const char *attrname)
{
	struct ldap_attribute *attr = ldap_entry_find_attrib(entry, attrname);

	if ((attr == NULL) || (attr->num_values != 1)) {
		DATA_BLOB result;
		result.data = NULL;
		result.length = 0;
		return result;
	}

	return attr->values[0];
}

static void ldap_fetch_fstring(struct ldap_entry *entry, const char *attrname,
			       fstring result)
{
	struct ldap_attribute *attr = ldap_entry_find_attrib(entry, attrname);

	result[0] = '\0';

	if ((attr == NULL) || (attr->num_values != 1))
		return;

	blob_to_fstring(attr->values[0], result);
}

static void ldap_fetch_uint32(struct ldap_entry *entry, const char *attrname,
			      uint32 *result)
{
	fstring tmp;
	char *end;

	*result = 0;

	ldap_fetch_fstring(entry, attrname, tmp);

	if (tmp[0] == '\0')
		return;

	*result = strtoul(tmp, &end, 10);

	if (*end != '\0')
		*result = 0;
}

static void ldap_fetch_fstrings(struct ldap_entry *entry, const char *attrname,
				fstring **result)
{
	struct ldap_attribute *attr = ldap_entry_find_attrib(entry, attrname);
	int i, num;

	if (attr == NULL)
		num = 0;
	else
		num = attr->num_values;

	*result = malloc(sizeof(fstring)*(num+1));
	if (*result == NULL)
		return;

	for (i=0; i<num; i++)
		blob_to_fstring(attr->values[i], (*result)[i]);

	fstrcpy((*result)[i], "");
}

static BOOL attr_has_value(const struct ldap_attribute *attr, DATA_BLOB value)
{
	int i;

	for (i=0; i<attr->num_values; i++) {
		if (value.length != attr->values[i].length)
			continue;
		if (memcmp(value.data, attr->values[i].data,
			   value.length) == 0)
			return True;
	}
	return False;
}

static BOOL add_blob_to_bvals(DATA_BLOB value, struct berval ***bvals)
{
	int num = 0;

	if (*bvals == NULL) {
		*bvals = malloc(sizeof(**bvals));
		if (*bvals == NULL)
			return False;
		(*bvals)[0] = NULL;
	}

	while ((*bvals)[num] != NULL)
		num += 1;

	*bvals = realloc(*bvals, (num+2) * sizeof(**bvals));
	if (*bvals == NULL)
		return False;

	(*bvals)[num] = malloc(sizeof(struct berval));
	if ((*bvals)[num] == NULL)
		return False;

	(*bvals)[num+1] = NULL;

	(*bvals)[num]->bv_val = memdup(value.data, value.length);
	if (((*bvals)[num]->bv_val) == NULL)
		return False;
	(*bvals)[num]->bv_len = value.length;

	return True;
}

static BOOL add_mod_to_mods(struct ldapmod *mod, struct ldapmod ***mods)
{
	int num = 0;

	if (*mods == NULL) {
		*mods = malloc(sizeof(**mods));
		if (*mods == NULL)
			return False;
		(*mods)[0] = NULL;
	}

	while ((*mods)[num] != NULL)
		num += 1;

	*mods = realloc(*mods, (num+2) * sizeof(**mods));
	if (*mods == NULL)
		return False;

	(*mods)[num] = mod;
	(*mods)[num+1] = NULL;
	return True;
}
/* Create ldapmods to delete all existing attributes. Don't delete if in the
 * new entry the exact same value already exists. */

static struct ldapmod *delete_old_values(const struct ldap_attribute *old,
					 const struct ldap_attribute *new)
{
	struct ldapmod *result;
	int i;
	int num_bvals;
	struct berval **bvals;

	if ((new != NULL) && (!strequal(old->name, new->name)))
		return NULL;

	num_bvals = 0;
	bvals = NULL;

	for (i=0; i<old->num_values; i++) {

		if ((new != NULL) && (attr_has_value(new, old->values[i])))
			continue;

		if (!add_blob_to_bvals(old->values[i], &bvals))
			return NULL;
	}

	if (bvals == NULL)
	    return NULL;

	result = malloc(sizeof(*result));
	if (result == NULL)
		return NULL;

	result->mod_op = LDAP_MOD_DELETE | LDAP_MOD_BVALUES;
	result->mod_type = strdup(old->name);
	result->mod_bvalues = bvals;
	return result;
}

/* Create ldapmods to add all new attributes. Don't add if in the old entry
 * the exact same value already exists. */

static struct ldapmod *add_new_values(const struct ldap_attribute *old,
				      const struct ldap_attribute *new)
{
	struct ldapmod *result;
	int i;
	int num_bvals;
	struct berval **bvals;

	if ((old != NULL) && (!strequal(old->name, new->name)))
		return NULL;

	num_bvals = 0;
	bvals = NULL;

	for (i=0; i<new->num_values; i++) {

		if ((old != NULL) && (attr_has_value(old, new->values[i])))
			continue;

		if (!add_blob_to_bvals(new->values[i], &bvals))
			return NULL;
	}

	if (bvals == NULL)
		return NULL;

	result = malloc(sizeof(*result));
	if (result == NULL)
		return NULL;

	result->mod_op = LDAP_MOD_ADD | LDAP_MOD_BVALUES;
	result->mod_type = strdup(new->name);
	result->mod_bvalues = bvals;
	return result;
}

static BOOL ldap_create_mods(const struct ldap_entry *old,
			     const struct ldap_entry *new,
			     LDAPMod ***result)
{
	int i;
	struct bitmap *covered = bitmap_allocate(new->num_attribs);

	if (covered == NULL)
		return False;

	*result = NULL;

	if (old != NULL) {
		for (i=0; i<old->num_attribs; i++) {
			struct ldap_attribute *old_attr = &old->attribs[i];
			struct ldap_attribute *new_attr = NULL;
			int j;
			struct ldapmod *mod;

			for (j=0; j<new->num_attribs; j++) {
				if (strequal(new->attribs[j].name,
					     old_attr->name)) {
					new_attr = &new->attribs[j];
					bitmap_set(covered, j);
					break;
				}
			}

			mod = delete_old_values(old_attr, new_attr);

			if ((mod != NULL) &&
			    (!add_mod_to_mods(mod, result)))
				return False;

			if (new_attr == NULL)
				continue;

			mod = add_new_values(old_attr, new_attr);

			if ((mod != NULL) && (!add_mod_to_mods(mod, result)))
				return False;
		}
	}

	for (i=0; i<new->num_attribs; i++) {
		struct ldapmod *mod;

		if (bitmap_query(covered, i))
			continue;

		mod = add_new_values(NULL, &new->attribs[i]);
		
		if ((mod != NULL) && (!add_mod_to_mods(mod, result)))
			return False;
	}

	bitmap_free(covered);
	return True;
}

static BOOL ldap_search_entry(struct smbldap_state *ldap_state,
			      struct ldap_entry *entry)
{
	LDAP *ld = ldap_state->ldap_struct;
	LDAPMessage *res = NULL;
	int rc;

	/* First try the direct expected dn search */
	rc = smbldap_search(ldap_state, entry->dn, LDAP_SCOPE_BASE,
			    "(objectclass=*)", NULL, 0, &res);

	if ((rc == LDAP_SUCCESS) && (ldap_count_entries(ld, res) == 1)) {
		ldapmsg2entry(ld, ldap_first_entry(ld, res), entry);
		ldap_msgfree(res);
		return True;
	}

	if (res != NULL)
		ldap_msgfree(res);

	/* Do the full search if we have a filter */

	if (entry->filter == NULL)
		return False;

	rc = smbldap_search(ldap_state, entry->suffix, LDAP_SCOPE_SUBTREE,
			    entry->filter, NULL, 0, &res);

	if ((rc == LDAP_SUCCESS) && (ldap_count_entries(ld, res) == 1)) {
		ldapmsg2entry(ld, ldap_first_entry(ld, res), entry);
		ldap_msgfree(res);
		return True;
	}

	if (res != NULL)
		ldap_msgfree(res);

	return False;
}

static BOOL ldap_entry_set(struct smbldap_state *ldap_state,
			   struct ldap_entry *entry)
{
	int rc;
	struct ldap_entry *old = NULL;
	struct ldapmod **mods = NULL;

	old = ldap_entry_init();
	if (old == NULL)
		return False;

	old->dn = talloc_strdup(old->mem_ctx, entry->dn);
	old->filter = talloc_strdup(old->mem_ctx, entry->filter);
	old->suffix = talloc_strdup(old->mem_ctx, entry->suffix);

	if (!ldap_search_entry(ldap_state, old)) {
		talloc_destroy(old->mem_ctx);
		old = NULL;
	}

	if (!ldap_create_mods(old, entry, &mods)) {
		DEBUG(5, ("Could not create mods\n"));
		goto done;
	}

	rc = LDAP_SUCCESS;

	if (mods != NULL) {
		if (old != NULL)
			rc = smbldap_modify(ldap_state, old->dn, mods);
		else
			rc = smbldap_add(ldap_state, entry->dn, mods);
	}

 done:
	if (mods != NULL)
		ldap_mods_free(mods, 1);

	if (old != NULL)
		talloc_destroy(old->mem_ctx);

	return rc;
}

static BOOL ldap_split_dn(const char *dn, char **rdn, char **base)
{
	BOOL result = False;
	char **rdns = ldap_explode_dn(dn, 0);
	char **tmp;

	if (rdns == NULL)
		goto done;

	if ((rdns[0] == NULL) || (rdns[1] == NULL))
		goto done;

	*rdn = strdup(rdns[0]);
	*base = strdup(rdns[1]);

	if ((*rdn == NULL) || (*base == NULL))
		goto done;

	for (tmp = &(rdns[2]); *tmp != NULL; tmp++) {
		char *new_base;
		asprintf(&new_base, "%s,%s", *base, *tmp);
		free(*base);
		*base = new_base;
	}

	result = True;
 done:
	if (rdns != NULL)
		ldap_value_free(rdns);
	return result;
}

static int ldap_create_container(struct smbldap_state *ldap_state,
				  const char *dn)
{
	struct ldap_entry *container;
	char *rdn, *base, *name;
	int rc;

	if (!ldap_split_dn(dn, &rdn, &base))
		return -1;

	SAFE_FREE(base);

	name = strchr(rdn, '=');

	if (name == NULL) {
		SAFE_FREE(rdn);
		return -1;
	}

	*name = 0;

	if (strcmp(rdn, "cn") != 0) {
		DEBUG(1, ("Can only create containers as cn=name\n"));
		SAFE_FREE(rdn);
		return -1;
	}

	name += 1;

	if ((container = ldap_entry_init()) == NULL)
		return -1;

	container->dn = talloc_strdup(container->mem_ctx, dn);

	if (container->dn == NULL)
		return -1;

	ldap_entry_string(container, "objectClass", "sambaContainer");
	ldap_entry_string(container, "cn", name);
	SAFE_FREE(rdn);

	rc = ldap_entry_set(ldap_state, container);

	talloc_destroy(container->mem_ctx);

	return rc;
}

static int ldap_create_parent_container(struct smbldap_state *ldap_state,
					const char *dn)
{
	char *rdn, *base;
	int rc;

	if (!ldap_split_dn(dn, &rdn, &base))
		return -1;

	SAFE_FREE(rdn);

	rc = ldap_create_container(ldap_state, base);

	if (rc == LDAP_SUCCESS)
		return rc;

	if (rc == LDAP_NO_SUCH_OBJECT) {
		rc = ldap_create_parent_container(ldap_state, base);
		if (rc == LDAP_SUCCESS)
			return ldap_create_container(ldap_state, base);
	}

	return -1;
}

static struct ldap_entry *prepare_printer_entry(const char *name)
{
	struct ldap_entry *entry;

	if ((entry = ldap_entry_init()) == NULL)
		return False;

	entry->dn = talloc_asprintf(entry->mem_ctx,
				    "sambaPrintName=%s,cn=Printers,%s",
				    name, lp_ldap_printer_suffix());

	entry->filter =	talloc_asprintf(entry->mem_ctx,
					"(&(objectclass=sambaPrinter)"
					"(sambaPrintName=%s))", name);
	entry->suffix =	talloc_strdup(entry->mem_ctx,
				      lp_ldap_printer_suffix());

	return entry;
}

static void prldap_set_values(struct ldap_entry *entry, NT_PRINTER_DATA *data)
{
	int 		i, j;

	if (data == NULL)
		return;

	/* loop over all keys */
		
	for ( i=0; i<data->num_keys; i++ ) {	
		REGVAL_CTR *val_ctr;
		int num_values;

		val_ctr = &data->keys[i].values;
		num_values = regval_ctr_numvals( val_ctr );
		
		/* loop over all values */
		
		for ( j=0; j<num_values; j++ ) {
			REGISTRY_VALUE	*val;
			DATA_BLOB ldapval;

			/* pathname should be stored as <key>\<value> */
			
			val = regval_ctr_specific_value( val_ctr, j );

			ldapval = data_blob_pack("PPdB",
						 data->keys[i].name,
						 regval_name(val),
						 regval_type(val),
						 regval_size(val),
						 regval_data_p(val) );

			ldap_entry_bin(entry, "sambaPrintData",
				       ldapval.data, ldapval.length);

			data_blob_free(&ldapval);
		}
	
	}
}

BOOL prldap_set_printer(NT_PRINTER_INFO_LEVEL_2 *printer)
{
	int rc;
	char *buf;
	int len;
	struct ldap_entry *entry;

	if (!init_ldap_conn())
		return False;

	if ((entry = prepare_printer_entry(printer->printername)) == NULL)
		return False;

	ldap_entry_string(entry, "objectClass", "sambaPrinter");
	ldap_entry_string(entry, "sambaPrintName", printer->printername);
	ldap_entry_int   (entry, "sambaPrintAttributes", printer->attributes);
	ldap_entry_int   (entry, "sambaPrintPriority", printer->priority);
	ldap_entry_int   (entry, "sambaPrintDefPriority",
			  printer->default_priority);
	ldap_entry_int   (entry, "sambaPrintStartTime", printer->starttime);
	ldap_entry_int   (entry, "sambaPrintUntilTime", printer->untiltime);
	ldap_entry_int   (entry, "sambaPrintStatus", printer->status);
	ldap_entry_int   (entry, "sambaPrintCJobs", printer->cjobs);
	ldap_entry_int   (entry, "sambaPrintAveragePpm", printer->averageppm);
	ldap_entry_string(entry, "sambaShareName", printer->sharename);
	ldap_entry_string(entry, "sambaPrintPort", printer->portname);
	ldap_entry_string(entry, "sambaDrvName", printer->drivername);
	ldap_entry_string(entry, "sambaPrintComment", printer->comment);
	ldap_entry_string(entry, "sambaPrintLocation", printer->location);
	ldap_entry_string(entry, "sambaPrintSepFile", printer->sepfile);
	ldap_entry_string(entry, "sambaPrintProc", printer->printprocessor);
	ldap_entry_string(entry, "sambaPrintDataType", printer->datatype);
	ldap_entry_string(entry, "sambaPrintParams", printer->parameters);
	ldap_entry_int   (entry, "sambaPrintChangeID", printer->changeid);
	ldap_entry_int   (entry, "sambaPrintCSetPrinter",
			  printer->c_setprinter);
	ldap_entry_int   (entry, "sambaPrintSetupTime", printer->setuptime);

	if (!pack_devicemode_alloc(printer->devmode, &buf, &len))
		return False;

	ldap_entry_bin(entry, "sambaPrintDevMode", buf, len);
	SAFE_FREE(buf);

	prldap_set_values(entry, &printer->data);

	rc = ldap_entry_set(ldap_conn.smbldap_state, entry);

	if (rc == LDAP_NO_SUCH_OBJECT) {
		rc = ldap_create_parent_container(ldap_conn.smbldap_state,
						  entry->dn);
		if (rc == LDAP_SUCCESS)
			rc = ldap_entry_set(ldap_conn.smbldap_state, entry);
	}

	talloc_destroy(entry->mem_ctx);

	if (rc != LDAP_SUCCESS)
		DEBUG(3, ("Could not add printer to LDAP: %s\n",
			  ldap_err2string(rc)));

	return (rc == LDAP_SUCCESS);
}

static void prldap_get_values(struct ldap_entry *entry, NT_PRINTER_DATA *data)
{
	int i;
	struct ldap_attribute *attrib;

	if (data == NULL)
		return;

	attrib = ldap_entry_find_attrib(entry, "sambaPrintData");

	if (attrib == NULL)
		return;

	/* add the "PrinterDriverData" key first for performance reasons */
	
	add_new_printer_key( data, SPOOL_PRINTERDATA_KEY );

	for (i=0; i<attrib->num_values; i++) {

		fstring keyname, valuename;
		uint32 type;
		int size, key_index;
		uint8 *data_p = NULL;
		size_t len;
	
		/* unpack the next regval */
		
		len = tdb_unpack(attrib->values[i].data,
				 attrib->values[i].length,
				 "ffdB", keyname, valuename, &type,
				 &size, &data_p);

		if (len != attrib->values[i].length) {
			DEBUG(1, ("Could not parse printer data\n"));
			SAFE_FREE(data_p);
			continue;
		}

		/* see if we need a new key */

		if ((key_index=lookup_printerkey(data, keyname)) == -1)
			key_index = add_new_printer_key(data, keyname);
			
		if ( key_index == -1 ) {
			DEBUG(0,("unpack_values: Failed to allocate a new key "
				 "[%s]!\n", keyname));
			break;
		}
		
		/* add the new value */
		
		regval_ctr_addvalue( &data->keys[key_index].values,
				     valuename, type, (const char *)data_p,
				     size );

		SAFE_FREE(data_p); /* 'B' option to tdbpack does a malloc() */

		DEBUG(8,("specific: [%s:%s], len: %d\n", keyname,
			 valuename, size));
	}
}
			      

NT_PRINTER_INFO_LEVEL_2 *prldap_get_printer(const char *sharename)
{
	struct ldap_entry *entry;
	NT_PRINTER_INFO_LEVEL_2 *printer;
	DATA_BLOB value;

	if (!init_ldap_conn())
		return False;

	printer = malloc(sizeof(*printer));

	if (printer == NULL)
		return NULL;

	ZERO_STRUCTP(printer);

	if ((entry = prepare_printer_entry(sharename)) == NULL) {
		free(printer);
		return NULL;
	}

	if (!ldap_search_entry(ldap_conn.smbldap_state, entry)) {
		free(printer);
		talloc_destroy(entry->mem_ctx);
		return NULL;
	}

	ldap_fetch_fstring(entry, "sambaPrintName", printer->printername);
	ldap_fetch_uint32 (entry, "sambaPrintAttributes",
			   &printer->attributes);
	ldap_fetch_uint32 (entry, "sambaPrintPriority", &printer->priority);
	ldap_fetch_uint32 (entry, "sambaPrintDefPriority",
			   &printer->default_priority);
	ldap_fetch_uint32 (entry, "sambaPrintStartTime", &printer->starttime);
	ldap_fetch_uint32 (entry, "sambaPrintUntilTime", &printer->untiltime);
	ldap_fetch_uint32 (entry, "sambaPrintStatus", &printer->status);
	ldap_fetch_uint32 (entry, "sambaPrintCJobs", &printer->cjobs);
	ldap_fetch_uint32 (entry, "sambaPrintAveragePpm",
			   &printer->averageppm);
	ldap_fetch_fstring(entry, "sambaShareName", printer->sharename);
	ldap_fetch_fstring(entry, "sambaPrintPort", printer->portname);
	ldap_fetch_fstring(entry, "sambaDrvName", printer->drivername);
	ldap_fetch_fstring(entry, "sambaPrintComment", printer->comment);
	ldap_fetch_fstring(entry, "sambaPrintLocation", printer->location);
	ldap_fetch_fstring(entry, "sambaPrintSepFile", printer->sepfile);
	ldap_fetch_fstring(entry, "sambaPrintProc", printer->printprocessor);
	ldap_fetch_fstring(entry, "sambaPrintDataType", printer->datatype);
	ldap_fetch_fstring(entry, "sambaPrintParams", printer->parameters);
	ldap_fetch_uint32 (entry, "sambaPrintChangeID", &printer->changeid);
	ldap_fetch_uint32 (entry, "sambaPrintCSetPrinter",
			   &printer->c_setprinter);
	ldap_fetch_uint32 (entry, "sambaPrintSetupTime", &printer->setuptime);

	value = ldap_fetch_bin(entry, "sambaPrintDevMode");
	unpack_devicemode(&printer->devmode, value.data, value.length);

	prldap_get_values(entry, &printer->data);

	talloc_destroy(entry->mem_ctx);

	return printer;
}

static struct ldap_entry *prepare_form_entry(const char *name)
{
	struct ldap_entry *entry;

	if ((entry = ldap_entry_init()) == NULL)
		return False;

	entry->dn = talloc_asprintf(entry->mem_ctx,
				    "sambaFormName=%s,cn=Forms,%s",
				    name, lp_ldap_printer_suffix());

	entry->filter = talloc_asprintf(entry->mem_ctx,
					"(&(objectClass=sambaPrinterForm)"
					"(sambaFormName=%s))", name);

	entry->suffix = talloc_strdup(entry->mem_ctx,
				      lp_ldap_printer_suffix());

	return entry;
}

BOOL prldap_set_form(nt_forms_struct *form)
{
	char *dn;
	pstring buf;
	int len;
	int rc;
	struct ldap_entry *entry;

	if (!init_ldap_conn())
		return False;

	if ((entry = prepare_form_entry(form->name)) == NULL)
		return False;

	ldap_entry_string(entry, "objectClass", "sambaPrinterForm");
	ldap_entry_string(entry, "sambaFormName", form->name);
	ldap_entry_int   (entry, "sambaFormFlag", form->flag);

	len = tdb_pack(buf, sizeof(buf), "dddddd", form->width, form->length,
		       form->left, form->top, form->right, form->bottom);

	if (len > sizeof(buf)) {
		SAFE_FREE(dn);
		return False;
	}

	ldap_entry_bin(entry, "sambaFormDimensions", buf, len);

	rc = ldap_entry_set(ldap_conn.smbldap_state, entry);

	if (rc == LDAP_NO_SUCH_OBJECT) {
		rc = ldap_create_parent_container(ldap_conn.smbldap_state,
						  entry->dn);
		if (rc == LDAP_SUCCESS)
			rc = ldap_entry_set(ldap_conn.smbldap_state, entry);
	}

	talloc_destroy(entry->mem_ctx);

	if (rc != LDAP_SUCCESS)
		DEBUG(3, ("Could not add form to LDAP: %s\n",
			  ldap_err2string(rc)));

	return (rc == LDAP_SUCCESS);
}

/* This API needs to change .... */
BOOL prldap_get_form(const char *name, nt_forms_struct *form)
{
	struct ldap_entry *entry;
	DATA_BLOB value;

	if (!init_ldap_conn())
		return False;

	if ((entry = prepare_form_entry(name)) == NULL)
		return False;

	if (!ldap_search_entry(ldap_conn.smbldap_state, entry)) {
		talloc_destroy(entry->mem_ctx);
		return False;
	}

	ldap_fetch_fstring(entry, "sambaFormName", form->name);
	ldap_fetch_uint32(entry, "sambaFormFlag", &form->flag);

	value = ldap_fetch_bin(entry, "sambaFormDimensions");
	tdb_unpack(value.data, value.length, "dddddd",
		   &form->width, &form->length, &form->left,
		   &form->top, &form->right, &form->bottom);
	return True;
}

static struct ldap_entry *prepare_driver_entry(const char *name,
					       uint32 cversion,
					       const char *architecture)
{
	struct ldap_entry *entry;

	if ((entry = ldap_entry_init()) == NULL)
		return NULL;

	entry->dn = talloc_asprintf(entry->mem_ctx,
				    "sambaDrvName=%s,cn=%d,cn=%s,"
				    "cn=Drivers,%s", name, cversion,
				    architecture, lp_ldap_printer_suffix());

	entry->filter = talloc_asprintf(entry->mem_ctx,
					"(&(objectClass=sambaPrinterDriver)"
					"(sambaDrvName=%s)"
					"(sambaDrvVersion=%d)"
					"(sambaDrvEnvironment=%s))",
					name, cversion, architecture);

	entry->suffix = talloc_strdup(entry->mem_ctx,
				      lp_ldap_printer_suffix());


	return entry;
}

BOOL prldap_set_driver(NT_PRINTER_DRIVER_INFO_LEVEL_3 *driver)
{
	int rc;
	struct ldap_entry *entry;

	if (!init_ldap_conn())
		return False;

	entry = prepare_driver_entry(driver->name, driver->cversion,
				     driver->environment);

	if (entry == NULL)
		return False;

	ldap_entry_string(entry, "objectClass", "sambaPrinterDriver");
	ldap_entry_string(entry, "sambaDrvName", driver->name);
	ldap_entry_int   (entry, "sambaDrvVersion", driver->cversion);
	ldap_entry_string(entry, "sambaDrvEnvironment", driver->environment);
	ldap_entry_string(entry, "sambaDrvPath", driver->driverpath);
	ldap_entry_string(entry, "sambaDrvDataFile", driver->datafile);
	ldap_entry_string(entry, "sambaDrvConfigFile", driver->configfile);
	ldap_entry_string(entry, "sambaDrvHelpFile", driver->helpfile);
	ldap_entry_string(entry, "sambaDrvMonitorName", driver->monitorname);
	ldap_entry_string(entry, "sambaDrvDefDataType",
			  driver->defaultdatatype);

	if (driver->dependentfiles != NULL) {
		fstring *depfile = driver->dependentfiles;

		while (((*depfile) != NULL) && ((*depfile)[0] != '\0')) {
			ldap_entry_string(entry, "sambaDrvDepFile", *depfile);
			depfile += 1;
		}
	}

	rc = ldap_entry_set(ldap_conn.smbldap_state, entry);

	if (rc == LDAP_NO_SUCH_OBJECT) {
		rc = ldap_create_parent_container(ldap_conn.smbldap_state,
						  entry->dn);
		if (rc == LDAP_SUCCESS)
			rc = ldap_entry_set(ldap_conn.smbldap_state, entry);
	}

	talloc_destroy(entry->mem_ctx);

	if (rc != LDAP_SUCCESS)
		DEBUG(3, ("Could not add driver to LDAP: %s\n",
			  ldap_err2string(rc)));

	return (rc == LDAP_SUCCESS);
}

NT_PRINTER_DRIVER_INFO_LEVEL_3 *prldap_get_driver(const char *drivername,
						  const char *arch,
						  uint32 version)
{
	struct ldap_entry *entry;
	NT_PRINTER_DRIVER_INFO_LEVEL_3 *driver;

	if (!init_ldap_conn())
		return False;

	driver = malloc(sizeof(*driver));

	if (driver == NULL)
		return NULL;

	entry = prepare_driver_entry(drivername, version, arch);

	if (entry == NULL) {
		free(driver);
		return NULL;
	}

	if (!ldap_search_entry(ldap_conn.smbldap_state, entry)) {
		free(driver);
		talloc_destroy(entry->mem_ctx);
		return NULL;
	}

	ldap_fetch_uint32(entry, "sambaDrvVersion", &driver->cversion);
	ldap_fetch_fstring(entry, "sambaDrvName", driver->name);
	ldap_fetch_fstring(entry, "sambaDrvEnvironment", driver->environment);
	ldap_fetch_fstring(entry, "sambaDrvPath", driver->driverpath);
	ldap_fetch_fstring(entry, "sambaDrvDataFile", driver->datafile);
	ldap_fetch_fstring(entry, "sambaDrvConfigFile", driver->configfile);
	ldap_fetch_fstring(entry, "sambaDrvHelpFile", driver->helpfile);
	ldap_fetch_fstring(entry, "sambaDrvMonitorName", driver->monitorname);
	ldap_fetch_fstring(entry, "sambaDrvDefDataType",
			   driver->defaultdatatype);
	ldap_fetch_fstrings(entry, "sambaDrvDepFile", &driver->dependentfiles);

	return driver;
}
