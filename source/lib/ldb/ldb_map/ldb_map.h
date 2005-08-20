struct objectclass_mapping {
	char *local_name;
	char *remote_name;

	char *key; /* Name of attribute used in rdn */

	/* For mapping attributes used in searches */
	struct local_attribute_mapping {
		char *local_name;

		/* Attributes to request from the server for this attribute, 
		 * needed by generate */
		char *required_attributes[]; 

		/* If not set, the value for the first element of 
		 * required_attributes will simply be used here */
		struct ldb_message_element *(*generate) (LDAPMessage *msg); 
	} *local_attribute_mappings;

	/* Generate LDAPMod for adds and modifies */
	LDAPMod *(*generate_mod)(struct ldb_message *);
}

struct ldb_map_backend {
	struct objectclass_mapping *objectclass_mappings;
};

const char *ldb_map_dn(const char *old);
const char *ldb_map_rdn(const char *old);
