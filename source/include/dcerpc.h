/* unused.  Stub to make the pidl generated NDR parsers compile */

struct dcerpc_endpoint_list {
        uint32_t count;
        const char * const *names;
};

struct dcerpc_authservice_list {
        uint32_t count;
        const char * const *names;
};

struct dcerpc_interface_table {
        const char *name;
        struct ndr_syntax_id syntax_id;
        const char *helpstring;
        uint32_t num_calls;
        const struct ndr_interface_call *calls;
        const struct dcerpc_endpoint_list *endpoints;
        const struct dcerpc_authservice_list *authservices;
};

struct dcerpc_interface_list {
        struct dcerpc_interface_list *prev, *next;
        const struct dcerpc_interface_table *table;
};


