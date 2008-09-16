typedef const char *CIMSTRING;
enum ndr_err_code ndr_pull_WbemClassObject_Object(struct ndr_pull *ndr, int ndr_flags, struct WbemClassObject *r);
enum ndr_err_code ndr_pull_WbemClassObject(struct ndr_pull *ndr, int ndr_flags, struct WbemClassObject *r);
enum ndr_err_code ndr_push_WbemClassObject(struct ndr_push *ndr, int ndr_flags, const struct WbemClassObject *r);
enum ndr_err_code ndr_pull_CIMSTRING(struct ndr_pull *ndr, int ndr_flags, CIMSTRING *r);
enum ndr_err_code ndr_push_CIMSTRING(struct ndr_push *ndr, int ndr_flags, const CIMSTRING *r);
