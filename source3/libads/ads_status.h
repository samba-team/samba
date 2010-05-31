
/* there are 5 possible types of errors the ads subsystem can produce */
enum ads_error_type {ENUM_ADS_ERROR_KRB5, ENUM_ADS_ERROR_GSS,
		     ENUM_ADS_ERROR_LDAP, ENUM_ADS_ERROR_SYSTEM, ENUM_ADS_ERROR_NT};

typedef struct {
	enum ads_error_type error_type;
	union err_state{
		int rc;
		NTSTATUS nt_status;
	} err;
	/* For error_type = ENUM_ADS_ERROR_GSS minor_status describe GSS API error */
	/* Where rc represents major_status of GSS API error */
	int minor_status;
} ADS_STATUS;

/* macros to simplify error returning */
#define ADS_ERROR(rc) ADS_ERROR_LDAP(rc)
#define ADS_ERROR_LDAP(rc) ads_build_error(ENUM_ADS_ERROR_LDAP, rc, 0)
#define ADS_ERROR_SYSTEM(rc) ads_build_error(ENUM_ADS_ERROR_SYSTEM, rc?rc:EINVAL, 0)
#define ADS_ERROR_KRB5(rc) ads_build_error(ENUM_ADS_ERROR_KRB5, rc, 0)
#define ADS_ERROR_GSS(rc, minor) ads_build_error(ENUM_ADS_ERROR_GSS, rc, minor)
#define ADS_ERROR_NT(rc) ads_build_nt_error(ENUM_ADS_ERROR_NT,rc)

#define ADS_ERR_OK(status) ((status.error_type == ENUM_ADS_ERROR_NT) ? NT_STATUS_IS_OK(status.err.nt_status):(status.err.rc == 0))
#define ADS_SUCCESS ADS_ERROR(0)

#define ADS_ERROR_HAVE_NO_MEMORY(x) do { \
        if (!(x)) {\
                return ADS_ERROR(LDAP_NO_MEMORY);\
        }\
} while (0)

/* The following definitions come from libads/ads_status.c  */

ADS_STATUS ads_build_error(enum ads_error_type etype,
			   int rc, int minor_status);
ADS_STATUS ads_build_nt_error(enum ads_error_type etype,
			   NTSTATUS nt_status);
NTSTATUS ads_ntstatus(ADS_STATUS status);
const char *ads_errstr(ADS_STATUS status);
NTSTATUS gss_err_to_ntstatus(uint32 maj, uint32 min);
