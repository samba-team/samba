@BOTTOM@

#undef HAVE_INT8_T
#undef HAVE_INT16_T
#undef HAVE_INT32_T
#undef HAVE_INT64_T
#undef HAVE_U_INT8_T
#undef HAVE_U_INT16_T
#undef HAVE_U_INT32_T
#undef HAVE_U_INT64_T

/* Define this if your `struct tm' has a field `tm_gmtoff' */
#undef HAVE_STRUCT_TM_TM_GMTOFF

/* Define this if you have a variable `timezone' */
#undef HAVE_TIMEZONE

#undef VOID_RETSIGTYPE

#ifdef VOID_RETSIGTYPE
#define SIGRETURN(x) return
#else
#define SIGRETURN(x) return (RETSIGTYPE)(x)
#endif

#define RCSID(msg) \
static /**/const char *const rcsid[] = { (char *)rcsid, "\100(#)" msg }

#undef PROTOTYPES
