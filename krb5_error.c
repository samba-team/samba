#include "krb5_locl.h"

static char *krb5_error_table[] = {
  "No error",						/*  0 */
  "Client's entry in database has expired",		/*  1 */
  "Server's entry in database has expired",		/*  2 */
  "Requested protocol version number not supported",	/*  3 */
  "Client's key encrypted in old master key",		/*  4 */
  "Server's key encrypted in old master key",		/*  5 */
  "Client not found in Kerberos database",		/*  6 */
  "Server not found in Kerberos database",		/*  7 */
  "Multiple principal entries in database",		/*  8 */
  "he client or server has a null key",			/*  9 */
  "icket not eligible for postdating",			/* 10 */
  "Requested start time is later than end time",	/* 11 */
  "KDC policy rejects request",				/* 12 */
  "KDC cannot accommodate requested option",		/* 13 */
  "KDC has no support for encryption type",		/* 14 */
  "KDC has no support for checksum type",		/* 15 */
  "KDC has no support for padata type",			/* 16 */
  "KDC has no support for transited type",		/* 17 */
  "Clients credentials have been revoked",		/* 18 */
  "Credentials for server have been revoked",		/* 19 */
  "GT has been revoked",				/* 20 */
  "Client not yet valid - try again later",		/* 21 */
  "Server not yet valid - try again later",		/* 22 */
  "Password has expired - change password to reset",	/* 23 */
  "Pre-authentication information was invalid",		/* 24 */
  "Additional pre-authentication required",		/* 25 */
  "(reserved)",						/* 26 */
  "(reserved)",						/* 27 */
  "(reserved)",						/* 28 */
  "(reserved)",						/* 29 */
  "(reserved)",						/* 30 */
  "Integrity check on decrypted field failed",		/* 31 */
  "Ticket expired",					/* 32 */
  "Ticket not yet valid",				/* 33 */
  "Request is a replay",				/* 34 */
  "The ticket isn't for us",				/* 35 */
  "Ticket and authenticator don't match",		/* 36 */
  "Clock skew too great",				/* 37 */
  "Incorrect net address",				/* 38 */
  "Protocol version mismatch",				/* 39 */
  "Invalid msg type",					/* 40 */
  "Message stream modified",				/* 41 */
  "Message out of order",				/* 42 */
  "(reserved)",						/* 43 */
  "Specified version of key is not available",		/* 44 */
  "Service key not available",				/* 45 */
  "Mutual authentication failed",			/* 46 */
  "Incorrect message direction",			/* 47 */
  "Alternative authentication method required",		/* 48 */
  "Incorrect sequence number in message",		/* 49 */
  "Inappropriate type of checksum in message",		/* 50 */
  "(reserved)",						/* 51 */
  "(reserved)",						/* 52 */
  "(reserved)",						/* 53 */
  "(reserved)",						/* 54 */
  "(reserved)",						/* 55 */
  "(reserved)",						/* 56 */
  "(reserved)",						/* 57 */
  "(reserved)",						/* 58 */
  "(reserved)",						/* 59 */
  "Generic error",					/* 60 */
  "Field is too long for this implementation",		/* 61 */
};
