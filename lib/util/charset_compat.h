#ifndef _SAMBA_CHARSET_COMPAT_H_
#define _SAMBA_CHARSET_COMPAT_H_

#include <string.h>

#define strchr_m(h, n) strchr(h, n)
#define strstr_m(h, n) strstr(h, n)

#endif /* _SAMBA_CHARSET_COMPAT_H_ */
