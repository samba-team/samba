#ifndef _VIS_EXTRAS_H_
#define	_VIS_EXTRAS_H_

#include <roken.h>

ROKEN_CPP_START

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
	rk_strasvis(char **, const char *, int, const char *);

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
	rk_strasvisx(char **, const char *, size_t, int, const char *);

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
	rk_strrasvis(char **, size_t *, const char *, int, const char *);

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
	rk_strrasvisx(char **, size_t *, const char *, size_t, int, const char *);

ROKEN_CPP_END

#define strasvis(a, b, c, d)	    rk_strasvis(a, b, c, d)
#define strasvisx(a, b, c, d)	    rk_strasvisx(a, b, c, d)
#define strrasvis(a, b, c, d)	    rk_strrasvis(a, b, c, d)
#define strrasvisx(a, b, c, d)	    rk_strrasvisx(a, b, c, d)

#endif /* !_VIS_EXTRAS_H_ */
