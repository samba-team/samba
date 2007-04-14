AC_CACHE_CHECK([whether strptime is available and works],libreplace_cv_STRPTIME_OK,[
	AC_TRY_RUN([
		#include <stdio.h>
		#include <stdlib.h>
		#include <time.h>
		int main (void) {
		const char *s = "20061004023546Z";
		char *ret;
		struct tm t;
		ret = strptime(s, "%Y%m%d%H%M%S", &t);
		if ( ret == NULL ) return 1;
		return 0;
		}],
		[libreplace_cv_STRPTIME_OK=yes],
		[libreplace_cv_STRPTIME_OK=no],
		[libreplace_cv_STRPTIME_OK="assuming not"])
])
if test x"$libreplace_cv_STRPTIME_OK" != x"yes"; then
        AC_DEFINE(REPLACE_STRPTIME,1,[Whether strptime should be replaced])
        LIBREPLACEOBJ="${LIBREPLACEOBJ} strptime.o"
fi
