#include "kdc_locl.h"
RCSID("$Id$");

static char *logfile = "kdc.log";
static int loglevel = 17;

void
kdc_log(int level, const char *fmt, ...)
{
    va_list ap;
    FILE *f;
    char buf[128];
    char *s;
    
    if(level > loglevel)
	return;

    if(logfile == NULL)
	return;
    f = fopen(logfile, "a");
    if(f == NULL)
	return;
    
    va_start(ap, fmt);
    vasprintf(&s, fmt, ap);
    va_end(ap);
	
    if(s == NULL)
	return;
    strftime(buf, sizeof(buf), "%d-%b-%Y %H:%M:%S", localtime(&kdc_time));
    fprintf(f, "%s %s\n", buf, s);
    fclose(f);
    free(s);
}
