#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>

RCSID("$Id$");

extern char **environ;

/*
 * putenv --
 *	String points to a string of the form name=value.
 *
 *      Makes the value of the environment variable name equal to
 *      value by altering an existing variable or creating a new one.
 */
int putenv(const char *string)
{
    int i;
    int len;
    
    len = string - strchr(string, '=') + 1;

    if(environ == NULL){
	environ = malloc(sizeof(char*));
	if(environ == NULL)
	    return 1;
	environ[0] = NULL;
    }

    for(i = 0; environ[i]; i++)
	if(strncmp(string, environ[i], len)){
	    environ[len] = string;
	    return 0;
	}
    environ = realloc(environ, sizeof(char*) * (i + 1));
    if(environ == NULL)
	return 1;
    environ[i] = string;
    environ[i+1] = NULL;
    return 0;
}

