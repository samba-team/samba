#include "parser.h"


/*******************************************************************
 Count the number of characters (not bytes) in a unicode string.
********************************************************************/
size_t strlen_w(void *src)
{
	size_t len;

	for (len = 0; SVAL(src, len*2); len++) ;

	return len;
}

/****************************************************************************
expand a pointer to be a particular size
****************************************************************************/
void *Realloc(void *p,size_t size)
{
  void *ret=NULL;

  if (size == 0) {
    if (p) free(p);
    DEBUG(5,("Realloc asked for 0 bytes\n"));
    return NULL;
  }

  if (!p)
    ret = (void *)malloc(size);
  else
    ret = (void *)realloc(p,size);

  if (!ret)
    DEBUG(0,("Memory allocation error: failed to expand to %d bytes\n",(int)size));

  return(ret);
}


char *tab_depth(int depth)
{
	static pstring spaces;
	memset(spaces, ' ', depth * 4);
	spaces[depth * 4] = 0;
	return spaces;
}

void print_asc(int level, uchar const *buf, int len)
{
	int i;
	for (i = 0; i < len; i++)
	{
		DEBUGADD(level, ("%c", isprint(buf[i]) ? buf[i] : '.'));
	}
}

void dump_data(int level, char *buf1, int len)
{
	uchar const *buf = (uchar const *)buf1;
	int i = 0;
	if (buf == NULL)
	{
		DEBUG(level, ("dump_data: NULL, len=%d\n", len));
		return;
	}
	if (len < 0)
		return;
	if (len == 0)
	{
		DEBUG(level, ("\n"));
		return;
	}

	DEBUG(level, ("[%03X] ", i));
	for (i = 0; i < len;)
	{
		DEBUGADD(level, ("%02X ", (int)buf[i]));
		i++;
		if (i % 8 == 0)
			DEBUGADD(level, (" "));
		if (i % 16 == 0)
		{
			print_asc(level, &buf[i - 16], 8);
			DEBUGADD(level, (" "));
			print_asc(level, &buf[i - 8], 8);
			DEBUGADD(level, ("\n"));
			if (i < len)
				DEBUGADD(level, ("[%03X] ", i));
		}
	}

	if (i % 16 != 0)	/* finish off a non-16-char-length row */
	{
		int n;

		n = 16 - (i % 16);
		DEBUGADD(level, (" "));
		if (n > 8)
			DEBUGADD(level, (" "));
		while (n--)
			DEBUGADD(level, ("   "));

		n = MIN(8, i % 16);
		print_asc(level, &buf[i - (i % 16)], n);
		DEBUGADD(level, (" "));
		n = (i % 16) - n;
		if (n > 0)
			print_asc(level, &buf[i - n], n);
		DEBUGADD(level, ("\n"));
	}
}
