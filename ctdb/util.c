/*
  functions taken from samba4 for quick prototyping of ctdb. These are
  not intended to remain part of ctdb
*/

#include "includes.h"
#include "system/time.h"
#include "system/filesys.h"


/**
  return a zero timeval
*/
struct timeval timeval_zero(void)
{
	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = 0;
	return tv;
}

/**
  return True if a timeval is zero
*/
bool timeval_is_zero(const struct timeval *tv)
{
	return tv->tv_sec == 0 && tv->tv_usec == 0;
}

/**
  return a timeval for the current time
*/
struct timeval timeval_current(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv;
}

/**
  return a timeval struct with the given elements
*/
struct timeval timeval_set(uint32_t secs, uint32_t usecs)
{
	struct timeval tv;
	tv.tv_sec = secs;
	tv.tv_usec = usecs;
	return tv;
}

int timeval_compare(const struct timeval *tv1, const struct timeval *tv2)
{
	if (tv1->tv_sec  > tv2->tv_sec)  return 1;
	if (tv1->tv_sec  < tv2->tv_sec)  return -1;
	if (tv1->tv_usec > tv2->tv_usec) return 1;
	if (tv1->tv_usec < tv2->tv_usec) return -1;
	return 0;
}

struct timeval timeval_until(const struct timeval *tv1,
			     const struct timeval *tv2)
{
	struct timeval t;
	if (timeval_compare(tv1, tv2) >= 0) {
		return timeval_zero();
	}
	t.tv_sec = tv2->tv_sec - tv1->tv_sec;
	if (tv1->tv_usec > tv2->tv_usec) {
		t.tv_sec--;
		t.tv_usec = 1000000 - (tv1->tv_usec - tv2->tv_usec);
	} else {
		t.tv_usec = tv2->tv_usec - tv1->tv_usec;
	}
	return t;
}

_PUBLIC_ struct timeval timeval_add(const struct timeval *tv,
			   uint32_t secs, uint32_t usecs)
{
	struct timeval tv2 = *tv;
	const unsigned int million = 1000000;
	tv2.tv_sec += secs;
	tv2.tv_usec += usecs;
	tv2.tv_sec += tv2.tv_usec / million;
	tv2.tv_usec = tv2.tv_usec % million;
	return tv2;
}


_PUBLIC_ struct timeval timeval_current_ofs(uint32_t secs, uint32_t usecs)
{
	struct timeval tv = timeval_current();
	return timeval_add(&tv, secs, usecs);
}

_PUBLIC_ char *fd_load(int fd, size_t *size, TALLOC_CTX *mem_ctx)
{
	struct stat sbuf;
	char *p;

	if (fstat(fd, &sbuf) != 0) return NULL;

	p = (char *)talloc_size(mem_ctx, sbuf.st_size+1);
	if (!p) return NULL;

	if (read(fd, p, sbuf.st_size) != sbuf.st_size) {
		talloc_free(p);
		return NULL;
	}
	p[sbuf.st_size] = 0;

	if (size) *size = sbuf.st_size;

	return p;
}


_PUBLIC_ char *file_load(const char *fname, size_t *size, TALLOC_CTX *mem_ctx)
{
	int fd;
	char *p;

	if (!fname || !*fname) return NULL;
	
	fd = open(fname,O_RDONLY);
	if (fd == -1) return NULL;

	p = fd_load(fd, size, mem_ctx);

	close(fd);

	return p;
}


/**
parse a buffer into lines
'p' will be freed on error, and otherwise will be made a child of the returned array
**/
static char **file_lines_parse(char *p, size_t size, int *numlines, TALLOC_CTX *mem_ctx)
{
	int i;
	char *s, **ret;

	if (!p) return NULL;

	for (s = p, i=0; s < p+size; s++) {
		if (s[0] == '\n') i++;
	}

	ret = talloc_array(mem_ctx, char *, i+2);
	if (!ret) {
		talloc_free(p);
		return NULL;
	}	
	
	talloc_steal(ret, p);
	
	memset(ret, 0, sizeof(ret[0])*(i+2));
	if (numlines) *numlines = i;

	ret[0] = p;
	for (s = p, i=0; s < p+size; s++) {
		if (s[0] == '\n') {
			s[0] = 0;
			i++;
			ret[i] = s+1;
		}
		if (s[0] == '\r') s[0] = 0;
	}

	return ret;
}


/**
load a file into memory and return an array of pointers to lines in the file
must be freed with talloc_free(). 
**/
_PUBLIC_ char **file_lines_load(const char *fname, int *numlines, TALLOC_CTX *mem_ctx)
{
	char *p;
	size_t size;

	p = file_load(fname, &size, mem_ctx);
	if (!p) return NULL;

	return file_lines_parse(p, size, numlines, mem_ctx);
}
