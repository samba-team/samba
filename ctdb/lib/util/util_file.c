/*
  functions taken from samba4 for quick prototyping of ctdb. These are
  not intended to remain part of ctdb
*/

#include "includes.h"
#include "system/filesys.h"


static char *fd_load(int fd, size_t *size, TALLOC_CTX *mem_ctx)
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


static char *file_load(const char *fname, size_t *size, TALLOC_CTX *mem_ctx)
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

char *hex_encode_talloc(TALLOC_CTX *mem_ctx, const unsigned char *buff_in, size_t len)
{
	int i;
	char *hex_buffer;

	hex_buffer = talloc_array(mem_ctx, char, (len*2)+1);

	for (i = 0; i < len; i++)
		slprintf(&hex_buffer[i*2], 3, "%02X", buff_in[i]);

	return hex_buffer;
}

uint8_t *hex_decode_talloc(TALLOC_CTX *mem_ctx, const char *hex_in, size_t *len)
{
	int i, num;
	uint8_t *buffer;

	*len = strlen(hex_in) / 2;
	buffer = talloc_array(mem_ctx, unsigned char, *len);

	for (i=0; i<*len; i++) {
		sscanf(&hex_in[i*2], "%02X", &num);
		buffer[i] = (uint8_t)num;
	}

	return buffer;
}
