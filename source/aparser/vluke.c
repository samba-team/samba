#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include "parser.h"
#include "test.h"

int main(int argc, char *argv[])
{
	BOOL ret;
	TEST_STRUCT *il;
	char *desc = TEST_NAME;
	char *fname = argv[1];
	int fd;	
	struct stat st;
	prs_struct ps;

	if (argc < 2) {
		printf("usage: vluke <file>\n");
		exit(1);
	}

	fd = open(fname,O_RDONLY);
	fstat(fd, &st);

	prs_init(&ps, 0, 4, MARSHALL);
	ps.is_dynamic=True;
	prs_read(&ps, fd, st.st_size, 0);
	ps.data_offset = 0;
	ps.io = UNMARSHALL;
	il = (TEST_STRUCT *)malloc(sizeof(*il));
	ret = TEST_FUNC(desc, &ps, 1, il, PARSE_SCALARS|PARSE_BUFFERS);
	printf("\nret=%s\n", ret?"OK":"Bad");
	printf("Trailer is %d bytes\n\n", ps.grow_size - ps.data_offset);
	dump_data(0, ps.data_p, ps.grow_size);
	return !ret;
}
