#include "parser.h"
#include "test.h"

int main(int argc, char *argv[])
{
	BOOL ret;
	char *fname, *test;
	int fd;	
	struct stat st;
	io_struct ps;

	if (argc < 3) {
		printf("usage: vluke <structure> <file>\n");
		exit(1);
	}

	test = argv[1];
	fname = argv[2];

	fd = open(fname,O_RDONLY);
	if (fd == -1) {
	  perror(fname);
	  exit(1);
	}
	fstat(fd, &st);

	io_init(&ps, 0, MARSHALL);
	ps.is_dynamic=True;
	io_read(&ps, fd, st.st_size, 0);
	ps.data_offset = 0;	
	ps.buffer_size = ps.grow_size;
	ps.io = UNMARSHALL;
	ps.autoalign = OPTION_autoalign;
	ret = run_test(test, &ps, PARSE_SCALARS|PARSE_BUFFERS);
	printf("\nret=%s\n", ret?"OK":"Bad");
	printf("Trailer is %d bytes\n\n", ps.grow_size - ps.data_offset);
	if (ps.grow_size - ps.data_offset > 0) {
		dump_data(0, ps.data_p + ps.data_offset, ps.grow_size - ps.data_offset);
	}
	return !ret;
}
