# the main program

@include dump.awk
@include header.awk
@include util.awk
@include template.awk
#@include parsefn.awk
@include parserel.awk
@include harness.awk
@include parsetree.awk
@include token.awk

END {
	dump_structs("dump.out");
	printf("Producing headers...\n");
	produce_headers("prs_"module".h");
#	printf("Producing parsers...\n");
#	produce_parsers("prs_"module".c", "mod_"module".c");
	printf("Producing relative parsers...\n");
	produce_relative("prs_"module".c");
	printf("Producing harness...\n");
	produce_harness("test.h");
	printf("Done.\n");
	exit 0;
}
