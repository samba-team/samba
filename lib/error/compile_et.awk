#
# $Id$
#

$1 == "error_table" {
	name = $2
	base = 0
	for(i = 1; i <= 4; i++){
		base = base * 64 + index("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_", substr(name, i, 1))
	}
	base *= 256
	if(base >= 2147483648){ # 0x80000000
		base = -(4294967295 - base + 1) # 0xffffffff
	}
	sub("\\..*$", "", name)
# for normal awk:
#	split(name, foo, "\\.")
#	name = foo[1]
	c_file = name "_err.c"
	h_file = name "_err.h"
	H_FILE = "__" toupper(h_file) "__"
	gsub("[^A-Z0-9_]", "_", H_FILE)
	number = 0
	print "/* Generated from " FILENAME " */" > c_file
	print "#include <stddef.h>" > c_file # NULL
	print "#include <stdlib.h>" > c_file # malloc
	print "#include <error.h>" > c_file
	print "" > c_file
	print "static const char *text[] = {" > c_file

	print "/* Generated from " FILENAME " */" > h_file
	print "" > h_file
	print "#ifndef " H_FILE > h_file
	print "#define " H_FILE > h_file
	print "" > h_file
	print "#include <error.h>" > h_file
	print "" > h_file
	print "void initialize_" name "_error_table(struct error_table**);" > h_file
	print "" > h_file
	print "enum " name "_error_number{" > h_file
	print "\tERROR_TABLE_BASE_" name " = " base "," > h_file
	next
}

function end_file(c_file, h_file){
	print "\tNULL" > c_file
	print "};" > c_file
	print "" > c_file
	print "void initialize_" name "_error_table (struct error_table **list)" > c_file
	print "{" > c_file
	print "    struct error_table *et = malloc(sizeof(*et));" > c_file
	print "    if (et == NULL)" > c_file
	print "        return;" > c_file
	print "    et->msgs = text;" > c_file
	print "    et->n_msgs = " number ";" > c_file
	print "    et->base = " base ";" > c_file
	print "    et->next = *list;" > c_file
	print "    *list = et;" > c_file
	print "}" > c_file
	close(c_file)

	print "\t" name "_num_errors = " number > h_file
	print "};" > h_file
	print "" > h_file
	print "#endif /* " H_FILE " */" > h_file
	close(h_file)
}

function print_line(name, string, value) {
	printf("\t%s = %d,\n", name, value + base) > h_file
	printf("\t/* %3d */ %s,\n", value, string) > c_file
}

$1 == "index" {
	newnumber = $2
	for(; number < newnumber; number++)
		print_line(toupper(name)"_ERROR_" number, 
				"\"Reserved error number " number "\"", number)
	next
}
$1 == "prefix" {
	prefix = $2
	if(prefix != "")
		prefix = prefix "_"
	next
}

$1 == "error_code" {
	code = $0
	sub("error_code[ \t]+", "", code)
	sub(",.*", "", code)
	code = prefix code
	string = $0
	sub("[^,]*,", "", string)
	sub("[ \t]*", "", string)
	print_line(code, string, number)
	number++;
	next
}
END {
	end_file(c_file, h_file)
}
