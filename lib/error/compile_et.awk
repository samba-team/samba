#
# $Id$
#

$1 == "error_table" || $1 == "et" {
	name = $2
	base = 0
	for(i = 1; i <= 4; i++){
		base = base * 64 + index("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_", substr(name, i, 1))
	}
	base *= 256
	if(base >= 2147483648){ # 0x80000000
		base = -(4294967295 - base + 1) # 0xffffffff
	}
	split(name, x, "\\.")
	name=x[1]
# for normal awk:
#	split(name, foo, "\\.")
#	name = foo[1]
	c_file = name "_err.c"
	h_file = name "_err.h"
	h = ""
#	gsub("[^a-zA-Z0-9]", "_", H_FILE)
	for(i = 1; i <= length(h_file); i++){
		c = substr(h_file, i, 1)
		if(c ~ /[^a-zA-Z0-9]/)
			c = "_"
		h = h c
	}
	H_FILE= "__" h "__"
	number = 0
	print "/* Generated from " FILENAME " */" > c_file
	print "#include <stddef.h>" > c_file # NULL
	print "#include <stdlib.h>" > c_file # malloc
	print "#include <error.h>" > c_file
	print "#include <" h_file ">" > c_file
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
	print "typedef enum " name "_error_number{" > h_file
	print "\tERROR_TABLE_BASE_" name " = " base "," > h_file
	next
}

$1 == "index" {
	newnumber = $2
	for(; number < newnumber; number++) {
#		printf("\t%s = %d,\n", toupper(name) "_ERROR_" number, base+ number) > h_file
		printf("\t/* %3d */ %s,\n", number, "\"Reserved error number " number "\"") > c_file
	}
	next
}
$1 == "prefix" {
	prefix = $2
	if(prefix != "")
		prefix = prefix "_"
	next
}

$1 == "error_code" {
	code = $2
	split(code, x, ",")
	code = prefix x[1]
	split($0, x, "\"")
	string = x[2]
	printf("\t%s = %d,\n", code, number + base) > h_file
	printf("\t/* %3d */ \"%s\",\n", number, string) > c_file
	number++;
	next
}
END {
	print "\tNULL" > c_file
	print "};" > c_file
	print "" > c_file
	print "void initialize_" name "_error_table (struct error_table **list)" > c_file
	print "{" > c_file
	print "    struct error_table *et = malloc(sizeof(*et));" > c_file
	print "    if (et == NULL)" > c_file
	print "        return;" > c_file
	print "    et->msgs = text;" > c_file
	print "    et->n_msgs = " name "_num_errors;" > c_file
	print "    et->base = ERROR_TABLE_BASE_" name ";" > c_file
	print "    et->next = *list;" > c_file
	print "    *list = et;" > c_file
	print "}" > c_file
	close(c_file)

	print "\t" name "_num_errors = " number > h_file
	print "} " name "_error_number;" > h_file
	print "" > h_file
	print "#endif /* " H_FILE " */" > h_file
	close(h_file)
}
