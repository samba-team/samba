BEGIN {
	print "#include <stdio.h>"
	print "#ifdef HAVE_CONFIG_H"
	print "#include <config.h>"
	print "#endif"
	print ""
	print "int main()"
	print "{"
	print "printf(\"/* This is (as usual) a generated file,\\n\");"
	print "printf(\"   it is also machine dependent */\\n\");"
	print "printf(\"\\n\");"
	print "printf(\"#ifndef __ROKEN_H__\\n\");"
	print "printf(\"#define __ROKEN_H__\\n\");"
	print "printf(\"\\n\");"
}
END {
	print "printf(\"#endif /* __ROKEN_H__ */\\n\");"
	print "exit(0);"
	print "}"
}

$1 == "\#ifdef" || $1 == "\#ifndef" || $1 == "\#if" || $1 == "\#else" || $1 == "\#elif" || $1 == "\#endif" {
	print $0;
	next
}

{
	s = ""
	for(i = 1; i <= length; i++){
		x = substr($0, i, 1)
		if(x == "\"" || x == "\\")
			s = s "\\";
		s = s x;
	}
	printf("printf(\"%s\\n\");\n", s);
}
