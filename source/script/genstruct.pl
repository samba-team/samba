#!/usr/bin/perl -w
# a simple system for generating C parse info
# this can be used to write generic C structer load/save routines
# Copyright 2002 Andrew Tridgell <genstruct@tridgell.net>
# released under the GNU General Public License v2 or later

use strict;

my(%enum_done) = ();
my(%struct_done) = ();

###################################################
# general handler
sub handle_general($$$$$$$$)
{
	my($name) = shift;
	my($ptr_count) = shift;
	my($size) = shift;
	my($element) = shift;
	my($flags) = shift;
	my($dump_fn) = shift;
	my($parse_fn) = shift;
	my($tflags) = shift;
	my($array_len) = 0;
	my($dynamic_len) = "NULL";

	# handle arrays, currently treat multidimensional arrays as 1 dimensional
	while ($element =~ /(.*)\[(.*?)\]$/) {
		$element = $1;
		if ($array_len == 0) {
			$array_len = $2;
		} else {
			$array_len = "$2 * $array_len";
		}
	}

	if ($flags =~ /_LEN\((\w*?)\)/) {
		$dynamic_len = "\"$1\"";
	}

	if ($flags =~ /_NULLTERM/) {
		$tflags = "FLAG_NULLTERM";
	}

	print OFILE "{\"$element\", $ptr_count, $size, offsetof(struct $name, $element), $array_len, $dynamic_len, $tflags, $dump_fn, $parse_fn},\n";
}


####################################################
# parse one element
sub parse_one($$$$)
{
	my($name) = shift;
	my($type) = shift;
	my($element) = shift;
	my($flags) = shift;
	my($ptr_count) = 0;
	my($size) = "sizeof($type)";
	my($tflags) = "0";
	
	# enums get the FLAG_ALWAYS flag
	if ($type =~ /^enum /) {
		$tflags = "FLAG_ALWAYS";
	}


	# make the pointer part of the base type 
	while ($element =~ /^\*(.*)/) {
		$ptr_count++;
		$element = $1;
	}

	# convert spaces to _
	$type =~ s/ /_/g;

	my($dump_fn) = "gen_dump_$type";
	my($parse_fn) = "gen_parse_$type";

	handle_general($name, $ptr_count, $size, $element, $flags, $dump_fn, $parse_fn, $tflags);
}

####################################################
# parse one element
sub parse_element($$$)
{
	my($name) = shift;
	my($element) = shift;
	my($flags) = shift;
	my($type);
	my($data);

	# pull the base type
	if ($element =~ /^struct (\S*) (.*)/) {
		$type = "struct $1";
		$data = $2;
	} elsif ($element =~ /^enum (\S*) (.*)/) {
		$type = "enum $1";
		$data = $2;
	} elsif ($element =~ /^unsigned (\S*) (.*)/) {
		$type = "unsigned $1";
		$data = $2;
	} elsif ($element =~ /^(\S*) (.*)/) {
		$type = $1;
		$data = $2;
	} else {
		die "Can't parse element '$element'";
	}

	# handle comma separated lists 
	while ($data =~ /(\S*),[\s]?(.*)/) {
		parse_one($name, $type, $1, $flags);
		$data = $2;
	}
	parse_one($name, $type, $data, $flags);
}


my($first_struct) = 1;

####################################################
# parse the elements of one structure
sub parse_elements($$)
{
	my($name) = shift;
	my($elements) = shift;

	if ($first_struct) {
		$first_struct = 0;
		print "Parsing structs: $name";
	} else {
		print ", $name";
	}

	print OFILE "int gen_dump_struct_$name(struct parse_string *, const char *, unsigned);\n";
	print OFILE "int gen_parse_struct_$name(char *, const char *);\n";

	print OFILE "static const struct parse_struct pinfo_" . $name . "[] = {\n";

	while ($elements =~ /^.*?([a-z].*?);\s*?(\S*?)\s*?$(.*)/msi) {
		my($element) = $1;
		my($flags) = $2;
		$elements = $3;
		parse_element($name, $element, $flags);
	}

	print OFILE "{NULL, 0, 0, 0, 0, NULL, 0, NULL, NULL}};\n";

	print OFILE "
int gen_dump_struct_$name(struct parse_string *p, const char *ptr, unsigned indent) {
	return gen_dump_struct(pinfo_$name, p, ptr, indent);
}
int gen_parse_struct_$name(char *ptr, const char *str) {
	return gen_parse_struct(pinfo_$name, ptr, str);
}

";
}

my($first_enum) = 1;

####################################################
# parse out the enum declarations
sub parse_enum_elements($$)
{
	my($name) = shift;
	my($elements) = shift;

	if ($first_enum) {
		$first_enum = 0;
		print "Parsing enums: $name";
	} else {
		print ", $name";
	}

	print OFILE "static const struct enum_struct einfo_" . $name . "[] = {\n";

	my(@enums) = split(/,/s, $elements);
	for (my($i)=0; $i <= $#{@enums}; $i++) {
		my($enum) = $enums[$i];
		if ($enum =~ /\s*(\w*)/) {
			my($e) = $1;
			print OFILE "{\"$e\", $e},\n";
		}
	}

	print OFILE "{NULL, 0}};\n";

	print OFILE "
int gen_dump_enum_$name(struct parse_string *p, const char *ptr, unsigned indent) {
	return gen_dump_enum(einfo_$name, p, ptr, indent);
}

int gen_parse_enum_$name(char *ptr, const char *str) {
	return gen_parse_enum(einfo_$name, ptr, str);
}

";
}

####################################################
# parse out the enum declarations
sub parse_enums($)
{
	my($data) = shift;

	while ($data =~ /^GENSTRUCT\s+enum\s+(\w*?)\s*{(.*?)}\s*;(.*)/ms) {
		my($name) = $1;
		my($elements) = $2;
		$data = $3;

		if (!defined($enum_done{$name})) {
			$enum_done{$name} = 1;
			parse_enum_elements($name, $elements);
		}
	}

	if (! $first_enum) {
		print "\n";
	}
}

####################################################
# parse all the structures
sub parse_structs($)
{
	my($data) = shift;

	# parse into structures 
	while ($data =~ /^GENSTRUCT\s+struct\s+(\w+?)\s*{\s*(.*?)\s*}\s*;(.*)/ms) {
		my($name) = $1;
		my($elements) = $2;
		$data = $3;
		if (!defined($struct_done{$name})) {
			$struct_done{$name} = 1;
			parse_elements($name, $elements);
		}
	}

	if (! $first_struct) {
		print "\n";
	} else {
		print "No GENSTRUCT structures found?\n";
	}
}


####################################################
# parse a header file, generating a dumper structure
sub parse_data($)
{
	my($data) = shift;

	# collapse spaces 
	$data =~ s/[\t ]+/ /sg;
	$data =~ s/\s*\n\s+/\n/sg;
	# strip debug lines
	$data =~ s/^\#.*?\n//smg;

	parse_enums($data);
	parse_structs($data);
}


#########################################
# display help text
sub ShowHelp()
{
    print "
generator for C structure dumpers
Copyright Andrew Tridgell <genstruct\@tridgell.net>

Sample usage:
   genstruct -o output.h gcc -E -O2 -g test.h

Options:
    --help                this help page
    -o OUTPUT             place output in OUTPUT
";
    exit(0);
}

########################################
# main program
if ($ARGV[0] ne "-o" || $#ARGV < 2) {
	ShowHelp();
}

shift;
my($opt_ofile)=shift;

print "creating $opt_ofile\n";

open(OFILE, ">$opt_ofile") || die "can't open $opt_ofile";    

print OFILE "/* This is an automatically generated file - DO NOT EDIT! */\n\n";

parse_data(`@ARGV -DGENSTRUCT=GENSTRUCT`);
exit(0);
