#!/usr/bin/perl
use strict;

sub add($$)
{
	my ($name, $val) = @_;

	print "$name += $val\n";
}

my %vars = ();

foreach(@ARGV) {
	my $f = $_;
	my $b = $_; $b =~ s/.*\/(.*?).idl$/$1/;

	print "# $f\n";
	add("IDL_FILES", $f);
	add("IDL_HEADER_FILES", "\$(librpcsrcdir)/gen_ndr/$b.h");
	add("IDL_NDR_PARSE_H_FILES", "\$(librpcsrcdir)/gen_ndr/ndr_$b.h");
	add("IDL_NDR_PARSE_C_FILES", "\$(librpcsrcdir)/gen_ndr/ndr_$b.c");
	add("IDL_NDR_CLIENT_C_FILES", "\$(librpcsrcdir)/gen_ndr/ndr_$b\_c.c");
	add("IDL_NDR_CLIENT_H_FILES", "\$(librpcsrcdir)/gen_ndr/ndr_$b\_c.h");
	add("IDL_SWIG_FILES", "\$(librpcsrcdir)/gen_ndr/$b.i");
	add("IDL_NDR_SERVER_C_FILES", "\$(librpcsrcdir)/gen_ndr/ndr_$b\_s.c");
	add("IDL_NDR_EJS_C_FILES", "\$(librpcsrcdir)/gen_ndr/ndr_$b\_ejs.c");
	add("IDL_NDR_EJS_H_FILES", "\$(librpcsrcdir)/gen_ndr/ndr_$b\_ejs.h");
	add("IDL_NDR_PY_C_FILES", "\$(librpcsrcdir)/gen_ndr/py_$b.c");
	add("IDL_NDR_PY_H_FILES", "\$(librpcsrcdir)/gen_ndr/py_$b.h");
	print "\n";
}
