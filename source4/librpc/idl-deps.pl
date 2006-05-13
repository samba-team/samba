#!/usr/bin/perl
use strict;

my %vars = ();

foreach(@ARGV) {
	push (@{$vars{IDL_FILES}}, $_);
	my $b = $_; $b =~ s/.*\/(.*?).idl$/$1/;
	push (@{$vars{IDL_HEADER_FILES}}, "librpc/gen_ndr/$b.h");
	push (@{$vars{IDL_NDR_PARSE_H_FILES}}, "librpc/gen_ndr/ndr_$b.h");
	push (@{$vars{IDL_NDR_PARSE_C_FILES}}, "librpc/gen_ndr/ndr_$b.c");
	push (@{$vars{IDL_NDR_CLIENT_C_FILES}}, "librpc/gen_ndr/ndr_$b\_c.c");
	push (@{$vars{IDL_NDR_CLIENT_H_FILES}}, "librpc/gen_ndr/ndr_$b\_c.h");
	push (@{$vars{IDL_SWIG_FILES}}, "librpc/gen_ndr/$b.i");
	push (@{$vars{IDL_NDR_SERVER_C_FILES}}, "librpc/gen_ndr/ndr_$b\_s.c");
	push (@{$vars{IDL_NDR_EJS_C_FILES}}, "librpc/gen_ndr/ndr_$b\_ejs.c");
	push (@{$vars{IDL_NDR_EJS_H_FILES}}, "librpc/gen_ndr/ndr_$b\_ejs.h");
}

foreach (keys %vars) {
	print "$_ = " . join (' ', @{$vars{$_}}) . "\n";
}
