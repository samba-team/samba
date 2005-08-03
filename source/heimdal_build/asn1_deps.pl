#!/usr/bin/perl
# Generate make dependency rules for asn1 files
# Jelmer Vernooij <jelmer@samba.org> 2005
# GPL

use File::Basename;

my $file = shift;
my $prefix = shift;

if (not defined ($prefix)) { $prefix = "asn1"; }

$dirname = dirname($file);
$basename = basename($file);

my $header = "$dirname/$prefix.h";

print "$header: $file bin/asn1_compile\n";
print "\t\@echo \"Compiling ASN1 file $file\"\n";
print "\t\@cd $dirname && ../../../bin/asn1_compile $basename $prefix\n\n";

open(IN,$file) or die("Can't open $file: $!");
foreach(<IN>) {
	if (/^([A-Za-z0-9_-]+)[ \t]*::= /) {
		my $output = $1;
		$output =~ s/-/_/g;
		print "$dirname/asn1_$output.c: $header\n";
		print "\t\@mv $dirname/asn1_$output.x $dirname/asn1_$output.c\n\n";
	}
}
close(IN);
