#!/usr/bin/perl
# Generate make dependency rules for asn1 files
# Jelmer Vernooij <jelmer@samba.org> 2005
# GPL

use File::Basename;

my $file = shift;
my $prefix = shift;
my $options = join(' ', @ARGV);
my $x_file;
my @x_files = ();
my $c_file;
my @c_files = ();
if (not defined ($prefix)) { $prefix = "asn1"; }

$dirname = dirname($file);
$basename = basename($file);
if (not defined $options) {
    $options = "";
}

my $header = "$dirname/$prefix.h";

print "$header: $file bin/asn1_compile\n";
print "\t\@echo \"Compiling ASN1 file $file\"\n";
print "\t\@startdir=`pwd` && cd $dirname && " . ' $$startdir/bin/asn1_compile ' . "$options $basename $prefix\n\n";

open(IN,$file) or die("Can't open $file: $!");
foreach(<IN>) {
	if (/^([A-Za-z0-9_-]+)[ \t]*::= /) {
		my $output = $1;
		$output =~ s/-/_/g;
		$c_file = "$dirname/asn1_$output.c";
		$x_file = "$dirname/asn1_$output.x";
		print "$x_file: $header\n";
		print "$c_file: $dirname/asn1_$output.x\n";
		print "\t\@cp $x_file $c_file\n\n";
		push @x_files, $x_file;
		push @c_files, $c_file;
	}
}
close(IN);
print "clean:: \n";
print "\t\@echo \"Deleting ASN1 output files generated from $file\"";
print "\n\t\@rm -f $header";
foreach $c_file (@c_files) {
    print "\n\t\@rm -f $c_file";
}
foreach $x_file (@x_files) {
    print "\n\t\@rm -f $x_file";
}
print "\n\t\@rm -f $dirname/$prefix\_files";
print "\n\t\@rm -f $dirname/$prefix\.h";
print "\n\n";
