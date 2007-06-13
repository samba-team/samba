#!/usr/bin/perl
# Generate make dependency rules for asn1 files
# Jelmer Vernooij <jelmer@samba.org> 2005
# Andrew Bartlett <abartlet@samba.org> 2006
# Stefan Metzmacher <metze@samba.org> 2007
# GPL

use File::Basename;

my $file = shift;
my $prefix = shift;
my $dirname = shift;
my $options = join(' ', @ARGV);
my $x_file;
my @x_files = ();
my $c_file;
my @c_files = ();
my $o_file;
my @o_files = ();
my $import;
my @imports = ();
my $dep;
my @deps = ();

$basename = basename($file);
if (not defined $options) {
    $options = "";
}

my $header = "$dirname/$prefix.h";

print "$header: $file bin/asn1_compile\n";
print "\t\@echo \"Compiling ASN1 file $file\"\n";
print "\t\@\$(builddir)/heimdal_build/asn1_compile_wrapper.sh \$(srcdir) \$(builddir) $dirname bin/asn1_compile $file $prefix $options\n\n";

open(IN,$file) or die("Can't open $file: $!");
my @lines = <IN>;
close(IN);
foreach my $line (@lines) {
	if ($line =~ /^([\w]+[\w\-]+)(\s+OBJECT IDENTIFIER)?\s*::=/) {
		my $output = $1;
		$output =~ s/-/_/g;
		$c_file = "$dirname/asn1_$output.c";
		$x_file = "$dirname/asn1_$output.x";
		$o_file = "$dirname/asn1_$output.o";
		print "$x_file: $header\n";
		print "$c_file: $dirname/asn1_$output.x\n";
		print "\t\@cp $x_file $c_file\n\n";
		push @x_files, $x_file;
		push @c_files, $c_file;
		push @o_files, $o_file;
	} elsif ($line =~ /^(\s*IMPORT)([\w\,\s])*(\s+FROM\s+)([\w]+[\w\-]+);/) {
		$import = $line;
		chomp $import;
		push @imports, $import;
		$import = undef;
	} elsif ($line =~ /^(\s*IMPORT).*/) {
		$import = $line;
		chomp $import;
	} elsif (defined($import) and ($line =~ /;/)) {
		$import .= $line;
		chomp $import;
		push @imports, $import;
		$import = undef;
	} elsif (defined($import)) {
		$import .= $line;
		chomp $import;
	}
}

foreach $import (@imports) {
	next unless ($import =~ /^(\s*IMPORT)([\w\,\s])*(\s+FROM\s+)([\w]+[\w\-]+);/);

	my @froms = split (/\s+FROM\s+/, $import);
	foreach my $from (@froms) {
		next if ($from =~ /^(\s*IMPORT).*/);
		if ($from =~ /^(\w+)/) {
			my $f = $1;
			$dep = 'HEIMDAL_'.uc($f).'_ASN1';
			push @deps, $dep;
		}
	}
}

unshift @deps, "HEIMDAL_HEIM_ASN1" unless grep /HEIMDAL_HEIM_ASN1/, @deps;
my $depstr = join(' ', @deps);

print '[SUBSYSTEM::HEIMDAL_'.uc($prefix).']'."\n";
print "CFLAGS = -Iheimdal_build -Iheimdal/lib/roken -I$dirname\n";
print "OBJ_FILES = ";
foreach $o_file (@o_files) {
    print "\\\n\t$o_file";
}
print "\nPUBLIC_DEPENDENCIES = $depstr\n\n";

print "clean:: \n";
print "\t\@echo \"Deleting ASN1 output files generated from $file\"\n";
print "\t\@rm -f $header\n";
foreach $c_file (@c_files) {
    print "\t\@rm -f $c_file\n";
}
foreach $x_file (@x_files) {
    print "\t\@rm -f $x_file\n";
}
print "\t\@rm -f $dirname/$prefix\_files\n";
print "\t\@rm -f $dirname/$prefix\.h\n";
print "\n";
