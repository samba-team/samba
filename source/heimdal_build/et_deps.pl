#!/usr/bin/perl

use File::Basename;

my $file = shift;
my $dirname = shift;
my $basename = basename($file);

my $header = "$dirname/$basename"; $header =~ s/\.et$/.h/;
my $source = "$dirname/$basename"; $source =~ s/\.et$/.c/;
print "$header $source: $file bin/compile_et\n";
print "\t\@echo \"Compiling error table $file\"\n";
print "\t\@\$(builddir)/heimdal_build/et_compile_wrapper.sh \$(srcdir) \$(builddir) $dirname bin/compile_et $file\n\n";

print "clean:: \n";
print "\t\@rm -f $header $source\n\n";
