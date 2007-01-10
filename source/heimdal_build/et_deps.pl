#!/usr/bin/perl

use File::Basename;

my $file = shift;
my $dirname = shift;
my $basename = basename($file);

my $header = "$dirname/$basename"; $header =~ s/\.et$/.h/;
my $source = "$dirname/$basename"; $source =~ s/\.et$/.c/;
print "$header $source: $file bin/compile_et\n";
print "\t\@echo \"Compiling error table $file\"\n";
print "\t\@startdir=`pwd` && cd $dirname && " . '$$startdir/bin/compile_et $$startdir/' . "$file\n\n";

print "clean:: \n";
print "\n\t\@rm -f $header $source";
