#!/usr/bin/perl -w

#reads in the list of parameters from the source 
#compares this list to the list of parms documented in the docbook source
#prints out the names of the parameters that are in need of documentation
# (C) 2002 Bradley W. Langhorst" <brad@langhorst.com>

my $doc_file = "./docs/docbook/manpages/smb.conf.5.sgml";
my $source_file = "./source/param/loadparm.c";
my $ln;
my %params;

open(SOURCE, "<$source_file") || 
  die "Unable to open $source_file for input: $!\n";
open(DOC, "<$doc_file") || 
  die "Unable to open $doc_file for input: $!\n";

while ($ln= <SOURCE>) {
  last if $ln =~ m/^static\ struct\ parm_struct\ parm_table.*/;
} #burn through the preceding lines

while ($ln = <SOURCE>) {
  last if $ln =~ m/^\s*\}\;\s*$/;
  #pull in the param names only
  next if $ln =~ m/.*P_SEPARATOR.*/;
  $ln =~ m/.*\"(.*)\".*/;
  $params{lc($1)}='not_found'; #not case sensitive
}
close SOURCE;
#now read in the params list from the docs
@doclines = <DOC>;

foreach $ln (grep (/\<anchor\ id\=/, @doclines)) {
  $ln =~ m/^.*\<anchor\ id\=\".*\"\>\s*(?:\<.*?\>)*\s*(.*?)(?:\s*\(?[S,G]?\)?\s*(\<\/term\>)?){1}\s*$/;
  #print "got: $1 from: $ln";
  if (exists $params{lc($1)}) {
    $params{$1} = 'found';
  }
}

foreach (keys %params) {
  print "$_\n" if $params{$_} eq 'not_found';
}
