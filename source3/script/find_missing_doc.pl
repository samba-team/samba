#!/usr/bin/perl

my $doc_file = "/docs/docbook/manpages/smb.conf.5.sgml";
my $source_file = "/source/param/loadparm.c";

my %link,%doc,%param;

# This one shouldn't be documented at all
$doc{-valid} = "FOUND";

$topdir = (shift @ARGV) or $topdir = ".";

##################################################
# Reading links from manpage

open(IN,$topdir.$doc_file);

while(<IN>) {
	if( /<listitem><para><link linkend="([^"]*)"><parameter>([^<]*)<\/parameter><\/link><\/para><\/listitem>/g ){
		$link{$2} = $1;
		$ref{$1} = $2;
	}
}

close(IN);

##################################################
# Reading documentation from manpage

open(IN,$topdir.$doc_file) || die("Can't open $topdir$doc_file");

while(<IN>) {
	if( /<term><anchor id="([^"]*)">([^<]*?)([ ]*)\(.\)([ ]*)<\/term>/g ) {
		$key = $1;
		$value = $2;
		$doc{$value} = $key;

		# There is a reference to this entry
		if($ref{$key} eq $value){
			$ref{$key} = "FOUND";
		} else {
			if($ref{$key}) {
				print "$key should refer to $value, but refers to " . $ref{$key} . "\n";
			} else {
				print "$key should refer to $value, but has no reference!\n";
			}
			$ref{$key} = $value;
		}
	}
}

close(IN);

#################################################
# Reading entries from source code

open(SOURCE,$topdir.$source_file) || die("Can't open $topdir$source_file");

while ($ln = <SOURCE>) {
  last if $ln =~ m/^static\ struct\ parm_struct\ parm_table.*/;
} #burn through the preceding lines

while ($ln = <SOURCE>) {
  last if $ln =~ m/^\s*\}\;\s*$/;
  #pull in the param names only
  next if $ln =~ m/.*P_SEPARATOR.*/;
  next unless $ln =~ /.*\"(.*)\".*/;
  
  if($doc{lc($1)}) {
	$doc{lc($1)} = "FOUND";
  } else {
	print "$1 is not documented!\n";
  }
}
close SOURCE;

##################################################
# Trying to find missing references

foreach (keys %ref) {
	if($ref{$_} cmp "FOUND") {
		print "$_ references to " . $ref{$_} . ", but " . $ref{$_} . " isn't an anchor!\n";
	}
}

foreach (keys %doc) {
	if($doc{$_} cmp "FOUND") {
		print "$_ is documented but is not a configuration option!\n";
	}
}
