#!/usr/bin/perl -w

my ( $tag, $filename, $date );
my ( $tmp, $change_flag );

if ( $#ARGV != 2 ) {

	print "Usage: ", $0, " cvstag date file\n";
	exit 1;
}

$tag      = $ARGV[0];
$date     = $ARGV[1];
$filename = $ARGV[2];

print STDERR "$filename\n";

open ( CVSLOG, "cvs log -d\"$date\" $filename |" ) || die $!;

##
## First get the branch revision number
##
undef $revision;
while ( !defined($revision) ) {
	if ( eof( \*CVSLOG ) ) {
		print STDERR "Premature end of cvs log output!\n";
		exit (1);
	}

	$string = <CVSLOG>;
	chomp( $string );

	if ( $string =~ /$tag:/ ) {
		( $tmp, $revision ) = split( /:/, $string );
		$revision =~ s/\s+//g;
		$revision =~ s/\.0\./\./g;
	}
}

##
## Setup the beginning of the first record
##
$string = "";
while ( $string !~ /^-+/ ) {
	$string = <CVSLOG>;
	exit(0) if ( eof(\*CVSLOG) );
}

##
## Loop starting at the revision number for the entry
##

while ( $string = <CVSLOG> ) {

	($tmp, $entry_rev) = split( /\s+/, $string );
	if ( equal_revision( $revision, $entry_rev ) ) {
		if ( ! defined($change_flag) ) {
			print "++++++++++++++++++++++++++++++++++++++++++++++++++\n";
			print "## $filename\n";
			print "++\n";
			$change_flag = 1;
		}

		while ( $string !~ /^-+/ && !eof(CVSLOG) ) {
			print "$string";
			$string = <CVSLOG>;
		}
	}
	else {
		while ( ($string !~ /^-+/) && !eof(CVSLOG) ) {
			$string = <CVSLOG>; 
		}
	}
}

close( CVSLOG );
exit 0;

##############################################################
##
sub equal_revision {
	my ( $branch, $newfile ) = @_;
	my ( $indx );
	my ( @branch_rev, @file_rev );

	@branch_rev = split( /\./, $branch );
	@file_rev = split( /\./, $newfile );

	return 0 if ( $#branch_rev != ($#file_rev - 1) );

	$indx = 0;
	while( $indx <= $#branch_rev ) {
		if ( $branch_rev[$indx] != $file_rev[$indx] ) {
			return 0;
		}
		$indx++;
	}

	return 1;
}


