#! /usr/bin/perl5
##
## This is a simple script written by Herb Lewis @ SGI <herb@samba.org>
## for reporting which parameters where supported by loadparm.c but 
## not by SWAT I just thought it looked fun and might be of interest to others
## --jerry@samba.org
##

$lastone = "nothing";

if (@ARGV[0]) {
	$filename = @ARGV[0];
} else {
	$filename = "/usr3/samba20/samba/source/param/loadparm.c";
}

open (INFILE,$filename) || die "unable to open $filename\n";
while (not eof(INFILE))
{
	$_ = <INFILE>;
	last if ( /^static struct parm_struct parm_table/) ;
}
print "Option Name                     Global Page  Share Page  Printer Page\n";
print "---------------------------------------------------------------------";
while (not eof(INFILE))
{
	$_ = <INFILE>;
	last if (/};/);
	@fields = split(/,/,$_);
	next if not ($fields[0] =~ /^.*{"/);
	$fields[0] =~ s/.*{"//;
	$fields[0] =~ s/"//;
	if ($fields[3] eq $lastone) {
		print "     $fields[0]\n";
		next;
	}
	$lastone = $fields[3];
	$fields[2] =~ s/^\s+//;
	$fields[2] =~ s/\s+$//;
	$fields[2] =~ s/}.*$//;
	$fields[6] =~ s/^\s+//;
	$fields[6] =~ s/\s+$//;
	$fields[6] =~ s/}.*$//;
	if ($fields[2] =~ /P_SEPARATOR/) {
		print "\n****************$fields[0]\n";
		next;
	}
	else {
		if ($fields[6] =~ /FLAG_DEPRECATED/) {
			print "*$fields[0]".' 'x(31-length($fields[0]));
		}
		else {
			print "$fields[0]".' 'x(32-length($fields[0]));
		}
	}
	if (($fields[2] =~ /P_GLOBAL/) || ($fields[6] =~ /FLAG_GLOBAL/)) {
		if ($fields[6] =~ /FLAG_GLOBAL/) {
			print "*";
		}
		else {
			print " ";
		}
		if ($fields[6] =~ /FLAG_BASIC/) {
			print "BASIC       ";
		}
		else {
			print "ADVANCED    ";
		}
	}
	else {
		print " no          ";
	}
	if ($fields[6] =~ /FLAG_SHARE/) {
		if ($fields[6] =~ /FLAG_BASIC/) {
			print "BASIC       ";
		}
		else {
			print "ADVANCED    ";
		}
	}
	else {
		print "no          ";
	}
	if ($fields[6] =~ /FLAG_PRINT/) {
		if ($fields[6] =~ /FLAG_BASIC/) {
			print "BASIC";
		}
		else {
			print "ADVANCED";
		}
	}
	else {
		print "no";
	}
	print "\n";
}
