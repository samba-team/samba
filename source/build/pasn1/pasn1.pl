#!/usr/bin/perl -W

###################################################
# package to parse ASN.1 files and generate code for
# LDAP functions in Samba
# Copyright tridge@samba.org 2002-2003
# Copyright metze@samba.org 2004

# released under the GNU GPL

use strict;

use FindBin qw($RealBin);
use lib "$RealBin";
use lib "$RealBin/lib";
use Getopt::Long;
use File::Basename;
use asn1;
use util;

my($opt_help) = 0;
my($opt_parse) = 0;
my($opt_dump) = 0;
my($opt_keep) = 0;
my($opt_output);

my $asn1_parser = new asn1;

#####################################################################
# parse an ASN.1 file returning a structure containing all the data
sub ASN1Parse($)
{
    my $filename = shift;
    my $asn1 = $asn1_parser->parse_asn1($filename);
    util::CleanData($asn1);
    return $asn1;
}


#########################################
# display help text
sub ShowHelp()
{
    print "
           perl ASN.1 parser and code generator
           Copyright (C) tridge\@samba.org
           Copyright (C) metze\@samba.org

           Usage: pasn1.pl [options] <asn1file>

           Options:
             --help                this help page
             --output OUTNAME      put output in OUTNAME.*
             --parse               parse a asn1 file to a .pasn1 file
             --dump                dump a pasn1 file back to asn1
             --parser              create a C parser
             --keep                keep the .pasn1 file
           \n";
    exit(0);
}

# main program
GetOptions (
	    'help|h|?' => \$opt_help, 
	    'output=s' => \$opt_output,
	    'parse' => \$opt_parse,
	    'dump' => \$opt_dump,
	    'keep' => \$opt_keep
	    );

if ($opt_help) {
    ShowHelp();
    exit(0);
}

sub process_file($)
{
	my $asn1_file = shift;
	my $output;
	my $pasn1;

	my $basename = basename($asn1_file, ".asn1");

	if (!defined($opt_output)) {
		$output = $asn1_file;
	} else {
		$output = $opt_output . $basename;
	}

	my($pasn1_file) = util::ChangeExtension($output, ".pasn1");

	print "Compiling $asn1_file\n";

	if ($opt_parse) {
		$pasn1 = ASN1Parse($asn1_file);
		defined $pasn1 || die "Failed to parse $asn1_file";
		#ASN1Validator::Validate($pasn1);
		if ($opt_keep && !util::SaveStructure($pasn1_file, $pasn1)) {
			    die "Failed to save $pasn1_file\n";
		}
	} else {
		$pasn1 = util::LoadStructure($pasn1_file);
		defined $pasn1 || die "Failed to load $pasn1_file - maybe you need --parse\n";
	}

	if ($opt_dump) {
		print ASN1Dump::Dump($pasn1);
	}
}


foreach my $filename (@ARGV) {
	process_file($filename);
}
