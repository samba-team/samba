#!/usr/bin/perl -w

###################################################
# package to parse IDL files and generate code for 
# rpc functions in Samba
# Copyright tridge@samba.org 2000-2003
# released under the GNU GPL

use strict;

use FindBin qw($RealBin);
use lib "$RealBin";
use lib "$RealBin/lib";
use Getopt::Long;
use File::Basename;
use idl;
use dump;
use header;
use parser;
use eparser;
use validator;
use util;

my($opt_help) = 0;
my($opt_parse) = 0;
my($opt_dump) = 0;
my($opt_diff) = 0;
my($opt_header) = 0;
my($opt_parser) = 0;
my($opt_eparser) = 0;
my($opt_keep) = 0;
my($opt_output);

my $idl_parser = new idl;

#####################################################################
# parse an IDL file returning a structure containing all the data
sub IdlParse($)
{
    my $filename = shift;
    my $idl = $idl_parser->parse_idl($filename);
    util::CleanData($idl);
    return $idl;
}


#########################################
# display help text
sub ShowHelp()
{
    print "
           perl IDL parser and code generator
           Copyright (C) tridge\@samba.org

           Usage: pidl.pl [options] <idlfile>

           Options:
             --help                this help page
             --output OUTNAME      put output in OUTNAME.*
             --parse               parse a idl file to a .pidl file
             --dump                dump a pidl file back to idl
             --header              create a C header file
             --parser              create a C parser
             --eparser             create an ethereal parser
             --diff                run diff on the idl and dumped output
             --keep                keep the .pidl file
           \n";
    exit(0);
}

# main program
GetOptions (
	    'help|h|?' => \$opt_help, 
	    'output=s' => \$opt_output,
	    'parse' => \$opt_parse,
	    'dump' => \$opt_dump,
	    'header' => \$opt_header,
	    'parser' => \$opt_parser,
	    'eparser' => \$opt_eparser,
	    'diff' => \$opt_diff,
	    'keep' => \$opt_keep
	    );

if ($opt_help) {
    ShowHelp();
    exit(0);
}

sub process_file($)
{
	my $idl_file = shift;
	my $output;

	my $basename = basename($idl_file, ".idl");

	if (!defined($opt_output)) {
		$output = $idl_file;
	} else {
		$output = $opt_output . $basename;
	}

	my($pidl_file) = util::ChangeExtension($output, "pidl");

	if ($opt_parse) {
		print "Generating $pidl_file from $idl_file\n";
		my($idl) = IdlParse($idl_file);
		defined $idl || die "Failed to parse $idl_file";
		util::SaveStructure($pidl_file, $idl) || die "Failed to save $pidl_file";
		
		IdlValidator::Validate($idl);
	}
	
	if ($opt_dump) {
		my($idl) = util::LoadStructure($pidl_file);
		print IdlDump::Dump($idl);
	}
	
	if ($opt_header) {
		my($idl) = util::LoadStructure($pidl_file);
		my($header) = util::ChangeExtension($output, "h");
		print "Generating $header\n";
		util::FileSave($header, IdlHeader::Parse($idl));
	}
	
	if ($opt_parser) {
		my($idl) = util::LoadStructure($pidl_file);
		my($parser) = util::ChangeExtension($output, "c");
		print "Generating $parser\n";
		IdlParser::Parse($idl, $parser);
	}
	
	if ($opt_eparser) {
		my($idl) = util::LoadStructure($pidl_file);
		my($parser) = util::ChangeExtension($output, "c");
		print "Generating $parser for ethereal\n";
		util::FileSave($parser, IdlEParser::Parse($idl));
	}
	
	if ($opt_diff) {
		my($idl) = util::LoadStructure($pidl_file);
		my($tempfile) = util::ChangeExtension($output, "tmp");
		util::FileSave($tempfile, IdlDump::Dump($idl));
		system("diff -wu $idl_file $tempfile");
		unlink($tempfile);
	}
	
	if (!$opt_keep) {
		system("rm -f $pidl_file");
	}
}


foreach my $filename (@ARGV) {
	process_file($filename);
}
