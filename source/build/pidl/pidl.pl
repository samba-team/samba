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
use server;
use parser;
use eparser;
use validator;
use util;
use template;

my($opt_help) = 0;
my($opt_parse) = 0;
my($opt_dump) = 0;
my($opt_diff) = 0;
my($opt_header) = 0;
my($opt_template) = 0;
my($opt_server) = 0;
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
             --server              create server boilerplate
             --template            print a template for a pipe
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
	    'server' => \$opt_server,
	    'template' => \$opt_template,
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
	my $pidl;

	my $basename = basename($idl_file, ".idl");

	if (!defined($opt_output)) {
		$output = $idl_file;
	} else {
		$output = $opt_output . $basename;
	}

	my($pidl_file) = util::ChangeExtension($output, ".pidl");

	print "Compiling $idl_file\n";

	if ($opt_parse) {
		$pidl = IdlParse($idl_file);
		defined $pidl || die "Failed to parse $idl_file";
#		IdlValidator::Validate($pidl);
		if ($opt_keep && !util::SaveStructure($pidl_file, $pidl)) {
			    die "Failed to save $pidl_file\n";
		}
	} else {
		$pidl = util::LoadStructure($pidl_file);
		defined $pidl || die "Failed to load $pidl_file - maybe you need --parse\n";
	}

	if ($opt_dump) {
		print IdlDump::Dump($pidl);
	}

	if ($opt_header) {
		my($header) = util::ChangeExtension($output, ".h");
		util::FileSave($header, IdlHeader::Parse($pidl));
	}

	if ($opt_server) {
		my($server) = util::ChangeExtension($output, "_s.c");
		util::FileSave($server, IdlServer::Parse($pidl));
	}

	if ($opt_parser) {
		my($parser) = util::ChangeExtension($output, ".c");
		IdlParser::Parse($pidl, $parser);
	}

	if ($opt_eparser) {
		my($parser) = dirname($output) . "/packet-dcerpc-$basename.c";
		IdlEParser::Parse($pidl, $parser);
		$parser = dirname($output) . "/packet-dcerpc-proto-$basename.h";
		IdlEParser::ParseHeader($pidl, $parser);
		my($header) = dirname($output) . "/packet-dcerpc-proto.h";
		open(OUT, ">>$header") || die "can't open $header";
		print OUT "#include \"ndr_$basename.h\"\n";
		print OUT "#include \"packet-dcerpc-proto-$basename.h\"\n";
		close(OUT);
	}

	if ($opt_diff) {
		my($tempfile) = util::ChangeExtension($output, ".tmp");
		util::FileSave($tempfile, IdlDump::Dump($pidl));
		system("diff -wu $idl_file $tempfile");
		unlink($tempfile);
	}

	if ($opt_template) {
		print IdlTemplate::Parse($pidl);
	}
}


foreach my $filename (@ARGV) {
	process_file($filename);
}
