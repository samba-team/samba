#!/usr/bin/perl -w

###################################################
# package to parse IDL files and generate code for 
# rpc functions in Samba
# Copyright tridge@samba.org 2000
# released under the GNU GPL

use strict;
use Getopt::Long;
use Data::Dumper;
use Parse::RecDescent;
use dump;
use header;
use parser;
use eparser;
use util;

my($opt_help) = 0;
my($opt_parse) = 0;
my($opt_dump) = 0;
my($opt_diff) = 0;
my($opt_header) = 0;
my($opt_parser) = 0;
my($opt_eparser) = 0;

#####################################################################
# parse an IDL file returning a structure containing all the data
sub IdlParse($)
{
    # this autoaction allows us to handle simple nodes without an action
#    $::RD_TRACE = 1;
    $::RD_AUTOACTION = q { 
                          $#item==1 && ref($item[1]) eq "" ? 
                          $item[1] : 
                          "XX_" . $item[0] . "_XX[$#item]"  };
    my($filename) = shift;
    my($grammer) = util::FileLoad("idl.gram");    
    my($parser) = Parse::RecDescent->new($grammer);
    my($saved_sep) = $/;
    undef $/;
    my($idl) = $parser->idl(`cpp $filename`);
    $/ = $saved_sep;
    util::CleanData($idl);
    return $idl;
}


#########################################
# display help text
sub ShowHelp()
{
    print "
           perl IDL parser and code generator
           Copyright tridge\@samba.org

           Usage: pidl.pl [options] <idlfile>

           Options:
             --help                this help page
             --parse               parse a idl file to a .pidl file
             --dump                dump a pidl file back to idl
             --header              create a C header file
             --parser              create a C parser
             --eparser             create an ethereal parser
             --diff                run diff on the idl and dumped output
           \n";
    exit(0);
}

# main program
GetOptions (
	    'help|h|?' => \$opt_help, 
	    'parse' => \$opt_parse,
	    'dump' => \$opt_dump,
	    'header' => \$opt_header,
	    'parser' => \$opt_parser,
	    'eparser' => \$opt_eparser,
	    'diff' => \$opt_diff
	    );

if ($opt_help) {
    ShowHelp();
    exit(0);
}

my($idl_file) = shift;
die "ERROR: You must specify an idl file to process" unless ($idl_file);

my($pidl_file) = util::ChangeExtension($idl_file, "pidl");

if ($opt_parse) {
    print "Generating $pidl_file\n";
    my($idl) = IdlParse($idl_file);
    util::SaveStructure($pidl_file, $idl) || die "Failed to save $pidl_file";
}

if ($opt_dump) {
    my($idl) = util::LoadStructure($pidl_file);
    print IdlDump::Dump($idl);
}

if ($opt_header) {
    my($idl) = util::LoadStructure($pidl_file);
    my($header) = util::ChangeExtension($idl_file, "h");
    print "Generating $header\n";
    util::FileSave($header, IdlHeader::Dump($idl));
}

if ($opt_parser) {
    my($idl) = util::LoadStructure($pidl_file);
    my($parser) = util::ChangeExtension($idl_file, "c");
    print "Generating $parser\n";
    util::FileSave($parser, IdlParser::Parse($idl));
}

if ($opt_eparser) {
    my($idl) = util::LoadStructure($pidl_file);
    my($parser) = util::ChangeExtension($idl_file, "c");
    print "Generating $parser for ethereal\n";
    util::FileSave($parser, IdlEParser::Parse($idl));
}

if ($opt_diff) {
    my($idl) = util::LoadStructure($pidl_file);
    my($tempfile) = util::ChangeExtension($idl_file, "tmp");
    util::FileSave($tempfile, IdlDump::Dump($idl));
    system("diff -wu $idl_file $tempfile");
    unlink($tempfile);
}
