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
use ndr_client;
use ndr_header;
use ndr;
use server;
use dcom_proxy;
use dcom_stub;
use com_header;
use odl;
use eparser;
use validator;
use typelist;
use util;
use template;
use swig;

my($opt_help) = 0;
my($opt_parse) = 0;
my($opt_dump) = 0;
my($opt_diff) = 0;
my($opt_header) = 0;
my($opt_template) = 0;
my($opt_client) = 0;
my($opt_server) = 0;
my($opt_parser) = 0;
my($opt_eparser) = 0;
my($opt_keep) = 0;
my($opt_swig) = 0;
my($opt_dcom_proxy) = 0;
my($opt_com_header) = 0;
my($opt_odl) = 0;
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
         --header              create a C NDR header file
         --parser              create a C NDR parser
         --client              create a C NDR client
         --server              create server boilerplate
         --template            print a template for a pipe
         --eparser             create an ethereal parser
         --swig                create swig wrapper file
         --diff                run diff on the idl and dumped output
         --keep                keep the .pidl file
         --odl                 accept ODL input
         --dcom-proxy          create DCOM proxy (implies --odl)
         --com-header          create header for COM interfaces (implies --odl)
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
        'client' => \$opt_client,
	    'eparser' => \$opt_eparser,
	    'diff' => \$opt_diff,
		'odl' => \$opt_odl,
	    'keep' => \$opt_keep,
	    'swig' => \$opt_swig,
		'dcom-proxy' => \$opt_dcom_proxy,
		'com-header' => \$opt_com_header
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
		defined @$pidl || die "Failed to parse $idl_file";
		typelist::LoadIdl($pidl);
		IdlValidator::Validate($pidl);
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

	if ($opt_diff) {
		my($tempfile) = util::ChangeExtension($output, ".tmp");
		util::FileSave($tempfile, IdlDump::Dump($pidl));
		system("diff -wu $idl_file $tempfile");
		unlink($tempfile);
	}

	if ($opt_com_header) {
		my $res = COMHeader::Parse($pidl);
		if ($res) {
			my $h_filename = dirname($output) . "/com_$basename.h";
			util::FileSave($h_filename, 
			"#include \"librpc/gen_ndr/ndr_orpc.h\"\n" . 
			"#include \"librpc/gen_ndr/ndr_$basename.h\"\n" . 
			$res);
		}
		$opt_odl = 1;
	}

	if ($opt_dcom_proxy) {
		my $res = DCOMProxy::Parse($pidl);
		if ($res) {
			my ($client) = util::ChangeExtension($output, "_p.c");
			util::FileSave($client, 
			"#include \"includes.h\"\n" .
			"#include \"librpc/gen_ndr/com_$basename.h\"\n" . 
			"#include \"lib/dcom/common/orpc.h\"\n". $res);
		}
		$opt_odl = 1;
	}

	if ($opt_odl) {
		$pidl = ODL::ODL2IDL($pidl);
	}

	if ($opt_header) {
		my($header) = util::ChangeExtension($output, ".h");
		util::FileSave($header, NdrHeader::Parse($pidl));
		if ($opt_eparser) {
		  my($eparserhdr) = dirname($output) . "/packet-dcerpc-$basename.h";
		  IdlEParser::RewriteHeader($pidl, $header, $eparserhdr);
		}
		if ($opt_swig) {
		  my($filename) = $output;
		  $filename =~ s/\/ndr_/\//;
		  $filename = util::ChangeExtension($filename, ".i");
		  IdlSwig::RewriteHeader($pidl, $header, $filename);
		}
	}

	if ($opt_client) {
		my ($client) = util::ChangeExtension($output, "_c.c");
		my $res = "";
		my $h_filename = util::ChangeExtension($output, ".h");

		$res .= "#include \"includes.h\"\n";
		$res .= "#include \"$h_filename\"\n\n";

		foreach my $x (@{$pidl}) {
			$res .= NdrClient::ParseInterface($x);
		}

		util::FileSave($client, $res);
	}

	if ($opt_server) {
		my $h_filename = util::ChangeExtension($output, ".h");
		my $plain = "";
		my $dcom = "";

		foreach my $x (@{$pidl}) {
			next if ($x->{TYPE} ne "INTERFACE");

			if (util::has_property($x, "object")) {
				$dcom .= DCOMStub::ParseInterface($x);
			} else {
				$plain .= IdlServer::ParseInterface($x);
			}
		}

		if ($plain ne "") {
			util::FileSave(util::ChangeExtension($output, "_s.c"), $plain);
		}

		if ($dcom ne "") {
			$dcom = "
#include \"includes.h\"
#include \"$h_filename\"
#include \"rpc_server/dcerpc_server.h\"
#include \"rpc_server/common/common.h\"

$dcom
";
			util::FileSave(util::ChangeExtension($output, "_d.c"), $dcom);
		}
	}

	if ($opt_parser) {
		my($parser) = util::ChangeExtension($output, ".c");
		util::FileSave($parser, NdrParser::Parse($pidl, $parser));
		if($opt_eparser) {
		  my($eparser) = dirname($output) . "/packet-dcerpc-$basename.c";
		  IdlEParser::RewriteC($pidl, $parser, $eparser);
		}
	}

	if ($opt_template) {
		print IdlTemplate::Parse($pidl);
	}
}


foreach my $filename (@ARGV) {
	process_file($filename);
}
