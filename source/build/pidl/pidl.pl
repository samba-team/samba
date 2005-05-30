#!/usr/bin/perl -w

###################################################
# package to parse IDL files and generate code for
# rpc functions in Samba
# Copyright tridge@samba.org 2000-2003
# Copyright jelmer@samba.org 2005
# released under the GNU GPL

use strict;

use FindBin qw($RealBin);
use lib "$RealBin/..";
use Getopt::Long;
use File::Basename;
use pidl::idl;
use pidl::dump;
use pidl::ndr_client;
use pidl::ndr_header;
use pidl::ndr_parser;
use pidl::server;
use pidl::dcom_proxy;
use pidl::dcom_stub;
use pidl::com_header;
use pidl::odl;
use pidl::eth_parser;
use pidl::eth_header;
use pidl::validator;
use pidl::typelist;
use pidl::util;
use pidl::template;
use pidl::swig;
use pidl::compat;

my($opt_help) = 0;
my($opt_parse) = 0;
my($opt_dump) = 0;
my($opt_diff) = 0;
my($opt_header);
my($opt_template) = 0;
my($opt_client) = 0;
my($opt_server) = 0;
my($opt_parser);
my($opt_eth_parser);
my($opt_eth_header);
my($opt_keep) = 0;
my($opt_swig) = 0;
my($opt_dcom_proxy) = 0;
my($opt_com_header) = 0;
my($opt_odl) = 0;
my($opt_quiet) = 0;
my($opt_output);
my($opt_warn_compat) = 0;

my $idl_parser = new idl;

#########################################
# display help text
sub ShowHelp()
{
print "perl IDL parser and code generator
Copyright (C) tridge\@samba.org

Usage: pidl.pl [options] <idlfile>

Options:
 --help                this help page
 --output=OUTNAME      put output in OUTNAME.*
 --parse               parse a idl file to a .pidl file
 --dump                dump a pidl file back to idl
 --header[=OUTFILE]    create a C NDR header file
 --parser[=OUTFILE]    create a C NDR parser
 --client              create a C NDR client
 --server              create server boilerplate
 --template            print a template for a pipe
 --eth-parser          create an ethereal parser
 --eth-header          create an ethereal header file
 --swig                create swig wrapper file
 --diff                run diff on the idl and dumped output
 --keep                keep the .pidl file
 --odl                 accept ODL input
 --dcom-proxy          create DCOM proxy (implies --odl)
 --com-header          create header for COM interfaces (implies --odl)
 --warn-compat         warn about incompatibility with other compilers
 --quiet               be quiet
\n";
    exit(0);
}

# main program
GetOptions (
	    'help|h|?' => \$opt_help, 
	    'output=s' => \$opt_output,
	    'parse' => \$opt_parse,
	    'dump' => \$opt_dump,
	    'header:s' => \$opt_header,
	    'server' => \$opt_server,
	    'template' => \$opt_template,
	    'parser:s' => \$opt_parser,
        'client' => \$opt_client,
	    'eth-parser:s' => \$opt_eth_parser,
		'eth-header:s' => \$opt_eth_header,
	    'diff' => \$opt_diff,
		'odl' => \$opt_odl,
	    'keep' => \$opt_keep,
	    'swig' => \$opt_swig,
		'dcom-proxy' => \$opt_dcom_proxy,
		'com-header' => \$opt_com_header,
		'quiet' => \$opt_quiet,
		'warn-compat' => \$opt_warn_compat
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
	my $ndr;

	my $basename = basename($idl_file, ".idl");

	if (!defined($opt_output)) {
		$output = $idl_file;
	} else {
		$output = $opt_output . $basename;
	}

	my($pidl_file) = util::ChangeExtension($output, ".pidl");

	unless ($opt_quiet) { print "Compiling $idl_file\n"; }

	if ($opt_parse) {
		$pidl = $idl_parser->parse_idl($idl_file);
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
			"#include \"lib/com/dcom/dcom.h\"\n" .$res);
		}
		$opt_odl = 1;
	}

	if ($opt_warn_compat) {
		IDLCompat::Check($pidl);
	}

	if ($opt_odl) {
		$pidl = ODL::ODL2IDL($pidl);
	}

	if (defined($opt_header) or defined($opt_eth_parser) or defined($opt_eth_header) or $opt_client or $opt_server or defined($opt_parser)) {
		$ndr = Ndr::Parse($pidl);
#		print util::MyDumper($ndr);
	}

	if (defined($opt_header)) {
		my $header = $opt_header;
		if ($header eq "") {
			$header = util::ChangeExtension($output, ".h");
		}
		util::FileSave($header, NdrHeader::Parse($ndr));
		if ($opt_swig) {
		  my($filename) = $output;
		  $filename =~ s/\/ndr_/\//;
		  $filename = util::ChangeExtension($filename, ".i");
		  IdlSwig::RewriteHeader($pidl, $header, $filename);
		}
	}

	if (defined($opt_eth_header)) {
	  my($eparserhdr) = $opt_eth_header;
	  if ($eparserhdr eq "") {
		  $eparserhdr = dirname($output) . "/packet-dcerpc-$basename.h";
	  }

	  util::FileSave($eparserhdr, EthHeader::Parse($ndr));
	}

	if ($opt_client) {
		my ($client) = util::ChangeExtension($output, "_c.c");
		my $h_filename = util::ChangeExtension($output, ".h");

		util::FileSave($client, NdrClient::Parse($ndr,$h_filename));
	}

	if ($opt_server) {
		my $h_filename = util::ChangeExtension($output, ".h");
		my $dcom = "";

		foreach my $x (@{$pidl}) {
			next if ($x->{TYPE} ne "INTERFACE");

			if (util::has_property($x, "object")) {
				$dcom .= DCOMStub::ParseInterface($x);
			}
		}

		util::FileSave(util::ChangeExtension($output, "_s.c"), NdrServer::Parse($ndr,$h_filename));

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

	if (defined($opt_parser)) {
		my $parser = $opt_parser;
		if ($parser eq "") {
			$parser = util::ChangeExtension($output, ".c");
		}
		
		util::FileSave($parser, NdrParser::Parse($ndr, $parser));
	}

	if (defined($opt_eth_parser)) {
	  my($eparser) = $opt_eth_parser;
	  if ($eparser eq "") {
		  $eparser = dirname($output) . "/packet-dcerpc-$basename.c";
	  }
	  util::FileSave($eparser, EthParser::Parse($ndr, $basename, $eparser));
	}


	if ($opt_template) {
		print IdlTemplate::Parse($pidl);
	}
}

foreach my $filename (@ARGV) {
	process_file($filename);
}
