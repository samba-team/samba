# Samba Build System
# - config.mk parsing functions
#
#  Copyright (C) Stefan (metze) Metzmacher 2004
#  Copyright (C) Jelmer Vernooij 2005
#  Released under the GNU GPL
#

package smb_build::config_mk;
use smb_build::input;
use File::Basename;

use strict;

my $section_types = {
	"EXT_LIB" => {
		"LIBS"			=> "list",
		"CFLAGS"		=> "list",
		"CPPFLAGS"		=> "list",
		"LDFLAGS"		=> "list",
		},
	"SUBSYSTEM" => {
		"INIT_FUNCTION"		=> "string",
		"OBJ_FILES"		=> "list",

		"REQUIRED_SUBSYSTEMS"	=> "list",

		"ENABLE"		=> "bool",
		"NOPROTO"		=> "bool",

		"MANPAGE"		=> "string",

		"PUBLIC_PROTO_HEADER" => "string",
		"PRIVATE_PROTO_HEADER" => "string"
		},
	"MODULE" => {
		"SUBSYSTEM"		=> "string",

		"INIT_FUNCTION"		=> "string",
		"OBJ_FILES"		=> "list",

		"REQUIRED_SUBSYSTEMS"	=> "list",

		"ENABLE"		=> "bool",
		"NOPROTO"		=> "bool",

		"MANPAGE"		=> "string",
		},
	"BINARY" => {
		"OBJ_FILES"		=> "list",

		"REQUIRED_SUBSYSTEMS"	=> "list",

		"ENABLE"		=> "bool",
		"NOPROTO"		=> "bool",

		"MANPAGE"		=> "string",
		"INSTALLDIR"		=> "string",
		},
	"LIBRARY" => {
		"MAJOR_VERSION"		=> "string",
		"MINOR_VERSION"		=> "string",
		"RELEASE_VERSION"	=> "string",

		"INIT_FUNCTION"		=> "string",
		"OBJ_FILES"		=> "list",

		"DESCRIPTION" => "string",

		"REQUIRED_SUBSYSTEMS"	=> "list",

		"ENABLE"		=> "bool",
		"NOPROTO"		=> "bool",

		"MANPAGE"		=> "string",

		"PUBLIC_HEADERS" => "list",

		"PUBLIC_PROTO_HEADER" => "string",
		"PRIVATE_PROTO_HEADER" => "string"
		}
};

use vars qw(@parsed_files);

@parsed_files = ();

###########################################################
# The parsing function which parses the file
#
# $result = _parse_config_mk($filename)
#
# $filename -	the path of the config.mk file
#		which should be parsed
sub run_config_mk($$)
{
	sub run_config_mk($$);
	my ($input, $filename) = @_;
	my $result;
	my $linenum = -1;
	my $infragment = 0;
	my $section = "GLOBAL";
	my $makefile = "";

	push (@parsed_files, $filename);
	
	open(CONFIG_MK, $filename) or die("Can't open `$filename'\n");
	my @lines = <CONFIG_MK>;
	close(CONFIG_MK);

	my $line = "";
	my $prev = "";

	foreach (@lines) {
		$linenum++;

		# lines beginning with '#' are ignored
		next if (/^\#.*$/);
		
		if (/^(.*)\\$/) {
			$prev .= $1;
			next;
		} else {
			$line = "$prev$_";
			$prev = "";
		}

		if ($line =~ /^\[([a-zA-Z0-9_:]+)\][\t ]*$/) 
		{
			$section = $1;
			$infragment = 0;
			next;
		}

		# include
		if ($line =~ /^include (.*)$/) {
			$makefile .= run_config_mk($input, dirname($filename)."/$1");
			next;
		}

		# empty line
		if ($line =~ /^[ \t]*$/) {
			$section = "GLOBAL";
			if ($infragment) { $makefile.="\n"; }
			next;
		}

		# global stuff is considered part of the makefile
		if ($section eq "GLOBAL") {
			$makefile .= $line;
			$infragment = 1;
			next;
		}

		
		# Assignment
		if ($line =~ /^([a-zA-Z0-9_]+)[\t ]*=(.*)$/) {
			$result->{$section}{$1}{VAL} = $2;
			$result->{$section}{$1}{KEY} = $1;
		
			next;
		}

		die("$filename:$linenum: Bad line while parsing $filename");
	}

	foreach my $section (keys %{$result}) {
		my ($type, $name) = split(/::/, $section, 2);

		my $sectype = $section_types->{$type};
		if (not defined($sectype)) {
			die($filename.":[".$section."] unknown section type \"".$type."\"!");
		}

		$input->{$name}{NAME} = $name;
		$input->{$name}{TYPE} = $type;
		$input->{$name}{BASEDIR} = dirname($filename);

		foreach my $key (values %{$result->{$section}}) {
			$key->{VAL} = smb_build::input::strtrim($key->{VAL});
			my $vartype = $sectype->{$key->{KEY}};
			if (not defined($vartype)) {
				die($filename.":[".$section."]: unknown attribute type \"$key->{KEY}\"!");
			}
			if ($vartype eq "string") {
				$input->{$name}{$key->{KEY}} = $key->{VAL};
			} elsif ($vartype eq "list") {
				$input->{$name}{$key->{KEY}} = [smb_build::input::str2array($key->{VAL})];
			} elsif ($vartype eq "bool") {
				if (($key->{VAL} ne "YES") and ($key->{VAL} ne "NO")) {
					die("Invalid value for bool attribute $key->{KEY}: $key->{VAL} in section $section");
				}
				$input->{$name}{$key->{KEY}} = $key->{VAL};
			}
		}
	}

	return $makefile;
}

1;
