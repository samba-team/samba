# SMB Build Environment Path Checks
# -------------------------------------------------------
#  Copyright (C) Stefan (metze) Metzmacher 2004
#  Released under the GNU GPL
# -------------------------------------------------------
#

#################################################
# Directory handling stuff to support both the
# legacy SAMBA directories and FHS compliant
# ones...
$prefix = "/usr/local/samba";

if (defined($options{"with-fhs"})) {
    $configdir="$sysconfdir/samba";
    $lockdir="$VARDIR/cache/samba";
    $piddir="$VARDIR/run/samba";
    $logfilebase="$VARDIR/log/samba";
    $privatedir="$CONFIGDIR/private";
    $libdir="$prefix/lib/samba";
    $swatdir="$DATADIR/samba/swat";
    $configdir="$LIBDIR";
    $logfilebase="$VARDIR";
    $lockdir="$VARDIR/locks";
    $piddir="$VARDIR/locks";
    $privatedir="$prefix/private";
    $swatdir="$prefix/swat";
}

#################################################
# set private directory location
if (defined($options{"with-privatedir"})) {
	$privatedir = $options{"with-privatedir"};
}

#################################################
# set lock directory location
if (defined($options{"with-lockdir"})) {
	$lockdir = $options{"with-lockdir"};
}

#################################################
# set pid directory location
if (defined($options{"with-piddir"})) {
	$piddir = $options{"with-piddir"};
}

#################################################
# set configuration directory location
if (defined($options{"with-configdir"})) {
	$configdir = $options{"with-configdir"};
}

#################################################
# set log directory location
if (defined($options{"with-logfilebase"})) {
	$logfilebase = $options{"with-logfilebase"};
}

$debug = 0;
$debug = 1 if (defined($options{"enable-debug"}));

$developer = 0;
if (defined($options{"enable-developer"})) {
	$debug = 1;
	$developer = 1;
	$CFLAGS+=" -g -Wall";
	$DEVELOPER_CFLAGS="-Wshadow -Werror-implicit-function-declaration -Wstrict-prototypes -Wpointer-arith -Wcast-qual -Wcast-align -Wwrite-strings -Wdeclaration-after-statement -Wmissing-format-attribute -Wformat=2 -DDEBUG_PASSWORD -DDEVELOPER";
}

if (defined($options{"enable-krb5developer"})) {
	$debug = 1;
	$developer = 1;
	$DEVELOPER_CFLAGS="-Wshadow -Wpointer-arith -Wcast-qual -Wcast-align -Wwrite-strings  -Wdeclaration-after-statement -Wmissing-format-attribute -DDEBUG_PASSWORD -DDEVELOPER";
}

if (defined($options{"enable-gtkdeveloper"})) {
	$debug = 1;
	$developer = 1;
	$CFLAGS="${CFLAGS} -g -Wall";
	$DEVELOPER_CFLAGS="-Wpointer-arith -Wcast-qual -Wcast-align -Wwrite-strings  -Wdeclaration-after-statement -Wmissing-format-attribute -DDEBUG_PASSWORD -DDEVELOPER";
}

$experimental = 0;
$experimental = 1 if (defined($options{"enable-experimental"}));

if (defined($options{"disable-ext-lib"})) {
	@libs = split /,/, $options{"disable-ext-lib"};

	foreach (@libs) {
		$FIXME{$_} = 0;
	}
}

if (defined($options{"exclude-modules"})) {
	@libs = split /,/, $options{"exclude-modules"};

	foreach (@libs) {
		$FIXME{$_} = 0;
	}
}

if (defined($options{"shared-modules"})) {
	@libs = split /,/, $options{"shared-modules"};

	foreach (@libs) {
		$FIXME{$_} = "shared";
	}
}

if (defined($options{"static-modules"})) {
	@libs = split /,/, $options{"static-modules"};

	foreach (@libs) {
		$FIXME{$_} = "static";
	}
}

1;
