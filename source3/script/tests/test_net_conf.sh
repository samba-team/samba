#!/bin/sh
#
# Blackbox test for net [rpc] conf.
#
# Copyright (C) 2011 Vicentiu Ciorbaru <cvicentiu@gmail.com>

if [ $# -lt 3 ]; then
cat <<EOF
Usage: test_net_conf.sh SCRIPTDIR SERVERCONFFILE NET CONFIGURATION [rpc]
EOF
exit 1;
fi

SCRIPTDIR="$1"
SERVERCONFFILE="$2"
NET="$3"
CONFIGURATION="$4"
RPC="$5"

LOGDIR_PREFIX="conf_test"

# remove old logs:
for OLDDIR in $(find ${PREFIX} -type d -name "${LOGDIR_PREFIX}_*") ; do
	echo "removing old directory ${OLDDIR}"
	rm -rf ${OLDDIR}
done


NET="$VALGRIND ${NET:-$BINDIR/net} $CONFIGURATION"
DIR=$(mktemp -d ${PREFIX}/${LOGDIR_PREFIX}_XXXXXX)
LOG=$DIR/log


if test "x${RPC}" = "xrpc" ; then
	NETCMD="${NET} -U${USERNAME}%${PASSWORD} -I ${SERVER_IP} rpc"
else
	NETCMD="${NET}"
fi

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

failed=0

log_print() {
    RC=$?
    echo "CMD: $*" >>$LOG
    echo "RC: $RC" >> $LOG
    return $RC
#    echo -n .
}

test_conf_addshare()
{
    echo '\nTesting conf addshare' >> $LOG
    echo ------------------------- >> $LOG
    echo '\nDropping existing configuration' >> $LOG

    $NETCMD conf drop
    log_print $NETCMD conf drop
    test "x$?" = "x0" || {
	echo 'ERROR: RC does not match, expected: 0' | tee -a $LOG
	return 1
    }

#create a lot of shares
    for i in $(seq 1 100); do
	if [ $(($i % 2)) -eq 0 ]; then
		$NETCMD conf addshare share$i /tmp "writeable=y" "guest_ok=n" \
					   "test comment" >>$DIR/addshare_exp \
							  2>>$DIR/addshare_exp
		log_print $NETCMD conf addshare share$i /tmp "writeable=y" "guest_ok=n" \
					   "test comment"
	else
		$NETCMD conf addshare share$i /tmp "writeable=n" "guest_ok=y" \
					   "test comment" >>$DIR/addshare_exp \
							  2>>$DIR/addshare_exp
		log_print $NETCMD conf addshare share$i /tmp "writeable=n" "guest_ok=y" \
					   "test comment"
	fi
	test "x$?" = "x0" || {
		echo 'ERROR: RC does not match, expected: 0' | tee -a $LOG
		return 1
	}
    done

    $NETCMD conf listshares > $DIR/listshares_out
    log_print $NETCMD conf listshares
    test "x$?" = "x0" || {
	echo 'ERROR: RC does not match, expected: 0' | tee -a $LOG
	return 1
    }

    for i in $(seq 1 100); do
	grep "share$i" $DIR/listshares_out >/dev/null 2>>$LOG
	if [ "$?" = "1" ]; then
		echo "ERROR: share not found" | tee -a $LOG
		return 1
	fi
    done

#check the integrity of the shares
#if it fails, it can also point to an error in showshare
    for i in $(seq 1 100); do
	$NETCMD conf showshare share$i > $DIR/showshare_out
	test "x$?" = "x0" || {
		echo 'ERROR: RC does not match, expected: 0' | tee -a $LOG
		return 1
	}

	grep "path" $DIR/showshare_out >/dev/null 2>>$LOG
	if [ "$?" = "1" ]; then
		echo "ERROR: share not found" | tee -a $LOG
		return 1
	fi

	if [ $(($i % 2)) -eq 0 ]; then
		grep "read only *= *no" $DIR/showshare_out >/dev/null 2>>$LOG
		if [ "$?" = "1" ]; then
			echo "ERROR: share not set correctly" | tee -a $LOG
			return 1
		fi
	else
		grep "read only *= *yes" $DIR/showshare_out >/dev/null 2>>$LOG
		if [ "$?" = "1" ]; then
			echo "ERROR: share not set correctly" | tee -a $LOG
			return 1
		fi
	fi

	if [ $(($i % 2)) -eq 0 ]; then
		grep "guest ok *= *no" $DIR/showshare_out >/dev/null 2>>$LOG
		if [ "$?" = "1" ]; then
			echo "ERROR: share not set correctly" | tee -a $LOG
			return 1
		fi
	else
		grep "guest ok *= *yes" $DIR/showshare_out >/dev/null 2>>$LOG
		if [ "$?" = "1" ]; then
			echo "ERROR: share not set correctly" | tee -a $LOG
			return 1
		fi
	fi

	grep "comment *= *test comment" $DIR/showshare_out >/dev/null 2>>$LOG
	if [ "$?" = "1" ]; then
		echo "ERROR: share not set correctly" | tee -a $LOG
		return 1
	fi
    done

    echo '\nTaking a conf snapshot for later use' >> $LOG
    $NETCMD conf list > $DIR/conf_import_in
    log_print $NETCMD conf list
    test "x$?" = "x0" || {
	echo 'ERROR: RC does not match, expected: 0' | tee -a $LOG
	return 1
    }
}

test_conf_addshare_existing()
{
#try adding an already existing share
    echo '\nAdding an already existing share' >>$LOG
    $NETCMD conf addshare share1 /tmp "writeable=n" "guest_ok=y" \
			      "test comment" >>$DIR/addshare_exp \
					    2>>$DIR/addshare_exp
    log_print $NETCMD conf addshare share1 /tmp "writeable=n" "guest_ok=y" \
			      "test comment"
    test "x$?" = "x255" || {
	echo 'ERROR: RC does not match, expected: 0' | tee -a $LOG
	return 1
    }

    test -z `cat $DIR/addshare_exp` && {
	echo "ERROR: addshare output does not match" >> $LOG
	return 1
    }

    return 0
}

test_conf_addshare_usage()
{
#check to see if command prints usage
    echo '\nChecking usage' >>$LOG
    $NETCMD conf addshare > $DIR/addshare_usage_exp
    log_print $NETCMD conf addshare
    test "x$?" = "x255" || {
	echo 'ERROR: RC does not match, expected: 255' | tee -a $LOG
	return 1
    }

    grep "$RPC *conf addshare" $DIR/addshare_usage_exp >/dev/null 2>>$LOG
    if [ "$?" = "1" ]; then
	echo "ERROR: no/wrong usage message printed" | tee -a $LOG
	return 1
    fi
}

test_conf_delshare()
{
    echo '\nTesting conf delshare' >>$LOG
    echo ------------------------- >> $LOG
    echo -n '\n' >> $LOG

    $NETCMD conf delshare share1
    log_print $NETCMD conf delshare share1
    test "x$?" = "x0" || {
	echo 'ERROR: RC does not match, expected: 0' | tee -a $LOG
	return 1
    }

    $NETCMD conf listshares > $DIR/listshares_out
    log_print $NETCMD conf listshares
    test "x$?" = "x0" || {
	echo 'ERROR: RC does not match, expected: 0' | tee -a $LOG
	return 1
    }

    grep "share1$" $DIR/listshares_out >/dev/null 2>>$LOG
    if [ "$?" = "0" ]; then
	echo "ERROR: delshare did not delete 'share1'" | tee -a $LOG
	return 1
    fi
}

test_conf_delshare_empty()
{
    echo '\nAttempting to delete non_existing share'
    $NETCMD conf delshare share1
    log_print $NETCMD conf delshare share1
    test "x$?" = "x255" || {
	echo 'ERROR: RC does not match, expected: 255' | tee -a $LOG
	return 1
    }

}

test_conf_delshare_usage()
{
    echo '\nChecking usage' >>$LOG
    $NETCMD conf delshare > $DIR/delshare_usage_exp
    log_print $NETCMD conf delshare
    test "x$?" = "x255" || {
	echo 'ERROR: RC does not match, expected: 255' | tee -a $LOG
	return 1
    }

    grep "$RPC *conf delshare" $DIR/delshare_usage_exp >/dev/null 2>>$LOG
    if [ "$?" = "1" ]; then
	echo "ERROR: no/wrong usage message printed" | tee -a $LOG
	return 1
    fi
}

test_conf_showshare_case()
{
	echo '\nChecking case in net conf shareshare' >>$LOG

	echo '\nDropping existing configuration' >> $LOG
	$NETCMD conf drop
	log_print $NETCMD conf drop
	test "x$?" = "x0" || {
		echo 'ERROR: RC does not match, expected: 0' | tee -a $LOG
		return 1
	}

	for share in UPPERCASE lowercase; do

		log_print $NETCMD conf addshare $share /tmp
		$NETCMD conf addshare $share /tmp \
			>>$DIR/case_addshare_exp \
			2>>$DIR/case_addshare_exp

		# Lookup share in different case, check that output has
		# share name in correct case.
		switch_case=$(echo $share | tr 'A-Za-z' 'a-zA-Z')
		log_print $NETCMD conf showshare $switch_case
		$NETCMD conf showshare $switch_case > $DIR/showshare_out
		test "x$?" = "x0" || {
			echo 'ERROR: net conf showshare failed.' | tee -a $LOG
			return 1
		}

		grep "\[$share\]" $DIR/showshare_out >/dev/null 2>>$LOG
		if [ "$?" = "1" ]; then
			echo "ERROR: share not found" | tee -a $LOG
			return 1
		fi
	done

}

test_conf_drop()
{

    echo '\nTesting conf drop' >> $LOG
    echo ------------------------- >> $LOG
    echo '\nDropping existing configuration' >> $LOG

    $NETCMD conf drop
    log_print $NETCMD conf drop
    test "x$?" = "x0" || {
	echo 'ERROR: RC does not match, expected: 0' | tee -a $LOG
	return 1
    }

#check to see if listing the configuration yields a blank file
    $NETCMD conf list 1>>$DIR/list_out
    log_print $NETCMD conf list
    test "x$?" = "x0" || {
	echo 'ERROR: RC does not match, expected: 0' | tee -a $LOG
	return 1
    }

    test -z "`cat $DIR/list_out`" || {
	echo "ERROR: Expected list output did not match" | tee -a $LOG
	return 1
    }
}

test_conf_drop_empty()
{
#Drop an empty config, see if conf drop fails
    echo '\nAttempting to drop an empty configuration' >>$LOG

    $NETCMD conf drop
    log_print $NETCMD conf drop
    test "x$?" = "x0" || {
	echo 'ERROR: RC does not match, expected: 0' | tee -a $LOG
	return 1
    }

#check to see if listing the configuration yields a blank file
    $NETCMD conf list 1>>$DIR/list_out
    log_print $NETCMD conf list
    test "x$?" = "x0" || {
	echo 'ERROR: RC does not match, expected: 0' | tee -a $LOG
	return 1
    }

    test -z "`cat $DIR/list_out`" || {
	echo ERROR:Expected list output did not match >> $LOG
	return 1
    }
}

test_conf_drop_usage()
{
#check to see if command prints usage
    echo '\nChecking usage' >>$LOG
    $NETCMD conf drop extra_arg > $DIR/drop_usage_exp
    log_print $NETCMD conf drop extra_arg
    test "x$?" = "x255" || {
	echo 'ERROR: RC does not match, expected: 0' | tee -a $LOG
	return 1
    }

   grep "$RPC *conf drop" $DIR/drop_usage_exp >/dev/null 2>>$LOG
   if [ "$?" = "1" ]; then
	echo "ERROR: no/wrong usage message printed" | tee -a $LOG
	return 1
   fi
}

test_conf_setparm()
{
    echo '\nTesting conf setparm' >> $LOG
    echo ------------------------- >> $LOG

    echo '\nDropping existing configuration' >> $LOG
    $NETCMD conf drop
    log_print $NETCMD conf drop
    test "x$?" = "x0" || {
	echo 'ERROR: RC does not match, expected: 0' | tee -a $LOG
	return 1
    }

    $NETCMD conf setparm share1 "read only" yes
    log_print $NETCMD conf setparm share1 "read only" yes
    test "x$?" = "x0" || {
	echo 'ERROR: RC does not match, expected: 0' | tee -a $LOG
	return 1
    }

    $NETCMD conf setparm share1 "path" /tmp/test_path
    log_print $NETCMD conf setparm share1 "path" /tmp/test_path
    test "x$?" = "x0" || {
	echo 'ERROR: RC does not match, expected: 0' | tee -a $LOG
	return 1
    }

    $NETCMD conf showshare share1 > $DIR/setparm_showshare_out
    test "x$?" = "x0" || {
	echo 'ERROR: RC does not match, expected: 0' | tee -a $LOG
	return 1
    }

    grep "read only *= *yes" $DIR/setparm_showshare_out >/dev/null 2>>$LOG
    if [ "$?" = "1" ]; then
	echo "ERROR: setparm did not set correctly" | tee -a $LOG
	return 1
    fi

    grep "path *= */tmp/test_path" $DIR/setparm_showshare_out >/dev/null 2>>$LOG
    if [ "$?" = "1" ]; then
	echo "ERROR: setparm did not set correctly" | tee -a $LOG
	return 1
    fi
}

test_conf_setparm_existing()
{

    echo '\nSetting already existing param with the same value'
    $NETCMD conf setparm share1 "read only" yes
    log_print $NETCMD conf setparm share1 "read only" yes
    test "x$?" = "x0" || {
	echo 'ERROR: RC does not match, expected: 0' | tee -a $LOG
	return 1
    }

    $NETCMD conf setparm share1 "read only" yes
    log_print $NETCMD conf setparm share1 "read only" yes
    test "x$?" = "x0" || {
	echo 'ERROR: RC does not match, expected: 0' | tee -a $LOG
	return 1
    }

    $NETCMD conf showshare share1 > $DIR/setparm_existing_showshare_out
    test "x$?" = "x0" || {
	echo 'ERROR: RC does not match, expected: 0' | tee -a $LOG
	return 1
    }

    grep "read only *= *yes" $DIR/setparm_existing_showshare_out >/dev/null 2>>$LOG
    if [ "$?" = "1" ]; then
	echo "ERROR: setparm did not set correctly" | tee -a $LOG
	return 1
    fi

    $NETCMD conf setparm share1 "read only" no
    log_print $NETCMD conf setparm share1 "read only" no
    test "x$?" = "x0" || {
	echo 'ERROR: RC does not match, expected: 0' | tee -a $LOG
	return 1
    }

    $NETCMD conf showshare share1 > $DIR/setparm_existing_showshare_out
    test "x$?" = "x0" || {
	echo 'ERROR: RC does not match, expected: 0' | tee -a $LOG
	return 1
    }

    grep "read only *= *no" $DIR/setparm_existing_showshare_out >/dev/null 2>>$LOG
    if [ "$?" = "1" ]; then
	echo "ERROR: setparm did not set correctly" | tee -a $LOG
	return 1
    fi
}

test_conf_setparm_forbidden()
{
	FORBIDDEN_PARAMS="state directory
lock directory
lock dir
config backend
include"

	echo '\nTrying to set forbidden parameters' >> $LOG

	echo '\nDropping existing configuration' >> $LOG
	$NETCMD conf drop
	log_print $NETCMD conf drop
	test "x$?" = "x0" || {
		echo 'ERROR: RC does not match, expected: 0' | tee -a $LOG
		return 1
	}

	OLD_IFS="$IFS"
	IFS='
'
	for PARAM in $FORBIDDEN_PARAMS ; do
		IFS="$OLD_IFS"
		echo "Trying to set parameter '$PARAM'" | tee -a $LOG
		$NETCMD conf setparm global "$PARAM" "value" > $DIR/setparm_forbidden_out 2>&1
		log_print $NETCMD conf setparm global \""$PARAM"\" "value"
		test "x$?" = "x0" && {
			echo "ERROR: setting forbidden parameter '$PARAM' succeeded" | tee -a $LOG
			return 1
		}

		echo "output of net command: " | tee -a $LOG
		cat $DIR/setparm_forbidden_out | tee -a $LOG

		SEARCH="Parameter '$PARAM' not allowed in registry."
		grep "$SEARCH" $DIR/setparm_forbidden_out >/dev/null 2>>$LOG
		test "x$?" = "x0" || {
			echo "ERROR: expected '$SEARCH'" | tee -a $LOG
			return 1
		}
	done

	IFS="$OLD_IFS"
	return 0
}

test_conf_setparm_usage()
{
    echo '\nChecking usage' >>$LOG
    $NETCMD conf setparm > $DIR/setparm_usage_exp
    log_print $NETCMD conf setparm
    test "x$?" = "x255" || {
	echo 'ERROR: RC does not match, expected: 0' | tee -a $LOG
	return 1
    }

    grep "$RPC *conf setparm" $DIR/setparm_usage_exp >/dev/null 2>>$LOG
    if [ "$?" = "1" ]; then
	echo "ERROR: setparm no/wrong usage message printed" | tee -a $LOG
	return 1
    fi
}

test_conf_delparm_delete_existing()
{
    echo '\nTesting conf delparm' >> $LOG
    echo ------------------------- >> $LOG
    echo -n '\n' >>$LOG

    $NETCMD conf drop
    log_print $NETCMD conf drop
    test "x$?" = "x0" || {
	echo 'ERROR: RC does not match, expected: 0' | tee -a $LOG
	return 1
    }

    $NETCMD conf addshare share1 /tmp "writeable=y" "guest_ok=n" \
				       "test comment"
    log_print $NETCMD conf addshare share$i /tmp "writeable=y" "guest_ok=n" \
				       "test comment"

    $NETCMD conf delparm share1 "path"
    log_print $NETCMD conf delparm share1 "path"
    test "x$?" = "x0" || {
	echo 'ERROR: RC does not match, expected: 0' | tee -a $LOG
	return 1
    }

    $NETCMD conf showshare share1 > $DIR/delparm_showshare_out
    test "x$?" = "x0" || {
	echo 'ERROR: RC does not match, expected: 0' | tee -a $LOG
	return 1
    }

#test to see what delparm did delete and how
    grep "read only *= *no" $DIR/delparm_showshare_out >/dev/null 2>>$LOG
    if [ "$?" = "1" ]; then
	echo "ERROR: delparm did not delete correctly" | tee -a $LOG
	return 1
    fi

    grep "path *= */tmp" $DIR/delparm_showshare_out >/dev/null 2>>$LOG
    if [ "$?" = "0" ]; then
	echo "ERROR: delparm did not delete correctly" | tee -a $LOG
	return 1
    fi
}

test_conf_delparm_delete_non_existing()
{
    echo '\nDelete non existing share' >> $LOG

    $NETCMD conf drop
    log_print $NETCMD conf drop
    test "x$?" = "x0" || {
	echo 'ERROR: RC does not match, expected: 0' | tee -a $LOG
	return 1
    }

    $NETCMD conf delparm share1 "path"
    log_print $NETCMD conf delparm share1 "path"
    test "x$?" = "x255" || {
	echo 'ERROR: RC does not match, expected: 255' | tee -a $LOG
	return 1
    }
}

test_conf_delparm_usage()
{

    echo '\nChecking usage' >>$LOG
    $NETCMD conf delparm > $DIR/delparm_usage_exp
    log_print $NETCMD conf delparm
    test "x$?" = "x255" || {
	echo 'ERROR: RC does not match, expected: 255' | tee -a $LOG
	return 1
    }

    grep "$RPC *conf delparm" $DIR/delparm_usage_exp >/dev/null 2>>$LOG
    if [ "$?" = "1" ]; then
	echo "ERROR: delparm no/wrong usage message printed" | tee -a $LOG
	return 1
    fi

}

test_conf_getparm()
{

    echo '\nTesting conf getparm' >> $LOG
    echo ------------------------- >> $LOG
    echo -n '\n' >>$LOG

    $NETCMD conf drop
    log_print $NETCMD conf drop
    test "x$?" = "x0" || {
	return 1
    }

    $NETCMD conf addshare share1 /tmp/path_test "writeable=n" "guest_ok=n" \
				       "test comment"
    log_print $NETCMD conf addshare share$i /tmp/path_test "writeable=n" "guest_ok=n" \
				       "test comment"
    test "x$?" = "x0" || {
	echo 'ERROR: RC does not match, expected: 0' | tee -a $LOG
	return 1
    }

    $NETCMD conf getparm share1 "read only" >$DIR/getparm_out
    log_print $NETCMD conf getparm share1 "read only"
    test "x$?" = "x0" || {
	echo 'ERROR: RC does not match, expected: 0' | tee -a $LOG
	return 1
    }

    $NETCMD conf getparm share1 "read only" >$DIR/getparm_out
    log_print $NETCMD conf getparm share1 "read only"
    test "x$?" = "x0" || {
	echo 'ERROR: RC does not match, expected: 0' | tee -a $LOG
	return 1
    }

    echo yes >$DIR/getparm_exp
    diff -q $DIR/getparm_out $DIR/getparm_exp  >> $LOG
    if [ "$?" = "1" ]; then
	echo "ERROR: getparm did not print correctly" | tee -a $LOG
	return 1
    fi

    $NETCMD conf getparm share1 "path" >$DIR/getparm_out
    log_print $NETCMD conf getparm share1 "path"
    test "x$?" = "x0" || {
	echo 'ERROR: RC does not match, expected: 0' | tee -a $LOG
	return 1
    }

    echo /tmp/path_test >$DIR/getparm_exp
    diff -q $DIR/getparm_out $DIR/getparm_exp  >> $LOG
    if [ "$?" = "1" ]; then
	echo "ERROR: getparm did not print correctly" | tee -a $LOG
	return 1
    fi
}

test_conf_getparm_usage()
{
    echo '\nChecking usage' >>$LOG
    $NETCMD conf getparm > $DIR/getparm_usage_exp
    log_print $NETCMD conf getparm
    test "x$?" = "x255" || {
	echo 'ERROR: RC does not match, expected: 255' | tee -a $LOG
	return 1
    }

    grep "$RPC *conf getparm" $DIR/getparm_usage_exp >/dev/null 2>>$LOG
    if [ "$?" = "1" ]; then
	echo "ERROR: getparm no/wrong usage message printed" | tee -a $LOG
	return 1
    fi

}

test_conf_getparm_non_existing()
{
    echo '\nTesting getparm non existing' >>$LOG
    $NETCMD conf getparm fictional_share fictional_param
    log_print $NETCMD conf getparm fictional_share fictional_param
    test "x$?" = "x255" || {
	echo 'ERROR: RC does not match, expected: 255' | tee -a $LOG
	return 1
    }

    $NETCMD conf getparm share1 fictional_param
    log_print $NETCMD conf getparm share1 fictional_param
    test "x$?" = "x255" || {
	echo 'ERROR: RC does not match, expected: 255' | tee -a $LOG
	return 1
    }
}

test_conf_setincludes()
{
    echo '\nTesting conf setincludes' >> $LOG
    echo ------------------------- >> $LOG
    echo '\nDropping existing configuration' >> $LOG

    $NETCMD conf drop
    log_print $NETCMD conf drop
    test "x$?" = "x0" || {
	echo 'ERROR: RC does not match, expected: 0' | tee -a $LOG
	return 1
    }

    $NETCMD conf addshare tmp_share /tmp
    log_print $NETCMD conf addshare tmp_share /tmp
    test "x$?" = "x0" || {
	echo 'ERROR: RC does not match, expected: 0' | tee -a $LOG
	return 1
    }

    $NETCMD conf setincludes tmp_share /tmp/include1 /tmp/include2 /tmp/include3
    log_print $NETCMD conf setincludes tmp_share /tmp/include1 /tmp/include2 /tmp/include3
    test "x$?" = "x0" || {
	echo 'ERROR: RC does not match, expected: 0' | tee -a $LOG
	return 1
    }

    $NETCMD conf list > $DIR/setincludes_list_out
    log_print $NETCMD conf list
    test "x$?" = "x0" || {
	echo 'ERROR: RC does not match, expected: 0' | tee -a $LOG
	return 1
    }

    grep "include *= */tmp/include1$" $DIR/setincludes_list_out >/dev/null 2>>$LOG
    if [ "$?" = "1" ]; then
	echo "ERROR: setincludes did not set correctly" | tee -a $LOG
	return 1
    fi

    grep "include *= */tmp/include2$" $DIR/setincludes_list_out >/dev/null 2>>$LOG
    if [ "$?" = "1" ]; then
	echo "ERROR: setincludes did not set correctly" | tee -a $LOG
	return 1
    fi

    grep "include *= */tmp/include3$" $DIR/setincludes_list_out >/dev/null 2>>$LOG
    if [ "$?" = "1" ]; then
	echo "ERROR: setincludes did not set correctly" | tee -a $LOG
	return 1
    fi

}

test_conf_setincludes_usage()
{
    echo '\nChecking usage' >>$LOG
    $NETCMD conf setincludes > $DIR/setincludes_usage_exp
    log_print $NETCMD conf setincludes
    test "x$?" = "x255" || {
	echo 'ERROR: RC does not match, expected: 255' | tee -a $LOG
	return 1
    }

    grep "$RPC *conf setincludes" $DIR/setincludes_usage_exp >/dev/null 2>>$LOG
    if [ "$?" = "1" ]; then
	echo "ERROR: no/wrong usage message printed" | tee -a $LOG
	return 1
    fi
}

test_conf_getincludes()
{
    $NETCMD conf getincludes tmp_share > $DIR/getincludes_out
    log_print $NETCMD conf getincludes tmp_share
    test "x$?" = "x0" || {
	echo 'ERROR: RC does not match, expected: 0' | tee -a $LOG
	return 1
    }

    grep "include *= */tmp/include1$" $DIR/getincludes_out >/dev/null 2>>$LOG
    if [ "$?" = "1" ]; then
	echo "ERROR: getincludes did not print correctly" | tee -a $LOG
	return 1
    fi

    grep "include *= */tmp/include2$" $DIR/getincludes_out >/dev/null 2>>$LOG
    if [ "$?" = "1" ]; then
	echo "ERROR: getincludes did not print correctly" | tee -a $LOG
	return 1
    fi
    grep "include *= */tmp/include3$" $DIR/getincludes_out >/dev/null 2>>$LOG
    if [ "$?" = "1" ]; then
	echo "ERROR: getincludes did not print correctly" | tee -a $LOG
	return 1
    fi
}

test_conf_getincludes_usage()
{
    $NETCMD conf getincludes > $DIR/getincludes_usage_exp
    log_print $NETCMD conf getincludes

    grep "$RPC *conf getincludes" $DIR/getincludes_usage_exp >/dev/null 2>>$LOG
    if [ "$?" = "1" ]; then
	echo "ERROR: no/wrong usage message printed" | tee -a $LOG
	return 1
    fi
}

test_conf_delincludes()
{
    echo '\nTesting conf delincludes' >> $LOG
    echo ------------------------- >> $LOG

    $NETCMD conf delincludes tmp_share
    log_print $NETCMD conf delincludes tmp_share
    test "x$?" = "x0" || {
	echo 'ERROR: RC does not match, expected: 0' | tee -a $LOG
	return 1
    }

    $NETCMD conf list > $DIR/delincludes_list_out
    log_print $NETCMD conf list
    test "x$?" = "x0" || {
	echo 'ERROR: RC does not match, expected: 0' | tee -a $LOG
	return 1
    }

    grep "include" $DIR/delincludes_list_out >/dev/null 2>>$LOG
    if [ "$?" = "0" ]; then
	echo "ERROR: delincludes did not delete correctly" | tee -a $LOG
	return 1
    fi
}

test_conf_delincludes_empty()
{
    $NETCMD conf delincludes tmp_share
    log_print $NETCMD conf delincludes tmp_share
    test "x$?" = "x0" || {
	echo 'ERROR: RC does not match, expected: 0' | tee -a $LOG
	return 1
    }

    $NETCMD conf delincludes fictional_share
    log_print $NETCMD conf delincludes fictional_share
    test "x$?" = "x255" || {
	echo 'ERROR: RC does not match, expected: 255' | tee -a $LOG
	return 1
    }
    return 0
}

test_conf_delincludes_usage()
{
    echo '\nChecking usage' >>$LOG
    $NETCMD conf delincludes > $DIR/delincludes_usage_exp
    log_print $NETCMD conf delincludes
    test "x$?" = "x255" || {
	echo 'ERROR: RC does not match, expected: 255' | tee -a $LOG
	return 1
    }

    grep "$RPC *conf delincludes" $DIR/delincludes_usage_exp >/dev/null 2>>$LOG
    if [ "$?" = "1" ]; then
	echo "ERROR: no/wrong usage message printed" | tee -a $LOG
	return 1
    fi
}

test_conf_import()
{
    echo '\nTesting conf import' >> $LOG
    echo ------------------------- >> $LOG
    echo '\nDropping existing configuration' >> $LOG

    $NETCMD conf drop
    log_print $NETCMD conf drop
    test "x$?" = "x0" || {
	echo 'ERROR: RC does not match, expected: 0' | tee -a $LOG
	return 1
    }

    $NETCMD conf import $DIR/conf_import_in
    log_print $NETCMD conf drop
    test "x$?" = "x0" || {
	echo 'ERROR: RC does not match, expected: 0' | tee -a $LOG
	return 1
    }

    $NETCMD conf list > $DIR/conf_import_out
    log_print $NETCMD conf list
    test "x$?" = "x0" || {
	echo 'ERROR: RC does not match, expected: 0' | tee -a $LOG
	return 1
    }

    diff -q $DIR/conf_import_in $DIR/conf_import_out  >> $LOG
    if [ "$?" = "1" ]; then
	echo "ERROR: import failed"  | tee -a $LOG
	return 1
    fi
}

test_conf_import_usage()
{
    echo '\nChecking usage' >>$LOG
    $NETCMD conf import > $DIR/import_usage_exp
    log_print $NETCMD conf import
    test "x$?" = "x255" || {
	echo 'ERROR: RC does not match, expected: 255' | tee -a $LOG
	return 1
    }

    grep "$RPC *conf import" $DIR/import_usage_exp >/dev/null 2>>$LOG
    if [ "$?" = "1" ]; then
	echo "ERROR: conf import no/wrong usage message printed" | tee -a $LOG
	return 1
    fi
}

CONF_FILES=$SERVERCONFFILE

    testit "conf_drop" \
	test_conf_drop \
	|| failed=`expr $failed + 1`

    testit "conf_drop_empty" \
	test_conf_drop_empty \
	|| failed=`expr $failed + 1`

    testit "conf_drop_usage" \
	test_conf_drop_usage \
	|| failed=`expr $failed + 1`

    testit "conf_addshare" \
	test_conf_addshare \
	|| failed=`expr $failed + 1`

    testit "conf_addshare_existing" \
	test_conf_addshare_existing \
	|| failed=`expr $failed + 1`

    testit "conf_addshare_usage" \
	test_conf_addshare_usage \
	|| failed=`expr $failed + 1`

    testit "conf_delshare" \
	test_conf_delshare \
	|| failed=`expr $failed + 1`

    testit "conf_delshare_empty" \
	test_conf_delshare_empty \
	|| failed=`expr $failed + 1`

    testit "conf_delshare_usage" \
	test_conf_delshare_usage \
	|| failed=`expr $failed + 1`

    testit "test_conf_showshare_case" \
	   test_conf_showshare_case \
	|| failed=`expr $failed + 1`

    testit "conf_setparm" \
	test_conf_setparm \
	|| failed=`expr $failed + 1`

    testit "conf_setparm_existing" \
	test_conf_setparm_existing \
	|| failed=`expr $failed + 1`

    testit "conf_setparm_forbidden" \
	test_conf_setparm_forbidden \
	|| failed=`expr $failed + 1`

    testit "conf_setparm_usage" \
	test_conf_setparm_usage \
	|| failed=`expr $failed + 1`

    testit "conf_delparm_delete_existing" \
	test_conf_delparm_delete_existing \
	|| failed=`expr $failed + 1`

    testit "conf_delparm_delete_non_existing" \
	test_conf_delparm_delete_non_existing \
	|| failed=`expr $failed + 1`

    testit "conf_delparm_delete_usage" \
	test_conf_delparm_usage \
	|| failed=`expr $failed + 1`

    testit "conf_getparm" \
	test_conf_getparm \
	|| failed=`expr $failed + 1`

    testit "conf_getparm_usage" \
	test_conf_getparm_usage \
	|| failed=`expr $failed + 1`

    testit "conf_setincludes" \
	test_conf_setincludes \
	|| failed=`expr $failed + 1`

    testit "conf_setincludes_usage" \
	test_conf_setincludes_usage \
	|| failed=`expr $failed + 1`

    testit "conf_getincludes" \
	test_conf_getincludes \
	|| failed=`expr $failed + 1`

    testit "conf_getincludes_usage" \
	test_conf_getincludes_usage \
	|| failed=`expr $failed + 1`

    testit "conf_delincludes" \
	test_conf_delincludes \
	|| failed=`expr $failed + 1`

    testit "conf_delincludes_empty" \
	test_conf_delincludes_usage \
	|| failed=`expr $failed + 1`

    testit "conf_delincludes_usage" \
	test_conf_delincludes_empty \
	|| failed=`expr $failed + 1`

    testit "conf_import" \
	test_conf_import \
	|| failed=`expr $failed + 1`

    testit "conf_import_usage" \
	test_conf_import_usage \
	|| failed=`expr $failed + 1`

    if [ $failed -eq 0 ]; then
	rm -r $DIR
    fi

testok $0 $failed

