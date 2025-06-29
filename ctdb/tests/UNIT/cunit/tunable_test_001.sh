#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

tfile="${CTDB_TEST_TMP_DIR}/tunable.$$"

remove_files()
{
	rm -f "$tfile"
}
test_cleanup remove_files

defaults="\
SeqnumInterval=1000
ControlTimeout=60
TraverseTimeout=20
KeepaliveInterval=5
KeepaliveLimit=5
RecoverTimeout=30
RecoverInterval=1
ElectionTimeout=3
TakeoverTimeout=9
MonitorInterval=15
TickleUpdateInterval=20
EventScriptTimeout=30
MonitorTimeoutCount=20
RecoveryGracePeriod=120
RecoveryBanPeriod=300
DatabaseHashSize=100001
DatabaseMaxDead=5
RerecoveryTimeout=10
EnableBans=1
NoIPFailback=0
VerboseMemoryNames=0
RecdPingTimeout=60
RecdFailCount=10
LogLatencyMs=0
RecLockLatencyMs=1000
RecoveryDropAllIPs=120
VacuumInterval=10
VacuumMaxRunTime=120
RepackLimit=10000
VacuumFastPathCount=60
MaxQueueDropMsg=1000000
AllowUnhealthyDBRead=0
StatHistoryInterval=1
DeferredAttachTO=120
AllowClientDBAttach=1
FetchCollapse=1
HopcountMakeSticky=50
StickyDuration=600
StickyPindown=200
NoIPTakeover=0
DBRecordCountWarn=100000
DBRecordSizeWarn=10000000
DBSizeWarn=100000000
PullDBPreallocation=10485760
LockProcessesPerDB=200
RecBufferSizeLimit=1000000
QueueBufferSize=1024
IPAllocAlgorithm=2
AllowMixedVersions=0
"

ok_tunable_defaults()
{
	ok "$defaults"
}

tunable_log()
{
	_level="$1"
	_msg="$2"

	_all=":DEBUG:INFO:NOTICE:WARNING:ERR:"
	# Keep the debug levels log at.  This strips off the levels up
	# to and including the current $CTDB_DEBUGLEVEL, but then puts
	# back $CTDB_DEBUGLEVEL.  Cheaper than a loop...
	_want=":${CTDB_DEBUGLEVEL}:${_all#*":${CTDB_DEBUGLEVEL}:"}"

	case "$_want" in
	*":${_level}:"*)
		log="${log}${_msg}
" # Intentional newline
		;;
	esac
}

# Update $_map with tunable settings from 1 file
# values
ok_tunable_1()
{
	_file="$1"

	if [ ! -r "$_file" ]; then
		tunable_log "INFO" "Optional tunables file ${_file} not found"
		return
	fi

	tunable_log "NOTICE" "Loading tunables from ${_file}"

	while IFS='= 	' read -r _var _val; do
		case "$_var" in
		\#* | "") continue ;;
		esac
		_decval=$((_val))
		_vl=$(echo "$_var" | tr '[:upper:]' '[:lower:]')
		_map=$(echo "$_map" |
			sed -e "s|^\\(${_vl}:.*=\\).*\$|\\1${_decval}|")
	done <"$_file"
}

# Set required output to a version of $defaults where values for
# tunables specified in $tfile replace the default values
ok_tunable()
{
	# Construct a version of $defaults prepended with a lowercase
	# version of the tunable variable, to allow case-insensitive
	# matching.  This would be easier with the GNU sed
	# case-insensitivity flag, but that is less portable.  The $0
	# condition in awk causes empty lines to be skipped, in case
	# there are trailing empty lines in $defaults.
	_map=$(echo "$defaults" |
		awk -F= '$0 { printf "%s:%s=%s\n", tolower($1), $1, $2 }')

	log=""

	ok_tunable_1 "$tfile"

	# Set result, stripping off lowercase tunable prefix
	ok "${log}$(echo "$_map" | awk -F: '{ print $2 }')"
}

export CTDB_DEBUGLEVEL="INFO"

test_case "Unreadable file"
: >"$tfile"
chmod a-r "$tfile"
uid=$(id -u)
# root can read unreadable files
if [ "$uid" = 0 ]; then
	ok_tunable_defaults
else
	required_error EINVAL <<EOF
ctdb_tunable_load_file: Failed to open ${tfile}
EOF
fi
unit_test tunable_test "$tfile"
rm -f "$tfile"

test_case "Invalid file, contains 1 word"
echo "Hello" >"$tfile"
required_error EINVAL <<EOF
Loading tunables from ${tfile}
ctdb_tunable_load_file: Invalid line containing "Hello"
EOF
unit_test tunable_test "$tfile"

test_case "Invalid file, contains multiple words"
echo "Hello world!" >"$tfile"
required_error EINVAL <<EOF
Loading tunables from ${tfile}
ctdb_tunable_load_file: Invalid line containing "Hello world!"
EOF
unit_test tunable_test "$tfile"

test_case "Invalid file, missing value"
echo "EnableBans=" >"$tfile"
required_error EINVAL <<EOF
Loading tunables from ${tfile}
ctdb_tunable_load_file: Invalid line containing "EnableBans"
EOF
unit_test tunable_test "$tfile"

test_case "Invalid file, invalid value (not a number)"
echo "EnableBans=value" >"$tfile"
required_error EINVAL <<EOF
Loading tunables from ${tfile}
ctdb_tunable_load_file: Invalid value "value" for tunable "EnableBans"
EOF
unit_test tunable_test "$tfile"

test_case "Invalid file, missing key"
echo "=123" >"$tfile"
required_error EINVAL <<EOF
Loading tunables from ${tfile}
ctdb_tunable_load_file: Syntax error
EOF
unit_test tunable_test "$tfile"

test_case "Invalid file, missing key but space before ="
cat >"$tfile" <<EOF
 =0
EOF
required_error EINVAL <<EOF
Loading tunables from ${tfile}
ctdb_tunable_load_file: Syntax error
EOF
unit_test tunable_test "$tfile"

test_case "Invalid file, unknown tunable"
echo "HelloWorld=123" >"$tfile"
required_error EINVAL <<EOF
Loading tunables from ${tfile}
ctdb_tunable_load_file: Unknown tunable "HelloWorld"
EOF
unit_test tunable_test "$tfile"

test_case "Invalid file, obsolete tunable"
echo "MaxRedirectCount=123" >"$tfile"
required_error EINVAL <<EOF
Loading tunables from ${tfile}
ctdb_tunable_load_file: Obsolete tunable "MaxRedirectCount"
EOF
unit_test tunable_test "$tfile"

test_case "Invalid file, trailing non-whitespace garbage"
echo "EnableBans=0xgg" >"$tfile"
required_error EINVAL <<EOF
Loading tunables from ${tfile}
ctdb_tunable_load_file: Invalid value "0xgg" for tunable "EnableBans"
EOF
unit_test tunable_test "$tfile"

test_case "Invalid file, multiple errors"
cat >"$tfile" <<EOF
EnableBans=
EnableBans=value
=123
HelloWorld=123
MaxRedirectCount =123
EOF
required_error EINVAL <<EOF
Loading tunables from ${tfile}
ctdb_tunable_load_file: Invalid line containing "EnableBans"
ctdb_tunable_load_file: Invalid value "value" for tunable "EnableBans"
ctdb_tunable_load_file: Syntax error
EOF
unit_test tunable_test "$tfile"

test_case "Invalid file, errors followed by valid"
cat >"$tfile" <<EOF
HelloWorld=123
EnableBans=value
EnableBans=0
EOF
required_error EINVAL <<EOF
Loading tunables from ${tfile}
ctdb_tunable_load_file: Unknown tunable "HelloWorld"
ctdb_tunable_load_file: Invalid value "value" for tunable "EnableBans"
EOF
unit_test tunable_test "$tfile"

test_case "OK, missing file"
rm -f "$tfile"
ok_tunable
unit_test tunable_test "$tfile"

test_case "OK, empty file"
: >"$tfile"
ok_tunable
unit_test tunable_test "$tfile"

test_case "OK, comments and blanks only"
cat >"$tfile" <<EOF
# This is a comment

# There are also some blank lines


EOF
ok_tunable
unit_test tunable_test "$tfile"

test_case "OK, 1 tunable"
cat >"$tfile" <<EOF
EnableBans=0
EOF
ok_tunable
unit_test tunable_test "$tfile"

test_case "OK, 1 tunable, hex"
cat >"$tfile" <<EOF
EnableBans=0xf
EOF
ok_tunable
unit_test tunable_test "$tfile"

test_case "OK, 1 tunable, octal"
cat >"$tfile" <<EOF
EnableBans=072
EOF
ok_tunable
unit_test tunable_test "$tfile"

test_case "OK, 1 tunable, tab before ="
cat >"$tfile" <<EOF
EnableBans	=0
EOF
ok_tunable
unit_test tunable_test "$tfile"

test_case "OK, 1 tunable, space after ="
cat >"$tfile" <<EOF
EnableBans= 0
EOF
ok_tunable
unit_test tunable_test "$tfile"

test_case "OK, 2 tunables, multiple spaces around ="
cat >"$tfile" <<EOF
EnableBans      =  0
RecoverInterval = 10
EOF
ok_tunable
unit_test tunable_test "$tfile"

test_case "OK, 2 tunables, whitespace everywhere"
cat >"$tfile" <<EOF
	EnableBans      = 0  
	RecoverInterval = 10 
EOF
ok_tunable
unit_test tunable_test "$tfile"

test_case "OK, several tunables"
cat >"$tfile" <<EOF
EnableBans=0
RecoverInterval=10
ElectionTimeout=5
EOF
ok_tunable
unit_test tunable_test "$tfile"

test_case "OK, several tunables, varying case"
cat >"$tfile" <<EOF
enablebans=0
ReCoVerInTeRvAl=10
ELECTIONTIMEOUT=5
EOF
ok_tunable
unit_test tunable_test "$tfile"

test_case "OK, miscellaneous..."
cat >"$tfile" <<EOF
# Leading comment
enablebans=0
ReCoVerInTeRvAl	 =    10

# Intermediate comment after a blank line
  ELECTIONTIMEOUT=25   


# Final comment among blanks lines




EOF
ok_tunable
unit_test tunable_test "$tfile"
