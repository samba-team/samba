#!/bin/sh

# config_migrate.sh - migrate old ctdbd.conf file to new configuration files
#
# Input files are old-style CTDB configuration files, including:
#
#   /etc/ctdb/ctdbd.conf
#   /usr/local/etc/ctdb/ctdbd.conf
#   /etc/sysconfig/ctdb
#   /etc/defaults/ctdb
#
# These files are sourced by this script.  They used to be sourced by
# ctdbd_wrapper, so this should not be too surprising.
#
# By default, the output directory is the given configuration
# directory.  An alternate output directory can be specified if this
# isn't desired.
#
# The output directory will contain the following if non-empty:
#
# * ctdb.conf (may be empty)
# * script.options
# * ctdb.tunables
# * ctdb.sysconfig - consider installing as /etc/sysconfig/ctdb,
#                    /etc/default/ctdb, or similar
# * commands.sh    - consider running commands in this files
# * README.warn    - warnings about removed/invalid configuration options

usage ()
{
	cat <<EOF
usage: config_migrate.sh [-f] [-d <ctdb-config-dir>] [-o <out-dir>] <file> ...
EOF
    exit 1
}

config_dir=""
out_dir=""
force=false

while getopts "d:fho:?" opt ; do
	case "$opt" in
	d) config_dir="$OPTARG" ;;
	f) force=true ;;
	o) out_dir="$OPTARG" ;;
	\?|h) usage ;;
	esac
done
shift $((OPTIND - 1))

if [ $# -lt 1 ] ; then
	usage
fi

if [ -z "$config_dir" ] ; then
	echo "Assuming \"/etc/ctdb\" as ctdb configuration directory"
	echo "If that's not correct, please specify config dir with -d"
	echo
	config_dir="/etc/ctdb"
else
	echo "Using \"$config_dir\" as ctdb configuration directory"
	echo
fi

if [ -z "$out_dir" ] ; then
	echo "No output directory specified, using \"$config_dir\""
	echo
	out_dir="$config_dir"
fi

############################################################

#
# Output file handling
#

out_file_check_and_create ()
{
	_out_file="$1"

	if [ -f "$_out_file" ] ; then
		if ! $force ; then
			echo "Not overwriting existing file: ${_out_file}" >&2
			return 1
		fi
		mv -v "$_out_file" "${_out_file}.convertsave"
	fi

	touch "$_out_file"

	return 0
}

out_file_remove_if_empty ()
{
	_out_file="$1"

	if [ ! -s "$_out_file" ] ; then
		rm "$_out_file"
	fi
}

############################################################

#
# Option/tunable/service conversion and validity checking
#
# This is basically the data that drives most of the rest of the
# script
#

# Convert a ctdbd.conf opt+val into a ctdb.conf section+opt+val
#
# If opt is matched and val is empty then output is printed, allowing
# this function to be reused to check if opt is valid.
#
# Note that for boolean options, the expected value and the new value
# form part of the data.
get_ctdb_conf_option ()
{
	_opt="$1"
	_val="$2"

	awk -v opt="${_opt}" -v val="${_val}" \
	    '$3 == opt {
		if (!$4 || !val || val == $4) {
		    if ($5) {
			print $1, $2, $5
		    } else {
			print $1, $2, val
		    }
		}
	    }' <<EOF
cluster	  node-address			CTDB_NODE_ADDRESS
cluster   recovery-lock			CTDB_RECOVERY_LOCK
cluster   transport			CTDB_TRANSPORT
database  lock-debug-script		CTDB_DEBUG_LOCKS
database  persistent-database-directory CTDB_DBDIR_PERSISTENT
database  state-database-directory	CTDB_DBDIR_STATE
database  volatile-database-directory	CTDB_DBDIR
event     debug-script			CTDB_DEBUG_HUNG_SCRIPT
legacy    lmaster-capability		CTDB_CAPABILITY_LMASTER		no  false
legacy    realtime-scheduling		CTDB_NOSETSCHED			yes false
legacy    recmaster-capability		CTDB_CAPABILITY_RECMASTER       no  false
legacy    script-log-level		CTDB_SCRIPT_LOG_LEVEL
legacy    start-as-disabled		CTDB_START_AS_DISABLED		yes true
legacy    start-as-stopped		CTDB_START_AS_STOPPED		yes true
logging   location			CTDB_LOGGING
logging   log-level			CTDB_DEBUGLEVEL
EOF

}

# Check if an option will convert to a ctdb.conf option
check_ctdb_conf_option ()
{
	_opt="$1"

	_out=$(get_ctdb_conf_option "$_opt" "")
	[ -n "$_out" ]
}

# Convert a ctdbd.conf tunable option into a ctdb.conf section+opt
#
# The difference between this and get_ctdb_conf_option() is that only
# the tunable part of the option is passed as opt and it is matched
# case-insensitively.
get_ctdb_conf_tunable_option ()
{
	_opt="$1"
	_val="$2"

	awk -v opt="${_opt}" -v val="${_val}" \
	    'tolower($3) == tolower(opt) {
		if (!$4 || !val || (val == 0 ? 0 : 1) == $4) {
		    if ($5) {
			print $1, $2, $5
		    } else {
			print $1, $2, val
		    }
		}
	    }' <<EOF
database  tdb-mutexes			TDBMutexEnabled		0 false
failover  disabled			DisableIPFailover	1 true
EOF

}

# Check if a tunable will convert to a ctdb.conf option
check_ctdb_conf_tunable_option ()
{
	_opt="$1"

	_out=$(get_ctdb_conf_tunable_option "$_opt" "")
	[ -n "$_out" ]
}

# Check if an option has been removed
check_removed_option ()
{
	_option="$1"

	grep -Fqx "$_option" <<EOF
CTDB_BASE
CTDB_PIDFILE
CTDB_SOCKET
CTDB_EVENT_SCRIPT_DIR
CTDB_NOTIFY_SCRIPT
CTDB_PUBLIC_INTERFACE
CTDB_MAX_PERSISTENT_CHECK_ERRORS
CTDB_SHUTDOWN_TIMEOUT
CTDB_MONITOR_SWAP_USAGE
EOF
}

# Check if an option is a valid script option
check_valid_script_option ()
{
	_option="$1"

	grep -Fqx "$_option" <<EOF
# 10.interface
CTDB_PARTIALLY_ONLINE_INTERFACES
# 11.natgw
CTDB_NATGW_DEFAULT_GATEWAY
CTDB_NATGW_NODES
CTDB_NATGW_PRIVATE_NETWORK
CTDB_NATGW_PUBLIC_IFACE
CTDB_NATGW_PUBLIC_IP
CTDB_NATGW_STATIC_ROUTES
# 13.per_ip_routing
CTDB_PER_IP_ROUTING_CONF
CTDB_PER_IP_ROUTING_RULE_PREF
CTDB_PER_IP_ROUTING_TABLE_ID_LOW
CTDB_PER_IP_ROUTING_TABLE_ID_HIGH
# 90.lvs
CTDB_LVS_NODES
CTDB_LVS_PUBLIC_IFACE
CTDB_LVS_PUBLIC_IP
# 20.multipathd
CTDB_MONITOR_MPDEVICES
# 31.clamd
CTDB_CLAMD_SOCKET
# 48.netbios
CTDB_SERVICE_NMB
# 49.winbind
CTDB_SERVICE_WINBIND
# 50.samba
CTDB_SAMBA_CHECK_PORTS
CTDB_SAMBA_SKIP_SHARE_CHECK
CTDB_SERVICE_SMB
# 60.nfs
CTDB_NFS_CALLOUT
CTDB_NFS_CHECKS_DIR
CTDB_NFS_SKIP_SHARE_CHECK
CTDB_RPCINFO_LOCALHOST
CTDB_RPCINFO_LOCALHOST6
CTDB_NFS_STATE_FS_TYPE
CTDB_NFS_STATE_MNT
# 70.iscsi
CTDB_START_ISCSI_SCRIPTS
# 00.ctdb
CTDB_MAX_CORRUPT_DB_BACKUPS
# 05.system
CTDB_MONITOR_FILESYSTEM_USAGE
CTDB_MONITOR_MEMORY_USAGE
# debug_hung_scripts.sh
CTDB_DEBUG_HUNG_SCRIPT_STACKPAT
EOF
}

# Check if a tunable is valid
check_valid_tunable ()
{
	_tunable="$1"

	grep -Fiqx "$_tunable" <<EOF
AllowClientDBAttach
AllowMixedVersions
AllowUnhealthyDBRead
ControlTimeout
DBRecordCountWarn
DBRecordSizeWarn
DBSizeWarn
DatabaseHashSize
DatabaseMaxDead
DeferredAttachTO
DisableIPFailover
ElectionTimeout
EnableBans
EventScriptTimeout
FetchCollapse
HopcountMakeSticky
IPAllocAlgorithm
KeepaliveInterval
KeepaliveLimit
LockProcessesPerDB
LogLatencyMs
MaxQueueDropMsg
MonitorInterval
MonitorTimeoutCount
NoIPFailback
NoIPTakeover
PullDBPreallocation
QueueBufferSize
RecBufferSizeLimit
RecLockLatencyMs
RecdFailCount
RecdPingTimeout
RecoverInterval
RecoverTimeout
RecoveryBanPeriod
RecoveryDropAllIPs
RecoveryGracePeriod
RepackLimit
RerecoveryTimeout
SeqnumInterval
StatHistoryInterval
StickyDuration
StickyPindown
TDBMutexEnabled
TakeoverTimeout
TickleUpdateInterval
TraverseTimeout
VacuumFastPathCount
VacuumInterval
VacuumMaxRunTime
VerboseMemoryNames
EOF
}

# Check if a tunable has been removed
check_removed_tunable ()
{
	_tunable="$1"

	grep -Fiqx "$_tunable" <<EOF
NoIPHostOnAllDisabled
VacuumLimit
EOF
}

# Print a command to enable an event script for the given service
print_event_script_enable_command ()
{
	_service="$1"

	_component=""
	_script=""
	case "$_service" in
	samba)         _component="legacy" ; _script="50.samba"   ;;
	winbind)       _component="legacy" ; _script="49.winbind" ;;
	apache2|httpd) _component="legacy" ; _script="41.httpd"   ;;
	clamd)         _component="legacy" ; _script="31.clamd"   ;;
	iscsi)         _component="legacy" ; _script="70.iscsi"   ;;
	nfs)           _component="legacy" ; _script="60.nfs"     ;;
	vsftpd)        _component="legacy" ; _script="40.vsftpd"  ;;
	esac

	if [ -z "$_script" ] ; then
		return 1
	fi

	cat <<EOF
# Enable the ${_service} service
ctdb event script enable ${_component} ${_script}

EOF
}

# Check if the given service is valid
check_valid_service ()
{
	_service="$1"

	print_event_script_enable_command "$_service" >/dev/null
}

############################################################

#
# Utilities
#

# List all options starting with "CTDB_" set in given configuration files
list_options ()
{
	set |
	sed -n 's|^\(CTDB_[^=]*\)=\(.*\)|\1 \2|p' |
	while read -r _var _val ; do
		# Strip quotes from value
		_val=$(echo "$_val" | sed -e "s|^'||" -e "s|'\$||")

		echo "${_var} ${_val}"
	done
}

# List all tunables set in the given configuration files
list_tunables ()
{
	list_options |
	while read -r _opt _val ; do
		case "$_opt" in
		CTDB_SET_*) echo "${_opt#CTDB_SET_} ${_val}" ;;
		esac
	done
}

# List all managed services according to the given configuration files
list_managed_services ()
{
	#
	# CTDB_MANAGES_<service>="yes"
	#
	list_options |
	while read -r _opt _val ; do
		case "$_opt" in
		CTDB_MANAGES_*) : ;;
		*) continue ;;
		esac

		if [ "$_val" != "yes" ] ; then
			continue
		fi

		# Trim and downcase
		echo "${_opt#CTDB_MANAGES_}" | tr '[:upper:]' '[:lower:]'
	done

	#
	# CTDB_MANAGED_SERVICES
	#
	for _service in $CTDB_MANAGED_SERVICES ; do
		echo "$_service"
	done
}

############################################################

#
# Print warnings for removed and unknown options
#


# Print a warning as a bullet list item
#
# Arguments after the 1st are printed as a subsequent paragraph.
warn ()
{
	bullet="$1" ; shift

	printf '* %s\n\n' "$bullet"

	if [ $# -gt 0 ] ; then
		printf '  %s\n\n' "$*"
	fi
}

warn_about_CTDB_DBDIR_tmpfs_yes ()
{
	if $ctdb_dbdir_tmpfs_magic ; then
		warn "Option \"CTDB_DBDIR=tmpfs\" is no longer available:" \
		     "Permanently mount a tmpfs filesystem on the volatile" \
		     "database directory"
	fi
}

warn_about_unknown_managed_services ()
{
	list_managed_services |
	while read -r _s ; do
		if check_valid_service "$_s" ; then
			continue
		fi
		warn "Unknown service \"${_s}\" marked as managed" \
		     "If this is a 3rd party service, please enable it manually"
	done
}

warn_about_removed_and_unknown_options ()
{
	list_options |
	while read -r _opt _val ; do
		if check_ctdb_conf_option "$_opt" ; then
			continue
		fi

		if check_valid_script_option "$_opt" ; then
			continue
		fi

		case "$_opt" in
		CTDB_MANAGED_SERVICES|\
		CTDB_MANAGES_*|\
		CTDB_SET_*|\
		CTDB_NODES|\
		CTDB_PUBLIC_ADDRESSES|\
		CTDB_MAX_OPEN_FILES|\
		CTDB_SUPPRESS_COREFILE)
			# Handled elsewhere
			continue
			;;
		esac

		if check_removed_option "$_opt" ; then
			warn "Option \"${_opt}\" is no longer available" \
			     "Please see the WHATSNEW.txt"
			continue
		fi

		warn "Option \"${_opt}\" is unknown"
	done
}

warn_about_removed_and_unknown_tunables ()
{
	list_tunables |
	while read -r _var _val ; do
		if check_valid_tunable "$_var" ; then
			continue
		fi

		if check_removed_tunable "$_var" ; then
			warn "Tunable \"${_var}\" is no longer available" \
			     "Please see the WHATSNEW.txt"
			continue
		fi

		warn "Tunable \"${_var}\" is unknown"
	done
}

############################################################

#
# Top-level file builders
#

build_ctdb_conf ()
{
	_out_file="$1"

	out_file_check_and_create "$_out_file" || return

	list_options |
	while read -r _opt _val ; do
		case "$_opt" in
		CTDB_SET_*)
			_opt="${_opt#CTDB_SET_}"
			_out=$(get_ctdb_conf_tunable_option "$_opt" "$_val")
			;;
		*)
			_out=$(get_ctdb_conf_option "$_opt" "$_val")
		esac
		if [ -z "$_out" ] ; then
			continue
		fi

		# $_out is section and key, replace dashes with spaces
		# Intentional word splitting
		# shellcheck disable=SC2086
		set -- $_out
		_section=$(echo "$1" | sed -e 's|-| |g')
		_key=$(echo "$2" | sed -e 's|-| |g')
		_newval="$3"

		if ! grep -Fqx "[${_section}]" "$_out_file" ; then
			# Add blank line if file is not empty
			if [ -s "$_out_file" ] ; then
				echo >>"$_out_file"
			fi
			# Create section at end of file
			echo "[${_section}]" >>"$_out_file"
		fi

		# Must escape leading TAB or sed eats it
		sed -i -e "/\\[${_section}\\]/a\
\\	${_key} = ${_newval}
" "$_out_file"

	done

}

build_script_options ()
{
	_out_file="$1"

	out_file_check_and_create "$_out_file" || return

	list_options |
	while read -r _var _val ; do
		if check_valid_script_option "$_var" ; then
			echo "${_var}=${_val}"
		fi
	done >>"$_out_file"

	out_file_remove_if_empty "$_out_file"
}

build_ctdb_tunables ()
{
	_out_file="$1"

	out_file_check_and_create "$_out_file" || return

	list_tunables |
	while read -r _var _val ; do
		if check_ctdb_conf_tunable_option "$_var" ; then
			continue
		fi
		if ! check_valid_tunable "$_var" ; then
			continue
		fi
		echo "${_var}=${_val}"
	done >>"$_out_file"

	out_file_remove_if_empty "$_out_file"
}

build_ctdb_sysconfig ()
{
	_out_file="$1"

	out_file_check_and_create "$_out_file" || return

	if [ -n "$CTDB_SUPPRESS_COREFILE" ] ; then
		if [ "$CTDB_SUPPRESS_COREFILE" = "yes" ] ; then
			echo "ulimit -c 0"
		else
			echo "ulimit -c unlimited"
		fi >>"$_out_file"
	fi

	if [ -n "$CTDB_MAX_OPEN_FILES" ] ; then
		echo "ulimit -n ${CTDB_MAX_OPEN_FILES}" >>"$_out_file"
	fi

	out_file_remove_if_empty "$_out_file"
}

build_commands_sh ()
{
	_out_file="$1"

	out_file_check_and_create "$_out_file" || return

	#
	# Enable script for managed services
	#
	list_managed_services |
	while read -r _service ; do
		print_event_script_enable_command "$_service"
	done >>"$_out_file"

	#
	# CTDB_NODES no longer available
	#
	if [ -n "$CTDB_NODES" ] ; then
		if [ "$CTDB_NODES" = "${config_dir}/nodes" ] ; then
			cat <<EOF
# CTDB_NODES=${CTDB_NODES}
# Looks like the standard location.  Nothing to do.

EOF
		else
			cat <<EOF
# CTDB_NODES=${CTDB_NODES}
# Looks like a non-standard location.  Use the default location
# in the configuration directory or create a symlink.
ln -s "$CTDB_NODES" "${config_dir}/nodes"

EOF
		fi >>"$_out_file"
	fi

	#
	# CTDB_PUBLIC_ADDRESSES no longer available
	#
	if [ -n "$CTDB_PUBLIC_ADDRESSES" ] ; then
		_pa="public_addresses"
		if [ "$CTDB_PUBLIC_ADDRESSES" = "${config_dir}/${_pa}" ] ; then
			cat <<EOF
# CTDB_PUBLIC_ADDRESSES=${CTDB_PUBLIC_ADDRESSES}
# Looks like the standard location.  Nothing to do.

EOF
		else
			cat <<EOF
# CTDB_PUBLIC_ADDRESSES=${CTDB_PUBLIC_ADDRESSES}
# Looks like a non-standard location.  Use the default location
# in the configuration directory or create a symlink.
ln -s "$CTDB_PUBLIC_ADDRESSES" "${config_dir}/${_pa}"

EOF
		fi >>"$_out_file"
	fi

	out_file_remove_if_empty "$_out_file"
}

build_README_warn ()
{
	_out_file="$1"

	out_file_check_and_create "$_out_file" || return

	{
		warn_about_CTDB_DBDIR_tmpfs_yes
		warn_about_unknown_managed_services
		warn_about_removed_and_unknown_options
		warn_about_removed_and_unknown_tunables
	} >>"$_out_file"

	out_file_remove_if_empty "$_out_file"
}

############################################################

mkdir -p "$out_dir" || exit 1

# Source the input files
for i ; do
	# Unknown non-constant source
	# shellcheck disable=SC1090
	. "$i"
done

# Special case
ctdb_dbdir_tmpfs_magic=false
if [ "$CTDB_DBDIR" = "tmpfs" ] ; then
	ctdb_dbdir_tmpfs_magic=true
	unset CTDB_DBDIR
fi

build_ctdb_conf      "${out_dir}/ctdb.conf"
build_script_options "${out_dir}/script.options"
build_ctdb_tunables  "${out_dir}/ctdb.tunables"
build_ctdb_sysconfig "${out_dir}/ctdb.sysconfig"
build_commands_sh    "${out_dir}/commands.sh"
build_README_warn    "${out_dir}/README.warn"
