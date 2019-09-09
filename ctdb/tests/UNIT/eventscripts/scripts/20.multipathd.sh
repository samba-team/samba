setup ()
{
	_failures=""
	_devices=""
	for i ; do
		case "$i" in
		\!*)
			_t="${i#!}"
			echo "Marking ${_t} as having no active paths"
			_failures="${_failures}${_failures:+ }${_t}"
		;;
		*)
			_t="$i"
		esac
		_devices="${_devices}${_devices:+ }${_t}"
	done

	setup_script_options <<EOF
CTDB_MONITOR_MPDEVICES="$_devices"
EOF

	export FAKE_MULTIPATH_FAILURES="$_failures"
	export FAKE_SLEEP_FORCE=0.1
}
