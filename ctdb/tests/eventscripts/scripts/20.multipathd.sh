setup_multipathd ()
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

	export CTDB_MONITOR_MPDEVICES="$_devices"
	export FAKE_MULTIPATH_FAILURES="$_failures"
	export FAKE_SLEEP_FORCE=0.1
}
