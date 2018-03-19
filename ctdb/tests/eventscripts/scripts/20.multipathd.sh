setup_multipathd ()
{
	for i ; do
		case "$i" in
		\!*)
			_t="${i#!}"
			echo "Marking ${_t} as having no active paths"
			FAKE_MULTIPATH_FAILURES="${FAKE_MULTIPATH_FAILURES}${FAKE_MULTIPATH+FAILURES:+ }${_t}"
		;;
		*)
			_t="$i"
		esac
		CTDB_MONITOR_MPDEVICES="${CTDB_MONITOR_MPDEVICES}${CTDB_MONITOR_MPDEVICES:+ }${_t}"
	done

	export CTDB_MONITOR_MPDEVICES FAKE_MULTIPATH_FAILURES
	export FAKE_SLEEP_FORCE=0.1
}
