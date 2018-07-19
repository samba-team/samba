#!/bin/sh

log="${CTDB_BASE}/debug_script.log"

case "$2" in
"timeout")
	echo "args: $*" > "$log"
	;;

"verbosetimeout")
	(ctdb-event status random $2) > "$log"
	;;

"verbosetimeout2")
	exec > "$log" 2>&1
	ctdb-event status random $2
	;;

*)
	;;

esac
