#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

out_file="${CTDB_TEST_TMP_DIR}/packet.out"

remove_file ()
{
	rm -f "$out_file"
}

test_cleanup remove_file

d=$(dirname "$out_file")
mkdir -p "$d"

########################################

arp_run ()
{
	$VALGRIND system_socket_test arp "$@" >"$out_file" || exit $?
	od -A x -t x1 "$out_file"
}

arp_test ()
{
	os=$(uname)
	if [ "$os" = "Linux" ] ; then
		unit_test_notrace arp_run "$@"
	else
		ok "PACKETSOCKET not supported"
		unit_test system_socket_test arp "$@"
	fi
}

ok <<EOF
000000 ff ff ff ff ff ff 12 34 56 78 9a bc 08 06 00 01
000010 08 00 06 04 00 01 12 34 56 78 9a bc c0 a8 01 19
000020 00 00 00 00 00 00 c0 a8 01 19 00 00 00 00 00 00
000030 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
000040
EOF
arp_test "192.168.1.25" "12:34:56:78:9a:bc"

ok <<EOF
000000 ff ff ff ff ff ff 12 34 56 78 9a bc 08 06 00 01
000010 08 00 06 04 00 02 12 34 56 78 9a bc c0 a8 01 19
000020 12 34 56 78 9a bc c0 a8 01 19 00 00 00 00 00 00
000030 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
000040
EOF
arp_test "192.168.1.25" "12:34:56:78:9a:bc" reply

ok <<EOF
000000 33 33 00 00 00 01 12 34 56 78 9a bc 86 dd 60 00
000010 00 00 00 20 3a ff fe 80 00 00 00 00 00 00 6a f7
000020 28 ff fe fa d1 36 ff 02 00 00 00 00 00 00 00 00
000030 00 00 00 00 00 01 88 00 8d e4 20 00 00 00 fe 80
000040 00 00 00 00 00 00 6a f7 28 ff fe fa d1 36 02 01
000050 12 34 56 78 9a bc
000056
EOF
arp_test "fe80::6af7:28ff:fefa:d136" "12:34:56:78:9a:bc"
