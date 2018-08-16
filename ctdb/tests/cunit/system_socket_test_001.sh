#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

out_file="${TEST_VAR_DIR}/cunit/packet.out"

remove_file ()
{
	rm -f "$out_file"
}

test_cleanup remove_file

d=$(dirname "$out_file")
mkdir -p "$d"

########################################

ok_null
unit_test system_socket_test types

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

tcp_run ()
{
	$VALGRIND system_socket_test tcp "$@" >"$out_file" || exit $?
	od -A x -t x1 "$out_file"
}

tcp_test ()
{
	unit_test_notrace tcp_run "$@"
}

ok <<EOF
000000 45 00 00 08 00 00 00 00 ff 06 00 00 c0 a8 01 19
000010 c0 a8 02 4b 01 bd d4 31 00 00 00 00 00 00 00 00
000020 50 10 04 d2 50 5f 00 00
000028
EOF
tcp_test "192.168.1.25:445" "192.168.2.75:54321" 0 0 0

ok <<EOF
000000 45 00 00 08 00 00 00 00 ff 06 00 00 c0 a8 01 19
000010 c0 a8 02 4b 01 bd d4 31 00 00 00 00 00 00 00 00
000020 50 14 04 d2 50 5b 00 00
000028
EOF
tcp_test "192.168.1.25:445" "192.168.2.75:54321" 0 0 1

ok <<EOF
000000 45 00 00 08 00 00 00 00 ff 06 00 00 c0 a8 01 19
000010 c0 a8 02 4b 01 bd d4 31 39 30 00 00 a0 5b 00 00
000020 50 14 04 d2 76 cf 00 00
000028
EOF
tcp_test "192.168.1.25:445" "192.168.2.75:54321" 12345 23456 1

ok <<EOF
000000 60 00 00 00 00 14 06 40 fe 80 00 00 00 00 00 00
000010 6a f7 28 ff fe fa d1 36 fe 80 00 00 00 00 00 00
000020 6a f7 28 ff fe fb d1 37 01 bd d4 31 00 00 00 00
000030 00 00 00 00 50 10 04 d2 0f c0 00 00
00003c
EOF
tcp_test "fe80::6af7:28ff:fefa:d136:445" "fe80::6af7:28ff:fefb:d137:54321" 0 0 0

ok <<EOF
000000 60 00 00 00 00 14 06 40 fe 80 00 00 00 00 00 00
000010 6a f7 28 ff fe fa d1 36 fe 80 00 00 00 00 00 00
000020 6a f7 28 ff fe fb d1 37 01 bd d4 31 00 00 00 00
000030 00 00 00 00 50 14 04 d2 0f bc 00 00
00003c
EOF
tcp_test "fe80::6af7:28ff:fefa:d136:445" "fe80::6af7:28ff:fefb:d137:54321" 0 0 1

ok <<EOF
000000 60 00 00 00 00 14 06 40 fe 80 00 00 00 00 00 00
000010 6a f7 28 ff fe fa d1 36 fe 80 00 00 00 00 00 00
000020 6a f7 28 ff fe fb d1 37 01 bd d4 31 39 30 00 00
000030 a0 5b 00 00 50 14 04 d2 36 30 00 00
00003c
EOF
tcp_test "fe80::6af7:28ff:fefa:d136:445" \
	 "fe80::6af7:28ff:fefb:d137:54321" 12345 23456 1
