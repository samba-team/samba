#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

ctdb_test_check_supported_OS "Linux"

arp_test()
{
	unit_test system_socket_test arp "$@"
}

test_case "IPv4 ARP send"
ok <<EOF
000000 00 01 08 00 06 04 00 01 12 34 56 78 9a bc c0 a8
000010 01 19 00 00 00 00 00 00 c0 a8 01 19
00001c
EOF
arp_test "192.168.1.25" "12:34:56:78:9a:bc"

test_case "IPv4 ARP reply"
ok <<EOF
000000 00 01 08 00 06 04 00 02 12 34 56 78 9a bc c0 a8
000010 01 19 12 34 56 78 9a bc c0 a8 01 19
00001c
EOF
arp_test "192.168.1.25" "12:34:56:78:9a:bc" reply

test_case "IPv4oIB ARP send"
ok <<EOF
000000 00 20 08 00 14 04 00 01 00 11 22 33 44 55 66 77
000010 88 99 aa bb cc dd 12 34 56 78 9a bc c0 a8 01 19
000020 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
000030 00 00 00 00 c0 a8 01 19
000038
EOF
arp_test \
	"192.168.1.25" \
	"00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:12:34:56:78:9a:bc"

test_case "IPv4oIB ARP reply"
ok <<EOF
000000 00 20 08 00 14 04 00 02 00 11 22 33 44 55 66 77
000010 88 99 aa bb cc dd 12 34 56 78 9a bc c0 a8 01 19
000020 00 11 22 33 44 55 66 77 88 99 aa bb cc dd 12 34
000030 56 78 9a bc c0 a8 01 19
000038
EOF
arp_test \
	"192.168.1.25" \
	"00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:12:34:56:78:9a:bc" reply

test_case "IPv6 neighbor advertisement"
ok <<EOF
000000 60 00 00 00 00 20 3a ff fe 80 00 00 00 00 00 00
000010 6a f7 28 ff fe fa d1 36 ff 02 00 00 00 00 00 00
000020 00 00 00 00 00 00 00 01 88 00 8d e4 20 00 00 00
000030 fe 80 00 00 00 00 00 00 6a f7 28 ff fe fa d1 36
000040 02 01 12 34 56 78 9a bc
000048
EOF
arp_test "fe80::6af7:28ff:fefa:d136" "12:34:56:78:9a:bc"

test_case "IPv6oIB neighbor advertisement"
ok <<EOF
000000 60 00 00 00 00 30 3a ff fe 80 00 00 00 00 00 00
000010 6a f7 28 ff fe fa d1 36 ff 02 00 00 00 00 00 00
000020 00 00 00 00 00 00 00 01 88 00 c0 8e 20 00 00 00
000030 fe 80 00 00 00 00 00 00 6a f7 28 ff fe fa d1 36
000040 02 03 00 00 00 11 22 33 44 55 66 77 88 99 aa bb
000050 cc dd 12 34 56 78 9a bc
000058
EOF
arp_test \
	"fe80::6af7:28ff:fefa:d136" \
	"00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:12:34:56:78:9a:bc"

ip6_sll_multicast_test()
{
	unit_test system_socket_test ip6_sll_multicast "$@"
}

test_case "IPv6 link-level multicast Ethernet"
#
# sll_family:   1100     (AF_PACKET)
# sll_protocol: 86dd     (htons(ETH_P_IPV6))
# sll_index:    02000000 (hardcoded to 2 hwaddr_to_sockaddr_ll())
# sll_hatype:   0000     (packet(7) says should be 0 when sending)
# sll_pkttype:  00       (packet(7) says should be 0 when sending)
#
ok <<EOF
000000 11 00 86 dd 02 00 00 00 00 00 00 06 33 33 00 00
000010 00 01
000012
EOF
ip6_sll_multicast_test "ff:ff:ff:ff:ff:ff"

test_case "IPv6 link-level multicast IPoIB"
#
# sll_family:   1100     (AF_PACKET)
# sll_protocol: 86dd     (htons(ETH_P_IPV6))
# sll_index:    02000000 (hardcoded to 2 hwaddr_to_sockaddr_ll())
# sll_hatype:   0000     (packet(7) says should be 0 when sending)
# sll_pkttype:  00       (packet(7) says should be 0 when sending)
#
# Output has IPoIB signature field changed to 60 and 00:00:00:01 at end
#
ok <<EOF
000000 11 00 86 dd 02 00 00 00 00 00 00 14 00 ff ff ff
000010 ff 12 60 1b ff ff 00 00 00 00 00 00 00 00 00 01
000020
EOF
ip6_sll_multicast_test \
	"00:ff:ff:ff:ff:12:40:1b:ff:ff:00:00:00:00:00:00:ff:ff:ff:ff"
