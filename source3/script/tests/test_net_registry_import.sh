#!/bin/sh

if [ $# -lt 4 ]; then
cat <<EOF
Usage: test_net_registry_import.sh SERVER LOCAL_PATH USERNAME PASSWORD
EOF
exit 1;
fi

SERVER="$1"
LOCAL_PATH="$2"
USERNAME="$3"
PASSWORD="$4"
shift 4
ADDARGS="$@"

failed=0

samba_net="$BINDIR/net"

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh


test_net_registry_import() {

#
# Expect:
# Found Byte Order Mark for : UTF-16LE
#
	cmd='$VALGRIND $samba_net rpc registry import $LOCAL_PATH/case3b45ccc3b.dat -S$SERVER -U$USERNAME%$PASSWORD $ADDARGS'

	eval echo "$cmd"
	out=`eval $cmd 2>&1`
	ret=$?

	if [ $ret != 0 ] ; then
		echo "$out"
		echo "command failed with output $ret"
		false
		return
	fi

	echo "$out" | grep 'Found Byte Order Mark for : UTF-16LE'
	ret=$?

	if [ $ret -ne 0 ] ; then
		echo "$out"
		echo "$samba_net rpc registry import $LOCAL_PATH/case3b45ccc3b.dat failed - should get 'Found Byte Order Mark for : UTF-16LE'"
		false
		return
	fi

#
# Expect:
# reg_parse_fd: smb_iconv error in file at line 0: <bf><77><d4><41>
#
	cmd='$VALGRIND $samba_net rpc registry import $LOCAL_PATH/casecbe8c2427.dat -S$SERVER -U$USERNAME%$PASSWORD $ADDARGS'

	eval echo "$cmd"
	out=`eval $cmd 2>&1`
	ret=$?

	if [ $? != 0 ] ; then
		echo "$out"
		echo "command failed with output $ret"
		false
		return
	fi

	echo "$out" | grep 'reg_parse_fd: smb_iconv error in file at line 0: <bf><77><d4><41>'
	ret=$?

	if [ $ret -ne 0 ] ; then
		echo "$out"
		echo "$samba_net rpc registry import $LOCAL_PATH/case3b45ccc3b.dat failed - should get 'reg_parse_fd: smb_iconv error in file at line 0: <bf><77><d4><41>'"
		false
		return
	fi

#
# For test3.dat, the parse of the first part of the file is successful,
# but fails on upload as we're writing to an unwriteable registry.
# Expect:
# setval ProductType failed: WERR_REGISTRY_IO_FAILED
# reg_parse_fd: reg_parse_line line 21 fail -2
# This counts as a success test as the file is parsed, but
# the upload failed.
#
	cmd='$VALGRIND $samba_net rpc registry import $LOCAL_PATH/regtest3.dat -S$SERVER -U$USERNAME%$PASSWORD $ADDARGS'

	eval echo "$cmd"
	out=`eval $cmd 2>&1`
	ret=$?

	if [ $? != 0 ] ; then
		echo "$out"
		echo "command failed with output $ret"
		false
		return
	fi

	echo "$out" | grep 'setval ProductType failed: WERR_REGISTRY_IO_FAILED'
	ret=$?

	if [ $ret -ne 0 ] ; then
		echo "$out"
		echo "$samba_net rpc registry import $LOCAL_PATH/regtest3.dat failed - should get 'setval ProductType failed: WERR_REGISTRY_IO_FAILED'"
		false
		return
	fi

	echo "$out" | grep 'reg_parse_fd: reg_parse_line 20 fail -2'
	ret=$?

	if [ $ret -ne 0 ] ; then
		echo "$out"
		echo "$samba_net rpc registry import $LOCAL_PATH/regtest3.dat failed - should get 'reg_parse_fd: reg_parse_line 20 fail -2'"
		false
		return
	fi

	true
	return
}

###########################################################
# Check net rpc registry import doesn't crash
###########################################################

	rm -f $LOCAL_PATH/case3b45ccc3b.dat
	rm -f $LOCAL_PATH/casecbe8c2427.dat
	rm -f $LOCAL_PATH/regtest3.dat

# Create test cases

	base64 -d <<'EOF' | gunzip -c > $LOCAL_PATH/case3b45ccc3b.dat
H4sIAODLjlwCA/v/L5whkyGPIYUhn6GcoZhBgSGIIZUhHShWzFDCUMRQCRRxBcpmAnn5QL4CQxhQ
vggomwnk5wH5pgx6DAZAyMvABcbRDB4M3kA9kQzxDD4M/gzODI5AOp7BF0g7A+U8GfyAsjEMwUAV
wQwhQLYvkOfMUPqRUvDw4yAHnz6OgsELgGlYh8EYCHXA6RnENmLIgbJNGZLh4jEMvEWRee8eXl8u
//f8N9vK5cVVXP9v2rB+/qYw+3xko5Su8jSiLZ0zwJ4GAO4s/cYABAAA
EOF

	base64 -d <<'EOF' | gunzip -c > $LOCAL_PATH/casecbe8c2427.dat
H4sIALjPjlwCA2NwZfBliGFwZihlKALCVIY8hhIgLx9MFwHpHIZgoGgJUA2ILmIoY8hkSAayioEi
OQyJQHW5YLIcqLaIIRsoXgLklwBVgcyIYSgA8oqAOBdsCsiEYoZYBl4GLgYlsG2JDElAc1KB6kCm
ZYLtTWWoAJIgncVACDE5BajeFkjCeFYMBijQEIuZxUCcDPZZJkNJ3f7yK45/V3S8epR2I14uf+4W
ee+dz0RXshv4SHxzff2XJYbx0pWaEs+ul5XKF9hlFIu4RG73Lf3rOXHW3NxpuvVnE9Xk7zxv2p3I
tlLtWjY/i1HIGhdpLy/Gub9nH5jLd/rqdYfv2uumzgq7PIldPY3Labru/65Q/nLJh1oBk/0tT2v2
eUdbzFg0NfPmamFH421aJxMPhnr7X+y0iRdSX+ex+IJ0Yaf0ahV5440Wj7cbK/jkbSjcNdvpR+WN
/5Knnn8PjvvD9O/Ws4pXUqG3lbdFrf1846zzcTOFW8yhB3QNZRP6TjOsu1rDvIaHZVfMyYd1Mhev
ik/a5m36Y85+y63pPmtXb8nOU5Zd0qK0yVJK8a27WqKHSOKaS7wpwULu1TsM94bVGD3xviR0u1Il
rFHoxeUrm2+6Ke4x2SGitD912ZGfLcmG0xiyIn+bmx0+s+dbXuT8xfl+CgL168yNzYxCgsviz/46
b7746Wnh8zXZHDof6/yDyxdf31JkzN5YVP4kf/vkvrS1ioauYemc3RIt7znZQvpOy7XO8VU5+KeP
VXKPXrzr+nMv/v5wkpA7v2TukgqHZ4e6i+Zsjfny6vHdg7+mLFjg/th4m55ppH75HYcLjEa/U4/w
SeXMTuVXablo/fmJnlPA6T12usz8nBGVKbVzTNqrTJ6d/+Y0y2bGc5MlzgnymUVq/9/PyZ2QxZvR
4WyR810zd32X5ncJRd/y7VNCd746G/jTTFLTJfHx86dVtlkL02zeCJeYsmkdrXVhtpl7Y5OOyJcD
DJXA9JPJkA5MT8YMOuA0psNgBExRMLYZgwkSOxnM1kdiG6CQkNTpD0zXGeBc4AJMx7nQFF8MTttA
8f8VDBoM5gya4NRNtgN0zczNjM1MDCwMLcwMTCwtLYxNjLE4wK5pwpebAAJ05DUABAAA
EOF

	base64 -d <<'EOF' > $LOCAL_PATH/regtest3.dat
UkVHRURJVDQKCltIS0VZX0xPQ0FMX01BQ0hJTkVdCgpbSEtFWV9MT0NBTF9NQUNISU5FXFNPRlRX
QVJFXQoKW0hLRVlfTE9DQUxfTUFDSElORVxTT0ZUV0FSRVxNaWNyb3NvZnRdCgpbSEtFWV9MT0NB
TF9NQUNISU5FXFNPRlRXQVJFXE1pY3Jvc29mdFxXaW5kb3dzIE5UXQoKW0hLRVlfTE9DQUxfTUFD
SElORVxTT0ZUV0FSRVxNaWNyb3NvZnRcV2luZG93cyBOVFxDdXJyZW50VmVyc2lvbl0KIkN1cnJl
bnRWZXJzaW9uIj0iNi4xIgoKW0hLRVlfTE9DQUxfTUFDSElORVxTWVNURU1dCgpbSEtFWV9MT0NB
TF9NQUNISU5FXFNZU1RFTVxDdXJyZW50Q29udHJvbFNldF0KCltIS0VZX0xPQ0FMX01BQ0hJTkVc
U1lTVEVNXEN1cnJlbnRDb250cm9sU2V0XENvbnRyb2xdCgpbSEtFWV9MT0NBTF9NQUNISU5FXFNZ
U1RFTVxDdXJyZW50Q29udHJvbFNldFxDb250cm9sXFByb2R1Y3RPcHRpb25zXQoiUHJvZHVjdFR5
cGUiPSJMYW5tYW5OVCIKCltIS0VZX0xPQ0FMX01BQ0hJTkVcU1lTVEVNXEN1cnJlbnRDb250cm9s
U2V0XENvbnRyb2xcUHJpbnRdCgpbSEtFWV9MT0NBTF9NQUNISU5FXFNZU1RFTVxDdXJyZW50Q29u
dHJvbFNldFxDb250cm9sXFRlcm1pbmFsIFNlcnZlcl0KCltIS0VZX0xPQ0FMX01BQ0hJTkVcU1lT
VEVNXQoKW0hLRVlfTE9DQUxfTUFDSElORVxTWVNURU1cQ3VycmVudENvbnRyb2xTZXRdCgpbSEtF
WV9MT0NBTF9NQUNISU5FXFNZU1RFTVxDdXJyZW50Q29udHJvbFNldFxTZXJ2aWNlc10KCltIS0VZ
X0xPQ0FMX01BQ0hJTkVcU1lTVEVNXEN1cnJlbnRDb250cm9sU2V0XFNlcnZpY2VzXE5ldGxvZ29u
XQoKW0hLRVlfTE9DQUxfTUFDSElORVxTWVNURU1cQ3VycmVudENvbnRyb2xTZXRcU2VydmljZXNc
TmV0bG9nb25cUGFyYW1ldGVyc10KIlJlZnVzZVBhc3N3b3JkQ2hhbmdlIj1kd29yZDowMDAwMDAw
MAoKW0hLRVlfTE9DQUxfTUFDSElORVxTWVNURU1cQ3VycmVudENvbnRyb2xTZXRcU2VydmljZXNc
QWxlcnRlcl0KCltIS0VZX0xPQ0FMX01BQ0hJTkVcU1lTVEVNXEN1cnJlbnRDb250cm9sU2V0XA==
EOF

testit "Test net rpc registry import" \
	test_net_registry_import || \
	failed=`expr $failed + 1`

# Clean up test cases.
	rm -f $LOCAL_PATH/case3b45ccc3b.dat
	rm -f $LOCAL_PATH/casecbe8c2427.dat
	rm -f $LOCAL_PATH/regtest3.dat

testok $0 $failed
