#!/bin/sh

if [ $# -lt 1 ]; then
cat <<EOF
Usage: test_update_keytab.sh DOMAIN CONFIGURATION
EOF
exit 1
fi

incdir="$(dirname "$0")/../../../testprogs/blackbox"
. "${incdir}/subunit.sh"
. "${incdir}/common_test_fns.inc"

DOMAIN="${1}"
CONFIGURATION="${2}"
shift 2

samba_wbinfo="$BINDIR/wbinfo"
samba_net="$BINDIR/net $CONFIGURATION"
samba_rpcclient="$BINDIR/rpcclient $CONFIGURATION"
smbclient="${BINDIR}/smbclient"

keytabs_sync_kvno="keytab0k keytab1k keytab2k keytab3k keytab4k"
keytabs_nosync_kvno="keytab0 keytab1 keytab2 keytab3"
keytabs_all="$keytabs_sync_kvno $keytabs_nosync_kvno"

# Generate the next ~300 lines for keytab templates using these steps:
# make testenv SELFTEST_TESTENV="ad_member_idmap_nss:local"
# source3/script/tests/test_update_keytab.sh ADDOMAIN --configfile=st/ad_member_idmap_nss/lib/server.conf
# and finally source it from the vim editor
# :r! for k in keytab0 keytab0k keytab1 keytab1k keytab2 keytab2k keytab3 keytab3k keytab4k ; do (echo $k=\"\\; bin/net --configfile=st/ad_member_idmap_nss/lib/server.conf ads keytab list /path/st/ad_member_idmap_nss/$k |sort -k3 |grep -v Vno|sed 's/\$/\\$/'; echo '";'; echo ); done

keytab0="\
 -1  arcfour-hmac-md5                            ADMEMIDMAPNSS\$@ADDOM.SAMBA.EXAMPLE.COM
 -2  arcfour-hmac-md5                            ADMEMIDMAPNSS\$@ADDOM.SAMBA.EXAMPLE.COM
 -3  arcfour-hmac-md5                            ADMEMIDMAPNSS\$@ADDOM.SAMBA.EXAMPLE.COM
 -1  aes128-cts-hmac-sha1-96                     ADMEMIDMAPNSS\$@ADDOM.SAMBA.EXAMPLE.COM
 -1  aes256-cts-hmac-sha1-96                     ADMEMIDMAPNSS\$@ADDOM.SAMBA.EXAMPLE.COM
 -2  aes128-cts-hmac-sha1-96                     ADMEMIDMAPNSS\$@ADDOM.SAMBA.EXAMPLE.COM
 -2  aes256-cts-hmac-sha1-96                     ADMEMIDMAPNSS\$@ADDOM.SAMBA.EXAMPLE.COM
 -3  aes128-cts-hmac-sha1-96                     ADMEMIDMAPNSS\$@ADDOM.SAMBA.EXAMPLE.COM
 -3  aes256-cts-hmac-sha1-96                     ADMEMIDMAPNSS\$@ADDOM.SAMBA.EXAMPLE.COM
";

keytab0k="\
  4  aes256-cts-hmac-sha1-96                     ADMEMIDMAPNSS\$@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     ADMEMIDMAPNSS\$@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     ADMEMIDMAPNSS\$@ADDOM.SAMBA.EXAMPLE.COM
";

keytab1="\
 -1  aes256-cts-hmac-sha1-96                     HOST/ADMEMIDMAPNSS@ADDOM.SAMBA.EXAMPLE.COM
 -2  aes256-cts-hmac-sha1-96                     HOST/ADMEMIDMAPNSS@ADDOM.SAMBA.EXAMPLE.COM
 -3  aes256-cts-hmac-sha1-96                     HOST/ADMEMIDMAPNSS@ADDOM.SAMBA.EXAMPLE.COM
 -1  aes256-cts-hmac-sha1-96                     HOST/ADMEMIDMAPNSS.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -2  aes256-cts-hmac-sha1-96                     HOST/ADMEMIDMAPNSS.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -3  aes256-cts-hmac-sha1-96                     HOST/ADMEMIDMAPNSS.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -1  aes256-cts-hmac-sha1-96                     HOST/host1.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -2  aes256-cts-hmac-sha1-96                     HOST/host1.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -3  aes256-cts-hmac-sha1-96                     HOST/host1.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -1  aes256-cts-hmac-sha1-96                     HOST/host2.other.com@ADDOM.SAMBA.EXAMPLE.COM
 -2  aes256-cts-hmac-sha1-96                     HOST/host2.other.com@ADDOM.SAMBA.EXAMPLE.COM
 -3  aes256-cts-hmac-sha1-96                     HOST/host2.other.com@ADDOM.SAMBA.EXAMPLE.COM
 -1  aes256-cts-hmac-sha1-96                     HOST/NETBIOS1@ADDOM.SAMBA.EXAMPLE.COM
 -2  aes256-cts-hmac-sha1-96                     HOST/NETBIOS1@ADDOM.SAMBA.EXAMPLE.COM
 -3  aes256-cts-hmac-sha1-96                     HOST/NETBIOS1@ADDOM.SAMBA.EXAMPLE.COM
 -1  aes256-cts-hmac-sha1-96                     HOST/netbios1.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -2  aes256-cts-hmac-sha1-96                     HOST/netbios1.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -3  aes256-cts-hmac-sha1-96                     HOST/netbios1.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -1  aes256-cts-hmac-sha1-96                     HOST/NETBIOS2@ADDOM.SAMBA.EXAMPLE.COM
 -2  aes256-cts-hmac-sha1-96                     HOST/NETBIOS2@ADDOM.SAMBA.EXAMPLE.COM
 -3  aes256-cts-hmac-sha1-96                     HOST/NETBIOS2@ADDOM.SAMBA.EXAMPLE.COM
 -1  aes256-cts-hmac-sha1-96                     HOST/netbios2.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -2  aes256-cts-hmac-sha1-96                     HOST/netbios2.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -3  aes256-cts-hmac-sha1-96                     HOST/netbios2.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -1  aes256-cts-hmac-sha1-96                     HOST/NETBIOS3@ADDOM.SAMBA.EXAMPLE.COM
 -2  aes256-cts-hmac-sha1-96                     HOST/NETBIOS3@ADDOM.SAMBA.EXAMPLE.COM
 -3  aes256-cts-hmac-sha1-96                     HOST/NETBIOS3@ADDOM.SAMBA.EXAMPLE.COM
 -1  aes256-cts-hmac-sha1-96                     HOST/netbios3.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -2  aes256-cts-hmac-sha1-96                     HOST/netbios3.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -3  aes256-cts-hmac-sha1-96                     HOST/netbios3.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -1  aes256-cts-hmac-sha1-96                     RestrictedKrbHost/ADMEMIDMAPNSS@ADDOM.SAMBA.EXAMPLE.COM
 -2  aes256-cts-hmac-sha1-96                     RestrictedKrbHost/ADMEMIDMAPNSS@ADDOM.SAMBA.EXAMPLE.COM
 -3  aes256-cts-hmac-sha1-96                     RestrictedKrbHost/ADMEMIDMAPNSS@ADDOM.SAMBA.EXAMPLE.COM
 -1  aes256-cts-hmac-sha1-96                     RestrictedKrbHost/ADMEMIDMAPNSS.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -2  aes256-cts-hmac-sha1-96                     RestrictedKrbHost/ADMEMIDMAPNSS.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -3  aes256-cts-hmac-sha1-96                     RestrictedKrbHost/ADMEMIDMAPNSS.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
";

keytab1k="\
  4  aes256-cts-hmac-sha1-96                     HOST/ADMEMIDMAPNSS@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     HOST/ADMEMIDMAPNSS@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     HOST/ADMEMIDMAPNSS@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     HOST/ADMEMIDMAPNSS.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     HOST/ADMEMIDMAPNSS.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     HOST/ADMEMIDMAPNSS.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     HOST/host1.example.com@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     HOST/host1.example.com@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     HOST/host1.example.com@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     HOST/host2.other.com@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     HOST/host2.other.com@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     HOST/host2.other.com@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     HOST/NETBIOS1@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     HOST/NETBIOS1@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     HOST/NETBIOS1@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     HOST/netbios1.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     HOST/netbios1.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     HOST/netbios1.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     HOST/NETBIOS2@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     HOST/NETBIOS2@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     HOST/NETBIOS2@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     HOST/netbios2.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     HOST/netbios2.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     HOST/netbios2.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     HOST/NETBIOS3@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     HOST/NETBIOS3@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     HOST/NETBIOS3@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     HOST/netbios3.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     HOST/netbios3.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     HOST/netbios3.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     RestrictedKrbHost/ADMEMIDMAPNSS@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     RestrictedKrbHost/ADMEMIDMAPNSS@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     RestrictedKrbHost/ADMEMIDMAPNSS@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     RestrictedKrbHost/ADMEMIDMAPNSS.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     RestrictedKrbHost/ADMEMIDMAPNSS.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     RestrictedKrbHost/ADMEMIDMAPNSS.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
";

keytab2="\
 -1  aes256-cts-hmac-sha1-96                     host/ADMEMIDMAPNSS@ADDOM.SAMBA.EXAMPLE.COM
 -2  aes256-cts-hmac-sha1-96                     host/ADMEMIDMAPNSS@ADDOM.SAMBA.EXAMPLE.COM
 -3  aes256-cts-hmac-sha1-96                     host/ADMEMIDMAPNSS@ADDOM.SAMBA.EXAMPLE.COM
 -1  aes256-cts-hmac-sha1-96                     host/admemidmapnss.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -2  aes256-cts-hmac-sha1-96                     host/admemidmapnss.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -3  aes256-cts-hmac-sha1-96                     host/admemidmapnss.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -1  aes256-cts-hmac-sha1-96                     host/host1.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -2  aes256-cts-hmac-sha1-96                     host/host1.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -3  aes256-cts-hmac-sha1-96                     host/host1.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -1  aes256-cts-hmac-sha1-96                     host/host2.other.com@ADDOM.SAMBA.EXAMPLE.COM
 -2  aes256-cts-hmac-sha1-96                     host/host2.other.com@ADDOM.SAMBA.EXAMPLE.COM
 -3  aes256-cts-hmac-sha1-96                     host/host2.other.com@ADDOM.SAMBA.EXAMPLE.COM
 -1  aes256-cts-hmac-sha1-96                     host/NETBIOS1@ADDOM.SAMBA.EXAMPLE.COM
 -2  aes256-cts-hmac-sha1-96                     host/NETBIOS1@ADDOM.SAMBA.EXAMPLE.COM
 -3  aes256-cts-hmac-sha1-96                     host/NETBIOS1@ADDOM.SAMBA.EXAMPLE.COM
 -1  aes256-cts-hmac-sha1-96                     host/netbios1.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -2  aes256-cts-hmac-sha1-96                     host/netbios1.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -3  aes256-cts-hmac-sha1-96                     host/netbios1.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -1  aes256-cts-hmac-sha1-96                     host/NETBIOS2@ADDOM.SAMBA.EXAMPLE.COM
 -2  aes256-cts-hmac-sha1-96                     host/NETBIOS2@ADDOM.SAMBA.EXAMPLE.COM
 -3  aes256-cts-hmac-sha1-96                     host/NETBIOS2@ADDOM.SAMBA.EXAMPLE.COM
 -1  aes256-cts-hmac-sha1-96                     host/netbios2.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -2  aes256-cts-hmac-sha1-96                     host/netbios2.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -3  aes256-cts-hmac-sha1-96                     host/netbios2.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -1  aes256-cts-hmac-sha1-96                     host/NETBIOS3@ADDOM.SAMBA.EXAMPLE.COM
 -2  aes256-cts-hmac-sha1-96                     host/NETBIOS3@ADDOM.SAMBA.EXAMPLE.COM
 -3  aes256-cts-hmac-sha1-96                     host/NETBIOS3@ADDOM.SAMBA.EXAMPLE.COM
 -1  aes256-cts-hmac-sha1-96                     host/netbios3.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -2  aes256-cts-hmac-sha1-96                     host/netbios3.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -3  aes256-cts-hmac-sha1-96                     host/netbios3.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -1  aes256-cts-hmac-sha1-96                     imap/ADMEMIDMAPNSS@ADDOM.SAMBA.EXAMPLE.COM
 -2  aes256-cts-hmac-sha1-96                     imap/ADMEMIDMAPNSS@ADDOM.SAMBA.EXAMPLE.COM
 -3  aes256-cts-hmac-sha1-96                     imap/ADMEMIDMAPNSS@ADDOM.SAMBA.EXAMPLE.COM
 -1  aes256-cts-hmac-sha1-96                     imap/admemidmapnss.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -2  aes256-cts-hmac-sha1-96                     imap/admemidmapnss.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -3  aes256-cts-hmac-sha1-96                     imap/admemidmapnss.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -1  aes256-cts-hmac-sha1-96                     imap/host1.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -2  aes256-cts-hmac-sha1-96                     imap/host1.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -3  aes256-cts-hmac-sha1-96                     imap/host1.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -1  aes256-cts-hmac-sha1-96                     imap/host2.other.com@ADDOM.SAMBA.EXAMPLE.COM
 -2  aes256-cts-hmac-sha1-96                     imap/host2.other.com@ADDOM.SAMBA.EXAMPLE.COM
 -3  aes256-cts-hmac-sha1-96                     imap/host2.other.com@ADDOM.SAMBA.EXAMPLE.COM
 -1  aes256-cts-hmac-sha1-96                     imap/NETBIOS1@ADDOM.SAMBA.EXAMPLE.COM
 -2  aes256-cts-hmac-sha1-96                     imap/NETBIOS1@ADDOM.SAMBA.EXAMPLE.COM
 -3  aes256-cts-hmac-sha1-96                     imap/NETBIOS1@ADDOM.SAMBA.EXAMPLE.COM
 -1  aes256-cts-hmac-sha1-96                     imap/netbios1.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -2  aes256-cts-hmac-sha1-96                     imap/netbios1.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -3  aes256-cts-hmac-sha1-96                     imap/netbios1.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -1  aes256-cts-hmac-sha1-96                     imap/NETBIOS2@ADDOM.SAMBA.EXAMPLE.COM
 -2  aes256-cts-hmac-sha1-96                     imap/NETBIOS2@ADDOM.SAMBA.EXAMPLE.COM
 -3  aes256-cts-hmac-sha1-96                     imap/NETBIOS2@ADDOM.SAMBA.EXAMPLE.COM
 -1  aes256-cts-hmac-sha1-96                     imap/netbios2.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -2  aes256-cts-hmac-sha1-96                     imap/netbios2.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -3  aes256-cts-hmac-sha1-96                     imap/netbios2.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -1  aes256-cts-hmac-sha1-96                     imap/NETBIOS3@ADDOM.SAMBA.EXAMPLE.COM
 -2  aes256-cts-hmac-sha1-96                     imap/NETBIOS3@ADDOM.SAMBA.EXAMPLE.COM
 -3  aes256-cts-hmac-sha1-96                     imap/NETBIOS3@ADDOM.SAMBA.EXAMPLE.COM
 -1  aes256-cts-hmac-sha1-96                     imap/netbios3.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -2  aes256-cts-hmac-sha1-96                     imap/netbios3.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -3  aes256-cts-hmac-sha1-96                     imap/netbios3.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -1  aes256-cts-hmac-sha1-96                     smtp/ADMEMIDMAPNSS@ADDOM.SAMBA.EXAMPLE.COM
 -2  aes256-cts-hmac-sha1-96                     smtp/ADMEMIDMAPNSS@ADDOM.SAMBA.EXAMPLE.COM
 -3  aes256-cts-hmac-sha1-96                     smtp/ADMEMIDMAPNSS@ADDOM.SAMBA.EXAMPLE.COM
 -1  aes256-cts-hmac-sha1-96                     smtp/admemidmapnss.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -2  aes256-cts-hmac-sha1-96                     smtp/admemidmapnss.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -3  aes256-cts-hmac-sha1-96                     smtp/admemidmapnss.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -1  aes256-cts-hmac-sha1-96                     smtp/host1.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -2  aes256-cts-hmac-sha1-96                     smtp/host1.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -3  aes256-cts-hmac-sha1-96                     smtp/host1.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -1  aes256-cts-hmac-sha1-96                     smtp/host2.other.com@ADDOM.SAMBA.EXAMPLE.COM
 -2  aes256-cts-hmac-sha1-96                     smtp/host2.other.com@ADDOM.SAMBA.EXAMPLE.COM
 -3  aes256-cts-hmac-sha1-96                     smtp/host2.other.com@ADDOM.SAMBA.EXAMPLE.COM
 -1  aes256-cts-hmac-sha1-96                     smtp/NETBIOS1@ADDOM.SAMBA.EXAMPLE.COM
 -2  aes256-cts-hmac-sha1-96                     smtp/NETBIOS1@ADDOM.SAMBA.EXAMPLE.COM
 -3  aes256-cts-hmac-sha1-96                     smtp/NETBIOS1@ADDOM.SAMBA.EXAMPLE.COM
 -1  aes256-cts-hmac-sha1-96                     smtp/netbios1.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -2  aes256-cts-hmac-sha1-96                     smtp/netbios1.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -3  aes256-cts-hmac-sha1-96                     smtp/netbios1.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -1  aes256-cts-hmac-sha1-96                     smtp/NETBIOS2@ADDOM.SAMBA.EXAMPLE.COM
 -2  aes256-cts-hmac-sha1-96                     smtp/NETBIOS2@ADDOM.SAMBA.EXAMPLE.COM
 -3  aes256-cts-hmac-sha1-96                     smtp/NETBIOS2@ADDOM.SAMBA.EXAMPLE.COM
 -1  aes256-cts-hmac-sha1-96                     smtp/netbios2.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -2  aes256-cts-hmac-sha1-96                     smtp/netbios2.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -3  aes256-cts-hmac-sha1-96                     smtp/netbios2.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -1  aes256-cts-hmac-sha1-96                     smtp/NETBIOS3@ADDOM.SAMBA.EXAMPLE.COM
 -2  aes256-cts-hmac-sha1-96                     smtp/NETBIOS3@ADDOM.SAMBA.EXAMPLE.COM
 -3  aes256-cts-hmac-sha1-96                     smtp/NETBIOS3@ADDOM.SAMBA.EXAMPLE.COM
 -1  aes256-cts-hmac-sha1-96                     smtp/netbios3.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -2  aes256-cts-hmac-sha1-96                     smtp/netbios3.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
 -3  aes256-cts-hmac-sha1-96                     smtp/netbios3.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
";

keytab2k="\
  4  aes256-cts-hmac-sha1-96                     host/ADMEMIDMAPNSS@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     host/ADMEMIDMAPNSS@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     host/ADMEMIDMAPNSS@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     host/admemidmapnss.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     host/admemidmapnss.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     host/admemidmapnss.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     host/host1.example.com@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     host/host1.example.com@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     host/host1.example.com@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     host/host2.other.com@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     host/host2.other.com@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     host/host2.other.com@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     imap/ADMEMIDMAPNSS@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     imap/ADMEMIDMAPNSS@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     imap/ADMEMIDMAPNSS@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     imap/admemidmapnss.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     imap/admemidmapnss.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     imap/admemidmapnss.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     imap/host1.example.com@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     imap/host1.example.com@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     imap/host1.example.com@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     imap/host2.other.com@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     imap/host2.other.com@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     imap/host2.other.com@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     smtp/ADMEMIDMAPNSS@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     smtp/ADMEMIDMAPNSS@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     smtp/ADMEMIDMAPNSS@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     smtp/admemidmapnss.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     smtp/admemidmapnss.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     smtp/admemidmapnss.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     smtp/host1.example.com@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     smtp/host1.example.com@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     smtp/host1.example.com@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     smtp/host2.other.com@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     smtp/host2.other.com@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     smtp/host2.other.com@ADDOM.SAMBA.EXAMPLE.COM
";

keytab3="\
 -1  aes256-cts-hmac-sha1-96                     wurst/brot@ADDOM.SAMBA.EXAMPLE.COM
 -2  aes256-cts-hmac-sha1-96                     wurst/brot@ADDOM.SAMBA.EXAMPLE.COM
 -3  aes256-cts-hmac-sha1-96                     wurst/brot@ADDOM.SAMBA.EXAMPLE.COM
";

keytab3k="\
  4  aes256-cts-hmac-sha1-96                     wurst1/brot@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     wurst1/brot@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     wurst1/brot@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     wurst2/brot@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     wurst2/brot@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     wurst2/brot@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     wurst/brot@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     wurst/brot@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     wurst/brot@ADDOM.SAMBA.EXAMPLE.COM
";

keytab4k="\
  4  aes256-cts-hmac-sha1-96                     ADMEMIDMAPNSS\$@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     ADMEMIDMAPNSS\$@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     ADMEMIDMAPNSS\$@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     ADMEMIDMAPNSS\$@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     ADMEMIDMAPNSS\$@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     ADMEMIDMAPNSS\$@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     host/ADMEMIDMAPNSS@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     host/ADMEMIDMAPNSS@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     host/ADMEMIDMAPNSS@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     host/admemidmapnss.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     host/admemidmapnss.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     host/admemidmapnss.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     host/host1.example.com@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     host/host1.example.com@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     host/host1.example.com@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     host/host2.other.com@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     host/host2.other.com@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     host/host2.other.com@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     host/NETBIOS1@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     host/NETBIOS1@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     host/NETBIOS1@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     host/netbios1.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     host/netbios1.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     host/netbios1.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     host/NETBIOS2@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     host/NETBIOS2@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     host/NETBIOS2@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     host/netbios2.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     host/netbios2.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     host/netbios2.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     host/NETBIOS3@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     host/NETBIOS3@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     host/NETBIOS3@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     host/netbios3.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     host/netbios3.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     host/netbios3.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     imap/ADMEMIDMAPNSS@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     imap/ADMEMIDMAPNSS@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     imap/ADMEMIDMAPNSS@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     imap/admemidmapnss.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     imap/admemidmapnss.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     imap/admemidmapnss.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     imap/host1.example.com@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     imap/host1.example.com@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     imap/host1.example.com@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     imap/host2.other.com@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     imap/host2.other.com@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     imap/host2.other.com@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     imap/NETBIOS1@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     imap/NETBIOS1@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     imap/NETBIOS1@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     imap/netbios1.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     imap/netbios1.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     imap/netbios1.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     imap/NETBIOS2@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     imap/NETBIOS2@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     imap/NETBIOS2@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     imap/netbios2.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     imap/netbios2.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     imap/netbios2.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     imap/NETBIOS3@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     imap/NETBIOS3@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     imap/NETBIOS3@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     imap/netbios3.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     imap/netbios3.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     imap/netbios3.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     smtp/ADMEMIDMAPNSS@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     smtp/ADMEMIDMAPNSS@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     smtp/ADMEMIDMAPNSS@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     smtp/admemidmapnss.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     smtp/admemidmapnss.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     smtp/admemidmapnss.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     smtp/host1.example.com@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     smtp/host1.example.com@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     smtp/host1.example.com@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     smtp/host2.other.com@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     smtp/host2.other.com@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     smtp/host2.other.com@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     smtp/NETBIOS1@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     smtp/NETBIOS1@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     smtp/NETBIOS1@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     smtp/netbios1.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     smtp/netbios1.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     smtp/netbios1.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     smtp/NETBIOS2@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     smtp/NETBIOS2@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     smtp/NETBIOS2@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     smtp/netbios2.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     smtp/netbios2.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     smtp/netbios2.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     smtp/NETBIOS3@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     smtp/NETBIOS3@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     smtp/NETBIOS3@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     smtp/netbios3.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     smtp/netbios3.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     smtp/netbios3.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     wurst1/brot@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     wurst1/brot@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     wurst1/brot@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     wurst2/brot@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     wurst2/brot@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     wurst2/brot@ADDOM.SAMBA.EXAMPLE.COM
  4  aes256-cts-hmac-sha1-96                     wurst/brot@ADDOM.SAMBA.EXAMPLE.COM
  5  aes256-cts-hmac-sha1-96                     wurst/brot@ADDOM.SAMBA.EXAMPLE.COM
  6  aes256-cts-hmac-sha1-96                     wurst/brot@ADDOM.SAMBA.EXAMPLE.COM
";

# find the biggest vno and store it into global variable vno
get_biggest_vno()
{
	keytab="$1"
	cmd="$samba_net ads keytab list $keytab"
	eval echo "$cmd"
	out=$(eval "$cmd")
	ret=$?

	echo "$out"

	if [ $ret != 0 ] ; then
		echo "command failed"
		return 1
	fi

	#global variable vno
	vno=$(echo "$out" | sort -n | tail -1 | awk '{printf $1}')

	if [ -z "$vno" ] ; then
		echo "There is no key with vno in the keytab list above."
		return 1
	fi

	return 0
}

# Heimdal format
#  3  aes256-cts-hmac-sha1-96                     HOST/ADMEMIDMAPNSS.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
#  3  aes128-cts-hmac-sha1-96                     HOST/ADMEMIDMAPNSS.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
#  3  arcfour-hmac-md5                            HOST/ADMEMIDMAPNSS.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM

# MIT format
#  3  AES-256 CTS mode with 96-bit SHA-1 HMAC     HOST/ADMEMIDMAPNSS.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
#  3  AES-128 CTS mode with 96-bit SHA-1 HMAC     HOST/ADMEMIDMAPNSS.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
#  3  ArcFour with HMAC/md5                       HOST/ADMEMIDMAPNSS.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM

# The sed command using the pattern $SED1 normalizes both:

#  Heimdal format
#  3 AES-256 HOST/ADMEMIDMAPNSS.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
#  3 AES-128 HOST/ADMEMIDMAPNSS.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
#  3 ArcFour HOST/ADMEMIDMAPNSS.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM

#  MIT format
#  3 AES-256 HOST/ADMEMIDMAPNSS.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
#  3 AES-128 HOST/ADMEMIDMAPNSS.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM
#  3 ArcFour HOST/ADMEMIDMAPNSS.addom.samba.example.com@ADDOM.SAMBA.EXAMPLE.COM


# Normalize enc types and remove repeating spaces
SED1="\
s/aes256-cts-hmac-sha1-96/AES-256/;\
s/aes128-cts-hmac-sha1-96/AES-128/;\
s/arcfour-hmac-md5/ArcFour/;\
s/AES-256 CTS mode with 96-bit SHA-1 HMAC/AES-256/;\
s/AES-128 CTS mode with 96-bit SHA-1 HMAC/AES-128/;\
s/ArcFour with HMAC\/md5/ArcFour/;\
s/ \\+/ /g"

# Remove the first column with Vno
SED2="s/^ \+-\?[0-9]\+ \+//"

compare_keytabs_sync_kvno()
{
	sed "$SED1" < "$1" | sed "$SED2" | sort > "${1}.sync_kvno"
	sed "$SED1" < "$2" | sed "$SED2" | sort > "${2}.sync_kvno"
	diff "${1}.sync_kvno"  "${2}.sync_kvno"
	return $?
}

compare_keytabs_nosync_kvno()
{
	sed "$SED1" < "$1"  | sort -k1rn -k3 > "${1}.nosync_kvno"
	sed "$SED1" < "$2"  | sort -k1rn -k3 > "${2}.nosync_kvno"
	diff "${1}.nosync_kvno"  "${2}.nosync_kvno"
	return $?
}

test_pwd_change()
{
	testname="$1"
	shift

	# get biggest vno before password change from keytab1k
	get_biggest_vno "$PREFIX_ABS/ad_member_idmap_nss/keytab1k"
	old_vno=$vno

	if [ ! "$old_vno" -gt 0 ] ; then
		echo "There is no key with vno in the keytab list above."
		return 1
	fi

	# change password
	cmd="$*";
	eval echo "$cmd"
	out=$(eval "$cmd")
	ret=$?

	if [ $ret != 0 ] ; then
		echo "$out"
		echo "command failed"
		return 1
	fi

	# test ads join
	cmd="$samba_net ads testjoin"
	eval echo "$cmd"
	out=$(eval "$cmd")
	ret=$?

	if [ $ret != 0 ] ; then
		echo "$out"
		echo "command failed"
		return 1
	fi

	# if keytab was updated the bigest vno should be incremented by one
	get_biggest_vno "$PREFIX_ABS/ad_member_idmap_nss/keytab1k"

	if [ ! "$vno" -eq $((old_vno + 1)) ] ; then
		echo "Old vno=$old_vno, new vno=$vno. Increment by one failed."
		return 1
	fi

	# Store keytabs in the tmp dir
	for keytab in $keytabs_all
	do
		$samba_net ads keytab list "$PREFIX_ABS/ad_member_idmap_nss/$keytab" | grep -v "^Vno\|^Warning\|^$"  > "$TMPDIR/${keytab}_${testname}"
	done

	# Compare keytabs that do not sync kvno
	for keytab in $keytabs_nosync_kvno
	do
		if ! compare_keytabs_nosync_kvno "$TMPDIR/${keytab}_template"  "$TMPDIR/${keytab}_${testname}"
		then
			echo "Comparison of $keytab failed"
			return 1
		fi
	done

	# Compare keytabs that sync kvno
	for keytab in $keytabs_sync_kvno
	do
		if ! compare_keytabs_sync_kvno "$TMPDIR/${keytab}_template"  "$TMPDIR/${keytab}_${testname}"
		then
			echo "Comparison of $keytab failed"
			return 1
		fi
	done

	return 0
}


# Create tmp dir
TMPDIR=$(mktemp -d "$PREFIX_ABS/ad_member_idmap_nss/keytab_dir_XXXXXX")

# Create template files using the variables defined above
printf '%s' "$keytab0" > "$TMPDIR/keytab0_template"
printf '%s' "$keytab0k" > "$TMPDIR/keytab0k_template"
printf '%s' "$keytab1" > "$TMPDIR/keytab1_template"
printf '%s' "$keytab1k" > "$TMPDIR/keytab1k_template"
printf '%s' "$keytab2" > "$TMPDIR/keytab2_template"
printf '%s' "$keytab2k" > "$TMPDIR/keytab2k_template"
printf '%s' "$keytab3" > "$TMPDIR/keytab3_template"
printf '%s' "$keytab3k" > "$TMPDIR/keytab3k_template"
printf '%s' "$keytab4k" > "$TMPDIR/keytab4k_template"

# Other approach could e.g. compare first six entries from the template.
# The 6 entries correspond to password and old_password, each has 3 enc. types.
# for k in "$TMPDIR"/keytab*_template
# do
# 	head -6 "$k" > "${k}_head6"
# done

# Remove all keytabs
for keytab in $keytabs_all
do
	rm -f "$PREFIX_ABS/ad_member_idmap_nss/$keytab"
done

DC_DNSNAME="${DC_SERVER}.${REALM}"
SMBCLIENT_UNC="//${DC_DNSNAME}/tmp"

# To have both old and older password we do one unnecessary password change:
testit "wbinfo_change_secret_initial" \
	"$samba_wbinfo" --change-secret --domain="${DOMAIN}" \
	|| failed=$((failed + 1))

testit "wbinfo_check_secret_initial" \
	"$samba_wbinfo" --check-secret --domain="${DOMAIN}" \
	|| failed=$((failed + 1))

# Create/sync all keytabs
testit "net_ads_keytab_sync" "$samba_net" ads keytab create || failed=$((failed + 1))

testit "wbinfo_change_secret" \
	test_pwd_change "wbinfo_changesecret" \
	"$samba_wbinfo --change-secret --domain=${DOMAIN}" \
	|| failed=$((failed + 1))

testit "wbinfo_check_secret" \
	"$samba_wbinfo" --check-secret --domain="${DOMAIN}" \
	|| failed=$((failed + 1))

test_smbclient "Test machine login with the changed secret" \
	"ls" "${SMBCLIENT_UNC}" \
	--machine-pass ||
	failed=$((failed + 1))


testit "rpcclient_changetrustpw" test_pwd_change "rpcclient_changetrustpw"	"$samba_rpcclient --machine-pass ncacn_np:${DC_DNSNAME}[schannel] -c change_trust_pw" || failed=$((failed + 1))
testit "net_rpc_changetrustpw"   test_pwd_change "net_rpc_changetrustpw"	"$samba_net rpc changetrustpw -I ${DC_DNSNAME}" || failed=$((failed + 1))
testit "net_ads_changetrustpw"   test_pwd_change "net_ads_changetrustpw"	"$samba_net ads changetrustpw -I ${DC_DNSNAME}" || failed=$((failed + 1))

test_smbclient "Test machine login with the changed secret end" \
	"ls" "${SMBCLIENT_UNC}" \
	--machine-pass ||
	failed=$((failed + 1))

# Delete tmp dir
rm -rf "$TMPDIR"

testok "$0" "$failed"
