#!/bin/ksh
##
## Samba-VirusFilter VFS modules
## Copyright (C) 2010-2016 SATOH Fumiyasu @ OSS Technology Corp., Japan
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 3 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program.  If not, see <http://www.gnu.org/licenses/>.
##

set -u

pdie() { echo "$0: ERROR: ${1-}" 1>&2; exit "${2-1}"; }

## ======================================================================

sendmail="${VIRUSFILTER_NOTIFY_SENDMAIL_COMMAND:-/usr/sbin/sendmail}"
sendmail_opts="${VIRUSFILTER_NOTIFY_SENDMAIL_OPTIONS:-}"

smbclient="${VIRUSFILTER_NOTIFY_SMBCLIENT_COMMAND:-@SAMBA_BINDIR@/smbclient}"
smbclient_opts="${VIRUSFILTER_NOTIFY_SMBCLIENT_OPTIONS:-}"

## ======================================================================

if [ -n "${VIRUSFILTER_RESULT_IS_CACHE-}" ]; then
  ## Result is cache. Ignore!
  exit 0
fi

if [ ! -t 1 ] && [ -z "${VIRUSFILTER_NOTIFY_BG-}" ]; then
  export VIRUSFILTER_NOTIFY_BG=1
  "$0" ${1+"$@"} </dev/null >/dev/null &
  exit 0
fi

## ----------------------------------------------------------------------

if [ -n "${VIRUSFILTER_INFECTED_FILE_ACTION-}" ]; then
  report="$VIRUSFILTER_INFECTED_FILE_REPORT"
else
  report="$VIRUSFILTER_SCAN_ERROR_REPORT"
fi

if [ X"$VIRUSFILTER_SERVER_NAME" != X"$VIRUSFILTER_SERVER_IP" ]; then
  server_name="$VIRUSFILTER_SERVER_NAME"
else
  server_name="$VIRUSFILTER_SERVER_NETBIOS_NAME"
fi

if [ X"$VIRUSFILTER_CLIENT_NAME" != X"$VIRUSFILTER_CLIENT_IP" ]; then
  client_name="$VIRUSFILTER_CLIENT_NAME"
else
  client_name="$VIRUSFILTER_CLIENT_NETBIOS_NAME"
fi

mail_to=""
winpopup_to=""
subject_prefix=""
sender=""
from=""
cc=""
bcc=""
content_type="text/plain"
content_encoding="UTF-8"

cmd_usage="Usage: $0 [OPTIONS]

Options:
  --mail-to ADDRESS
    Send a notice message to this e-mail address(es)
  --winpopup-to NAME
    Send a \"WinPopup\" message to this NetBIOS name
  --sender ADDRESS
    Envelope sender address for mail
  --from ADDRESS
    From: e-mail address for mail
  --cc ADDRESS
    Cc: e-mail address(es) for mail
  --bcc ADDRESS
    Bcc: e-mail address(es) for mail
  --subject-prefix PREFIX
    Subject: prefix string for mail
  --content-type TYPE
  --content-encoding ENCODING
    Content-Type: TYPE; charset=\"ENCODING\" for mail [$content_type; charset=\"$content_encoding\"]
  --header-file FILE
    Prepend the content of FILE to the message
  --footer-file FILE
    Append the content of FILE to the message
"

## ----------------------------------------------------------------------

getopts_want_arg()
{
  if [ "$#" -lt 2 ]; then
    pdie "Option requires an argument: $1"
  fi
  if [ "$#" -ge 3 ]; then
    if expr x"$2" : x"$3\$" >/dev/null; then
      : OK
    else
      pdie "Invalid value for option: $1 $2"
    fi
  fi
}

while [ "$#" -gt 0 ]; do
  OPT="$1"; shift
  case "$OPT" in
  --help)
    echo "$cmd_usage"
    exit 0
    ;;
  --mail-to)
    getopts_want_arg "$OPT" ${1+"$1"}
    mail_to="${mail_to:+$mail_to, }$1"; shift
    ;;
  --winpopup-to)
    getopts_want_arg "$OPT" ${1+"$1"}
    winpopup_to="$1"; shift
    ;;
  --sender)
    getopts_want_arg "$OPT" ${1+"$1"}
    sender="$1"; shift
    ;;
  --from)
    getopts_want_arg "$OPT" ${1+"$1"}
    from="$1"; shift
    ;;
  --cc)
    getopts_want_arg "$OPT" ${1+"$1"}
    cc="${cc:+$cc, }$1"; shift
    ;;
  --bcc)
    getopts_want_arg "$OPT" ${1+"$1"}
    bcc="${bcc:+$bcc, }$1"; shift
    ;;
  --subject-prefix)
    getopts_want_arg "$OPT" ${1+"$1"}
    subject_prefix="$1"; shift
    ;;
  --content-type)
    getopts_want_arg "$OPT" ${1+"$1"}
    content_type="$1"; shift
    ;;
  --content-encoding)
    getopts_want_arg "$OPT" ${1+"$1"}
    content_encoding="$1"; shift
    ;;
  --header-file)
    getopts_want_arg "$OPT" ${1+"$1"}
    header_file="$1"; shift
    ;;
  --footer-file)
    getopts_want_arg "$OPT" ${1+"$1"}
    footer_file="$1"; shift
    ;;
  --)
    break
    ;;
  -*)
    pdie "Invalid option: $OPT"
    ;;
  *)
    set -- "$OPT" ${1+"$@"}
    break
    ;;
  esac
done

[ -z "$sender" ] && sender="$from"
subject="$subject_prefix$report"

## ======================================================================

msg_header="\
Subject: $subject
Content-Type: $content_type; charset=$content_encoding
X-VIRUSFILTER-Version: $VIRUSFILTER_VERSION
X-VIRUSFILTER-Module-Name: $VIRUSFILTER_MODULE_NAME
"

if [ -n "${VIRUSFILTER_MODULE_VERSION-}" ]; then
  msg_header="${msg_header}\
X-VIRUSFILTER-Module-Version: $VIRUSFILTER_MODULE_VERSION
"
fi

if [ -n "${from-}" ]; then
  msg_header="${msg_header}\
From: $from
"
fi

if [ -n "${mail_to-}" ]; then
  msg_header="${msg_header}\
To: $mail_to
"
fi

if [ -n "${cc-}" ]; then
  msg_header="${msg_header}\
Cc: $cc
"
fi

if [ -n "${bcc-}" ]; then
  msg_header="${msg_header}\
Bcc: $bcc
"
fi

## ----------------------------------------------------------------------

msg_body=""

if [ -n "${header_file-}" ] && [ -f "$header_file" ]; then
  msg_body="${msg_body}\
`cat "$header_file"`
"
fi

msg_body="${msg_body}\
Server: $server_name ($VIRUSFILTER_SERVER_IP)
Server PID: $VIRUSFILTER_SERVER_PID
Service name: $VIRUSFILTER_SERVICE_NAME
Service path: $VIRUSFILTER_SERVICE_PATH
Client: $client_name ($VIRUSFILTER_CLIENT_IP)
User: $VIRUSFILTER_USER_DOMAIN\\$VIRUSFILTER_USER_NAME
"

if [ -n "${VIRUSFILTER_INFECTED_FILE_ACTION-}" ]; then
  msg_body="${msg_body}\
Infected file report: $VIRUSFILTER_INFECTED_FILE_REPORT
"
  msg_body="${msg_body}\
Infected file path: $VIRUSFILTER_SERVICE_PATH/$VIRUSFILTER_INFECTED_SERVICE_FILE_PATH
"
  msg_body="${msg_body}\
Infected file action: $VIRUSFILTER_INFECTED_FILE_ACTION
"
else
  msg_body="${msg_body}\
Scan error report: $VIRUSFILTER_SCAN_ERROR_REPORT
Scan error file path: $VIRUSFILTER_SERVICE_PATH/$VIRUSFILTER_SCAN_ERROR_SERVICE_FILE_PATH
"
fi

if [ -n "${VIRUSFILTER_QUARANTINED_FILE_PATH-}" ]; then
  msg_body="${msg_body}\
Quarantined/Renamed file path: ${VIRUSFILTER_QUARANTINED_FILE_PATH-}
"
fi

if [ -n "${footer_file-}" ] && [ -f "$footer_file" ]; then
  msg_body="${msg_body}\
`cat "$footer_file"`
"
fi

## ======================================================================

if [ -n "$mail_to" ]; then
  (echo "$msg_header"; echo "$msg_body") \
    |"$sendmail" -t -i ${sender:+-f "$sender"} $sendmail_opts
fi

if [ -n "$winpopup_to" ]; then
  echo "$msg_body" \
    |"$smbclient" -M "$winpopup_to" -U% $smbclient_opts \
    >/dev/null
fi

exit 0
