#! /bin/sh

LANG=C; export LANG
LC_ALL=C; export LC_ALL
LC_COLLATE=C; export LC_COLLATE

if (echo "testing\c"; echo 1,2,3) | grep c >/dev/null; then
  # Stardent Vistra SVR4 grep lacks -e, says ghazi@caip.rutgers.edu.
  if (echo -n testing; echo 1,2,3) | sed s/-n/xn/ | grep xn >/dev/null; then
    ac_n= ac_c='
' ac_t='	'
  else
    ac_n=-n ac_c= ac_t=
  fi
else
  ac_n= ac_c='\c' ac_t=
fi

if [ $# -lt 3 ]
then
  echo "Usage: $0 awk [-h headerdefine] outputheader proto_obj"
  exit 1
fi

awk="$1"
shift

if [ x"$1" = x-h ]
then
  headeropt="-v headername=$2"
  shift; shift;
else
  headeropt=""
fi

header="$1"
shift
headertmp="$header.$$.tmp~"

proto_src="`echo $@ | tr ' ' '\n' | sed -e 's/\.o/\.c/g' | sort | uniq | egrep -v 'ubiqx/|wrapped'`"

echo $ac_n "creating ${header}... " $ac_c

${awk} $headeropt \
  -f script/mkproto.awk $proto_src > $headertmp

if cmp -s $header $headertmp 2>/dev/null
then
  echo "$ac_t""unchanged."
  rm $headertmp
else
  echo "$ac_t""done."
  mv $headertmp $header
fi
