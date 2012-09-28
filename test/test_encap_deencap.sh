#!/bin/sh

APP="test_encap_deencap"

# parse arguments
SCRIPT="$0"
if [ "x$MAKELEVEL" != "x" ] ; then
    BASEDIR="${srcdir}"
    APP="./${APP}"
else
    BASEDIR=$( dirname "${SCRIPT}" )
    APP="${BASEDIR}/${APP}"
fi

gse_args="0 ${BASEDIR}/encap_deencap_max_pdu_length.pcap"

for args in "${gse_args}"; do
  ${APP} ${args} || ${APP} verbose ${args}
  if [ "$?" -ne "0" ]; then
    exit 1
  fi
done

