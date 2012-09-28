#!/bin/sh

APP="test_deencap_fault"

# parse arguments
SCRIPT="$0"
if [ "x$MAKELEVEL" != "x" ] ; then
    BASEDIR="${srcdir}"
    APP="./${APP}"
else
    BASEDIR=$( dirname "${SCRIPT}" )
    APP="${BASEDIR}/${APP}"
fi

gse_args="0x0801 ${BASEDIR}/input/deencap_padding.pcap"

for args in "${gse_args}"; do
  ${APP} ${args} || ${APP} verbose ${args}
  if [ "$?" -ne "0" ]; then
    exit 1
  fi
done

