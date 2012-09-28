#!/bin/sh

APP="test_fifo"

# parse arguments
SCRIPT="$0"
if [ "x$MAKELEVEL" != "x" ] ; then
    BASEDIR="${srcdir}"
    APP="./${APP}"
else
    BASEDIR=$( dirname "${SCRIPT}" )
    APP="${BASEDIR}/${APP}"
fi

gse_args="3 ${BASEDIR}/output/encap_mult_fifo.pcap ${BASEDIR}/input/encap_mult_fifo.pcap"

for args in "${gse_args}"; do
  ${APP} ${args} || ${APP} verbose ${args}
  if [ "$?" -ne "0" ]; then
    exit 1
  fi
done

