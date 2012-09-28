#!/bin/sh

APP="test_deencap"

# parse arguments
SCRIPT="$0"
if [ "x$MAKELEVEL" != "x" ] ; then
    BASEDIR="${srcdir}"
    APP="./${APP}"
else
    BASEDIR=$( dirname "${SCRIPT}" )
    APP="${BASEDIR}/${APP}"
fi

gse_args="${BASEDIR}/output/deencap_frag.pcap ${BASEDIR}/input/deencap_frag.pcap"
gse_mult_args="${BASEDIR}/output/deencap_mult_frag.pcap ${BASEDIR}/input/deencap_mult_frag.pcap"

for args in "${gse_args}" \
            "${gse_mult_args}"; do
  ${APP} ${args} || ${APP} verbose ${args}
  if [ "$?" -ne "0" ]; then
    exit 1
  fi
done

