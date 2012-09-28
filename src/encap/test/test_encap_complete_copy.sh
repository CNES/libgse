#!/bin/sh

APP="test_encap_copy"

# parse arguments
SCRIPT="$0"
if [ "x$MAKELEVEL" != "x" ] ; then
    BASEDIR="${srcdir}"
    APP="./${APP}"
else
    BASEDIR=$( dirname "${SCRIPT}" )
    APP="${BASEDIR}/${APP}"
fi

gse_args="-l 0 -c ${BASEDIR}/output/encap_complete.pcap -i ${BASEDIR}/input/encap_complete.pcap"
gse_mult_args="-l 0 -c ${BASEDIR}/output/encap_mult_complete.pcap -i ${BASEDIR}/input/encap_mult_complete.pcap"


for args in "${gse_args}" \
            "${gse_mult_args}"; do
  ${APP} ${args} || ${APP} --verbose ${args}
  if [ "$?" -ne "0" ]; then
    exit 1
  fi
done

