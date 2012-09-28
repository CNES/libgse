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

gse_args="-l 39 -c ${BASEDIR}/output/encap_frag.pcap -i ${BASEDIR}/input/encap_frag.pcap"
gse_mult_args="-l 39 -c ${BASEDIR}/output/encap_mult_frag.pcap -i ${BASEDIR}/input/encap_mult_frag.pcap"


for args in "${gse_args}" \
            "${gse_mult_args}"; do
  ${APP} ${args} || ${APP} --verbose ${args}
  if [ "$?" -ne "0" ]; then
    exit 1
  fi
done

