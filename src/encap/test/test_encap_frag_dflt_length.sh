#!/bin/sh

APP="test_encap"

# parse arguments
SCRIPT="$0"
if [ "x$MAKELEVEL" != "x" ] ; then
    BASEDIR="${srcdir}"
    APP="./${APP}"
else
    BASEDIR=$( dirname "${SCRIPT}" )
    APP="${BASEDIR}/${APP}"
fi

gse_args="-l 0 -c ${BASEDIR}/output/encap_frag_dflt_length.pcap -i ${BASEDIR}/input/encap_frag_dflt_length.pcap"
gse_mult_args="-l 0 -c ${BASEDIR}/output/encap_mult_frag_dflt_length.pcap -i ${BASEDIR}/input/encap_mult_frag_dflt_length.pcap"
gse_mult_args_lmax="-l 4097 -c ${BASEDIR}/output/encap_mult_frag_dflt_length.pcap -i ${BASEDIR}/input/encap_mult_frag_dflt_length.pcap"


for args in "${gse_args}" \
            "${gse_mult_args}" \
            "${gse_mult_args_lmax}"; do
  ${APP} ${args} || ${APP} --verbose ${args}
  if [ "$?" -ne "0" ]; then
    exit 1
  fi
done

