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

gse_args_complete_label3="--label-type 1 -l 0 -c ${BASEDIR}/output/encap_complete_label3.pcap -i ${BASEDIR}/input/encap_complete.pcap"
gse_args_complete_label0="--label-type 2 -l 0 -c ${BASEDIR}/output/encap_complete_label0.pcap -i ${BASEDIR}/input/encap_complete.pcap"

gse_args_frag_label3="-l 39 -c ${BASEDIR}/output/encap_frag_label3.pcap --label-type 1 -i ${BASEDIR}/input/encap_frag.pcap"
gse_args_frag_label0="-l 39 -c ${BASEDIR}/output/encap_frag_label0.pcap --label-type 2 -i ${BASEDIR}/input/encap_frag.pcap"

for args in "${gse_args_complete_label3}" \
            "${gse_args_complete_label0}" \
            "${gse_args_frag_label3}" \
            "${gse_args_frag_label0}"; do
  ${APP} ${args} || ${APP} --verbose ${args}
  if [ "$?" -ne "0" ]; then
    exit 1
  fi
done


