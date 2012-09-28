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

gse_args_complete_label3="${BASEDIR}/output/deencap_complete.pcap ${BASEDIR}/input/deencap_complete_label3.pcap"
gse_args_complete_label0="${BASEDIR}/output/deencap_complete.pcap ${BASEDIR}/input/deencap_complete_label0.pcap"

gse_args_frag_label3="${BASEDIR}/output/deencap_frag.pcap ${BASEDIR}/input/deencap_frag_label3.pcap"
gse_args_frag_label0="${BASEDIR}/output/deencap_frag.pcap ${BASEDIR}/input/deencap_frag_label0.pcap"

for args in "${gse_args_complete_label3}" \
            "${gse_args_complete_label0}" \
            "${gse_args_frag_label3}" \
            "${gse_args_frag_label0}"; do
  ${APP} ${args} || ${APP} verbose ${args}
  if [ "$?" -ne "0" ]; then
    exit 1
  fi
done


