#!/bin/sh

APP="test_refrag"

# parse arguments
SCRIPT="$0"
if [ "x$MAKELEVEL" != "x" ] ; then
    BASEDIR="${srcdir}"
    APP="./${APP}"
else
    BASEDIR=$( dirname "${SCRIPT}" )
    APP="${BASEDIR}/${APP}"
fi

gse_args_label3="39 ${BASEDIR}/output/refrag_label3.pcap ${BASEDIR}/input/refrag_label3.pcap"
gse_args_label0="39 ${BASEDIR}/output/refrag_label0.pcap ${BASEDIR}/input/refrag_label0.pcap"

for args in "${gse_args_label3}" \
            "${gse_args_label0}"; do
  ${APP} ${args} || ${APP} verbose ${args}
  if [ "$?" -ne "0" ]; then
    exit 1
  fi
done


