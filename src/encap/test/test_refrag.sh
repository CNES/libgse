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

gse_args="39 ${BASEDIR}/output/refrag.pcap ${BASEDIR}/input/refrag.pcap"
gse_min_args="14 ${BASEDIR}/output/refrag_min.pcap ${BASEDIR}/input/refrag_min.pcap"


for args in "${gse_args}" \
            "${gse_min_args}"; do
  ${APP} ${args} || ${APP} verbose ${args}
  if [ "$?" -ne "0" ]; then
    exit 1
  fi
done

