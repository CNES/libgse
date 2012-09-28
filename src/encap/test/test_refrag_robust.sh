#!/bin/sh

APP="test_refrag_robust"

# parse arguments
SCRIPT="$0"
if [ "x$MAKELEVEL" != "x" ] ; then
    BASEDIR="${srcdir}"
    APP="./${APP}"
else
    BASEDIR=$( dirname "${SCRIPT}" )
    APP="${BASEDIR}/${APP}"
fi

gse_args="0x402 1 ${BASEDIR}/input/refrag_one.pcap"
gse_min_args="0x404 39 ${BASEDIR}/input/refrag_min.pcap"
gse_refrag_min_args="0x404 39 ${BASEDIR}/input/refrag_min.pcap"
gse_refrag_one_args="0x402 12 ${BASEDIR}/input/refrag_one.pcap"

for args in "${gse_args}" \
            "${gse_min_args}" \
            "${gse_refrag_min_args}" \
            "${gse_refrag_one_args}"; do
  ${APP} ${args} || ${APP} verbose ${args}
  if [ "$?" -ne "0" ]; then
    exit 1
  fi
done

