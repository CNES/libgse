#!/bin/sh

APP="test_encap_robust"
APP2="test_encap_bad_zero_copy"

# parse arguments
SCRIPT="$0"
if [ "x$MAKELEVEL" != "x" ] ; then
    BASEDIR="${srcdir}"
    APP="./${APP}"
    APP2="./${APP2}"
else
    BASEDIR=$( dirname "${SCRIPT}" )
    APP="${BASEDIR}/${APP}"
    APP2="${BASEDIR}/${APP2}"
fi

gse_402_args="0x0402 2 ${BASEDIR}/input/encap_frag.pcap"
gse_403_args="0x0403 4098 ${BASEDIR}/input/encap_frag.pcap"
gse_fifo_full_args="0x0301 0 ${BASEDIR}/input/encap_fifo_full.pcap"
gse_pdu_too_long_args="0x0401 0 ${BASEDIR}/input/encap_pdu_too_long.pcap"

for args in "${gse_402_args}" \
            "${gse_403_args}" \
            "${gse_fifo_full_args}" \
            "${gse_pdu_too_long_args}"; do
  ${APP} ${args} || ${APP} verbose ${args}
  if [ "$?" -ne "0" ]; then
    exit 1
  fi
done


gse_201_args="0x0201 60 ${BASEDIR}/input/encap_complete.pcap"

for args in "${gse_201_args}"; do
  ${APP2} ${args} || ${APP2} verbose ${args}
  if [ "$?" -ne "0" ]; then
    exit 1
  fi
done

