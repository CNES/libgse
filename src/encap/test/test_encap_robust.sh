#!/bin/sh

APP="test_encap_robust"

# parse arguments
SCRIPT="$0"
if [ "x$MAKELEVEL" != "x" ] ; then
	BASEDIR="${srcdir}"
	APP="./${APP}"
else
	BASEDIR=$( dirname "${SCRIPT}" )
	APP="${BASEDIR}/${APP}"
fi

${APP} 0x0402 2 ${BASEDIR}/input/encap_frag.pcap || ${APP} verbose 0x0402 2 ${BASEDIR}/input/encap_frag.pcap
if [ "$?" -ne "0" ]; then
  exit 1
fi
${APP} 0x0403 4098 ${BASEDIR}/input/encap_frag.pcap || ${APP} verbose 0x0403 4098 ${BASEDIR}/input/encap_frag.pcap
if [ "$?" -ne "0" ]; then
  exit 1
fi
${APP} 0x0301 0 ${BASEDIR}/input/encap_fifo_full.pcap || ${APP} verbose 0x0301 0 ${BASEDIR}/input/encap_fifo_full.pcap
if [ "$?" -ne "0" ]; then
  exit 1
fi
${APP} 0x0401 0 ${BASEDIR}/input/encap_pdu_too_long.pcap || ${APP} verbose 0x0401 0 ${BASEDIR}/input/encap_pdu_too_long.pcap
if [ "$?" -ne "0" ]; then
  exit 1
fi

APP="test_encap_bad_zero_copy"

# parse arguments
SCRIPT="$0"
if [ "x$MAKELEVEL" != "x" ] ; then
	BASEDIR="${srcdir}"
	APP="./${APP}"
else
	BASEDIR=$( dirname "${SCRIPT}" )
	APP="${BASEDIR}/${APP}"
fi

${APP} 0x0201 60 ${BASEDIR}/input/encap_complete.pcap || ${APP} verbose 0x0201 60 ${BASEDIR}/input/encap_complete.pcap

