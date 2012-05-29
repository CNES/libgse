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

${APP} 0x402 1 ${BASEDIR}/input/refrag_one.pcap || ${APP} verbose 0x402 1 ${BASEDIR}/input/refrag_one.pcap
if [ "$?" -ne "0" ]; then
  exit 1
fi
${APP} 0x404 39 ${BASEDIR}/input/refrag_min.pcap || ${APP} verbose 0x404 39 ${BASEDIR}/input/refrag_min.pcap
if [ "$?" -ne "0" ]; then
  exit 1
fi
${APP} 0x404 50 ${BASEDIR}/input/refrag_min.pcap || ${APP} verbose 0x404 50 ${BASEDIR}/input/refrag_min.pcap
if [ "$?" -ne "0" ]; then
  exit 1
fi
${APP} 0x402 12 ${BASEDIR}/input/refrag_one.pcap || ${APP} verbose 0x402 12 ${BASEDIR}/input/refrag_one.pcap
