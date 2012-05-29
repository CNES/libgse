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

${APP} ${BASEDIR}/output/deencap_incomplete_pdu.pcap ${BASEDIR}/input/deencap_incomplete_pdu.pcap || ${APP} verbose ${BASEDIR}/output/deencap_incomplete_pdu.pcap ${BASEDIR}/input/deencap_incomplete_pdu.pcap

