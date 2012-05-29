#!/bin/sh

APP="test_encap_deencap"

# parse arguments
SCRIPT="$0"
if [ "x$MAKELEVEL" != "x" ] ; then
	BASEDIR="${srcdir}"
	APP="./${APP}"
else
	BASEDIR=$( dirname "${SCRIPT}" )
	APP="${BASEDIR}/${APP}"
fi

${APP} 0 ${BASEDIR}/encap_deencap_max_pdu_length.pcap || ${APP} verbose 0 ${BASEDIR}/encap_deencap_max_pdu_length.pcap
