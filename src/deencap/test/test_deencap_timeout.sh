#!/bin/sh

APP="test_deencap_timeout"

# parse arguments
SCRIPT="$0"
if [ "x$MAKELEVEL" != "x" ] ; then
	BASEDIR="${srcdir}"
	APP="./${APP}"
else
	BASEDIR=$( dirname "${SCRIPT}" )
	APP="${BASEDIR}/${APP}"
fi

${APP} 0x0602 ${BASEDIR}/input/deencap_frag.pcap || ${APP} verbose 0x0602 ${BASEDIR}/input/deencap_frag.pcap

