#!/bin/sh

APP="test_deencap_interleaving"

# parse arguments
SCRIPT="$0"
if [ "x$MAKELEVEL" != "x" ] ; then
	BASEDIR="${srcdir}"
	APP="./${APP}"
else
	BASEDIR=$( dirname "${SCRIPT}" )
	APP="${BASEDIR}/${APP}"
fi


${APP} ${BASEDIR}/output/deencap_interleaving.pcap ${BASEDIR}/input/deencap_interleaving.pcap || ${APP} verbose ${BASEDIR}/output/deencap_interleaving.pcap ${BASEDIR}/input/deencap_interleaving.pcap

