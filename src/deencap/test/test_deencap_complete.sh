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


${APP} ${BASEDIR}/output/deencap_complete.pcap ${BASEDIR}/input/deencap_complete.pcap || ${APP} verbose ${BASEDIR}/output/deencap_complete.pcap ${BASEDIR}/input/deencap_complete.pcap
if [ "$?" -ne "0" ]; then
  exit 1
fi
${APP} ${BASEDIR}/output/deencap_mult_complete.pcap ${BASEDIR}/input/deencap_mult_complete.pcap || ${APP} verbose ${BASEDIR}/output/deencap_mult_complete.pcap ${BASEDIR}/input/deencap_mult_complete.pcap

