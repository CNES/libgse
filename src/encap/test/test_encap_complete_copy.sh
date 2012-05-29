#!/bin/sh

APP="test_encap_copy"

# parse arguments
SCRIPT="$0"
if [ "x$MAKELEVEL" != "x" ] ; then
	BASEDIR="${srcdir}"
	APP="./${APP}"
else
	BASEDIR=$( dirname "${SCRIPT}" )
	APP="${BASEDIR}/${APP}"
fi

${APP} 0 ${BASEDIR}/output/encap_complete.pcap ${BASEDIR}/input/encap_complete.pcap || ${APP} verbose 0 ${BASEDIR}/output/encap_complete.pcap ${BASEDIR}/input/encap_complete.pcap
if [ "$?" -ne "0" ]; then
  exit 1
fi
${APP} 0 ${BASEDIR}/output/encap_mult_complete.pcap ${BASEDIR}/input/encap_mult_complete.pcap || ${APP} verbose 0 ${BASEDIR}/output/encap_mult_complete.pcap ${BASEDIR}/input/encap_mult_complete.pcap

