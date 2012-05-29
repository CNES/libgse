#!/bin/sh

APP="test_encap_length_min"

# parse arguments
SCRIPT="$0"
if [ "x$MAKELEVEL" != "x" ] ; then
	BASEDIR="${srcdir}"
	APP="./${APP}"
else
	BASEDIR=$( dirname "${SCRIPT}" )
	APP="${BASEDIR}/${APP}"
fi

${APP} ${BASEDIR}/output/encap_frag_min.pcap ${BASEDIR}/input/encap_frag_min.pcap || ${APP} verbose ${BASEDIR}/output/encap_frag_min.pcap ${BASEDIR}/input/encap_frag_min.pcap

