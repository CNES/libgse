#!/bin/sh

APP="test_fifo"

# parse arguments
SCRIPT="$0"
if [ "x$MAKELEVEL" != "x" ] ; then
	BASEDIR="${srcdir}"
	APP="./${APP}"
else
	BASEDIR=$( dirname "${SCRIPT}" )
	APP="${BASEDIR}/${APP}"
fi

${APP} 1 ${BASEDIR}/output/encap_mult_frag.pcap ${BASEDIR}/input/encap_mult_frag.pcap || ${APP} verbose 1 ${BASEDIR}/output/encap_mult_frag.pcap ${BASEDIR}/input/encap_mult_frag.pcap

