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

${APP} 3 ${BASEDIR}/output/encap_mult_fifo.pcap ${BASEDIR}/input/encap_mult_fifo.pcap || ${APP} verbose 3 ${BASEDIR}/output/encap_mult_fifo.pcap ${BASEDIR}/input/encap_mult_fifo.pcap

