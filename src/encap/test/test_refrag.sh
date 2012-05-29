#!/bin/sh

APP="test_refrag"

# parse arguments
SCRIPT="$0"
if [ "x$MAKELEVEL" != "x" ] ; then
	BASEDIR="${srcdir}"
	APP="./${APP}"
else
	BASEDIR=$( dirname "${SCRIPT}" )
	APP="${BASEDIR}/${APP}"
fi

${APP} 39 ${BASEDIR}/output/refrag.pcap ${BASEDIR}/input/refrag.pcap || ${APP} verbose 39 ${BASEDIR}/output/refrag.pcap ${BASEDIR}/input/refrag.pcap
if [ "$?" -ne "0" ]; then
  exit 1
fi
${APP} 14 ${BASEDIR}/output/refrag_min.pcap ${BASEDIR}/input/refrag_min.pcap || ${APP} verbose 14 ${BASEDIR}/output/refrag_min.pcap ${BASEDIR}/input/refrag_min.pcap

