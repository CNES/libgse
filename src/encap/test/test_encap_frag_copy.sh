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

${APP} 39 ${BASEDIR}/output/encap_frag.pcap ${BASEDIR}/input/encap_frag.pcap || ${APP} verbose 39 ${BASEDIR}/output/encap_frag.pcap ${BASEDIR}/input/encap_frag.pcap
if [ "$?" -ne "0" ]; then
  exit 1
fi
${APP} 39 ${BASEDIR}/output/encap_mult_frag.pcap ${BASEDIR}/input/encap_mult_frag.pcap || ${APP} verbose 39 ${BASEDIR}/output/encap_mult_frag.pcap ${BASEDIR}/input/encap_mult_frag.pcap

