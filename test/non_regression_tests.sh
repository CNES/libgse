#!/bin/sh

APP="non_regression_tests"

SCRIPT="$0"
if [ "x$MAKELEVEL" != "x" ] ; then
	BASEDIR="${srcdir}"
else
	BASEDIR=$( dirname "${SCRIPT}" )
fi
BASEDIR_APP=$( dirname "${SCRIPT}" )

# Try to determinate the path of the executable
if [ ! -x "${BASEDIR_APP}/${APP}" ] ; then
	if [ x"${builddir}" != "x" ] ; then
		APP="${builddir}/test/${APP}"
	else
		APP="${srcdir}/${APP}"
	fi
else
	APP="${BASEDIR_APP}/${APP}"
fi

ARGS=" -r ${BASEDIR}/refragmented.pcap ${BASEDIR}/fragmented.pcap ${BASEDIR}/source.pcap"

${APP} ${ARGS} || ${APP} verbose -lvl 2 ${ARGS}
