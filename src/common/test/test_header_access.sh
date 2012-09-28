#!/bin/sh

# file:        test_header_access.sh
# description: Check the header access API.
# author:      Didier Barvaux <didier.barvaux@toulouse.viveris.com>
# author:      Julien Bernard <julien.bernard@toulouse.viveris.com>
#
# Script arguments:
#    test_header_access.sh [verbose]
# where:
#   verbose          prints the traces of test application
#

APP="test_header_access"

# parse arguments
SCRIPT="$0"
if [ "x$MAKELEVEL" != "x" ] ; then
    BASEDIR="${srcdir}"
    APP="./${APP}"
else
    BASEDIR=$( dirname "${SCRIPT}" )
    APP="${BASEDIR}/${APP}"
fi

SOURCE=${BASEDIR}/input/header_access.pcap

${APP} ${SOURCE} || ${APP} verbose ${SOURCE}

