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
 
# parse arguments                       
SCRIPT="$0" 
VERBOSE="$1"
VERY_VERBOSE="$2"
if [ "x$MAKELEVEL" != "x" ] ; then      
	BASEDIR="${srcdir}"                 
	APP="./test_header_access"
else
	BASEDIR=$( dirname "${SCRIPT}" )    
	APP="${BASEDIR}/test_header_access"
fi
SOURCE=${BASEDIR}/input/header_access.pcap

# run in verbose mode or quiet mode     
if [ "${VERBOSE}" = "verbose" ] ; then  
	if [ "${VERY_VERBOSE}" = "verbose" ] ; then
		${APP} verbose ${SOURCE} || exit $?
	else
		${APP} ${SOURCE} || exit $?
	fi
else                                    
	${APP} ${SOURCE} > /dev/null 2>&1 || exit $?
fi
