#!/bin/sh

APP="test_deencap_fault"

# parse arguments
SCRIPT="$0"
if [ "x$MAKELEVEL" != "x" ] ; then
	BASEDIR="${srcdir}"
	APP="./${APP}"
else
	BASEDIR=$( dirname "${SCRIPT}" )
	APP="${BASEDIR}/${APP}"
fi

${APP} 0x0701 ${BASEDIR}/input/deencap_bad_total_length.pcap || ${APP} verbose 0x0701 ${BASEDIR}/input/deencap_bad_total_length.pcap
if [ "$?" -ne "0" ]; then
  exit 1
fi
${APP} 0x0701 ${BASEDIR}/input/deencap_bad_order_length_err.pcap || ${APP} verbose 0x0701 ${BASEDIR}/input/deencap_bad_order_length_err.pcap
if [ "$?" -ne "0" ]; then
  exit 1
fi
${APP} 0x0702 ${BASEDIR}/input/deencap_bad_order_crc_err.pcap || ${APP} verbose 0x0701 ${BASEDIR}/input/deencap_bad_order_crc_err.pcap
if [ "$?" -ne "0" ]; then
  exit 1
fi
${APP} 0x0504 ${BASEDIR}/input/deencap_bad_protocol.pcap || ${APP} verbose 0x0504 ${BASEDIR}/input/deencap_bad_protocol.pcap
if [ "$?" -ne "0" ]; then
  exit 1
fi
${APP} 0x0505 ${BASEDIR}/input/deencap_invalid_label.pcap || ${APP} verbose 0x0505 ${BASEDIR}/input/deencap_invalid_label.pcap
if [ "$?" -ne "0" ]; then
  exit 1
fi
${APP} 0x0601 ${BASEDIR}/input/deencap_context_not_init.pcap || ${APP} verbose 0x0601 ${BASEDIR}/input/deencap_context_not_init.pcap
if [ "$?" -ne "0" ]; then
  exit 1
fi
${APP} 0x0501 ${BASEDIR}/input/deencap_lt_not_supported_frag.pcap || ${APP} verbose 0x0501 ${BASEDIR}/input/deencap_lt_not_supported_frag.pcap
if [ "$?" -ne "0" ]; then
  exit 1
fi
${APP} 0x0501 ${BASEDIR}/input/deencap_lt_not_supported_complete.pcap || ${APP} verbose 0x0501 ${BASEDIR}/input/deencap_lt_not_supported_complete.pcap
if [ "$?" -ne "0" ]; then
  exit 1
fi
${APP} 0x0501 ${BASEDIR}/input/deencap_wrong_lt.pcap || ${APP} verbose 0x0501 ${BASEDIR}/input/deencap_wrong_lt.pcap
if [ "$?" -ne "0" ]; then
  exit 1
fi
${APP} 0x0603 ${BASEDIR}/input/deencap_too_much_data.pcap || ${APP} verbose 0x0603 ${BASEDIR}/input/deencap_too_much_data.pcap
if [ "$?" -ne "0" ]; then
  exit 1
fi
${APP} 0x0604 ${BASEDIR}/input/deencap_too_small.pcap || ${APP} verbose 0x0604 ${BASEDIR}/input/deencap_too_small.pcap
if [ "$?" -ne "0" ]; then
  exit 1
fi
${APP} 0x0503 ${BASEDIR}/input/deencap_bad_frag_id.pcap || ${APP} verbose 0x0503 ${BASEDIR}/input/deencap_bad_frag_id.pcap

