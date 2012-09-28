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

gse_bad_tl_args="0x0701 ${BASEDIR}/input/deencap_bad_total_length.pcap"
gse_bad_order_length_args="0x0701 ${BASEDIR}/input/deencap_bad_order_length_err.pcap"
gse_bad_order_crc_args="0x0702 ${BASEDIR}/input/deencap_bad_order_crc_err.pcap"
gse_bad_pt_args="0x0504 ${BASEDIR}/input/deencap_bad_protocol.pcap"
gse_invalid_label_args="0x0505 ${BASEDIR}/input/deencap_invalid_label.pcap"
gse_no_context_args="0x0601 ${BASEDIR}/input/deencap_context_not_init.pcap"
gse_wrong_lt_args="0x0501 ${BASEDIR}/input/deencap_wrong_lt.pcap"
gse_too_much_data_args="0x0603 ${BASEDIR}/input/deencap_too_much_data.pcap"
gse_too_small_args="0x0604 ${BASEDIR}/input/deencap_too_small.pcap"
gse_bad_frag_id_args="0x0503 ${BASEDIR}/input/deencap_bad_frag_id.pcap"

for args in "${gse_bad_tl_args}" \
            "${gse_bad_order_length_args}" \
            "${gse_bad_order_crc_args}" \
            "${gse_bad_pt_args}" \
            "${gse_invalid_label_args}" \
            "${gse_no_context_args}" \
            "${gse_wrong_lt_args}" \
            "${gse_too_much_data_args}" \
            "${gse_too_small_args}" \
            "${gse_bad_frag_id_args}"; do
  ${APP} ${args} || ${APP} verbose ${args}
  if [ "$?" -ne "0" ]; then
    exit 1
  fi
done

