#!/bin/sh

./test_deencap_fault 0x0701 ./input/deencap_bad_total_length.pcap || ./test_deencap_fault verbose 0x0701 ./input/deencap_bad_total_length.pcap
if [ "$?" -ne "0" ]; then
  exit 1
fi
./test_deencap_fault 0x0701 ./input/deencap_bad_order_length_err.pcap || ./test_deencap_fault verbose 0x0701 ./input/deencap_bad_order_length_err.pcap
if [ "$?" -ne "0" ]; then
  exit 1
fi
./test_deencap_fault 0x0702 ./input/deencap_bad_order_crc_err.pcap || ./test_deencap_fault verbose 0x0701 ./input/deencap_bad_order_crc_err.pcap
if [ "$?" -ne "0" ]; then
  exit 1
fi
./test_deencap_fault 0x0504 ./input/deencap_bad_protocol.pcap || ./test_deencap_fault verbose 0x0504 ./input/deencap_bad_protocol.pcap
if [ "$?" -ne "0" ]; then
  exit 1
fi
./test_deencap_fault 0x0502 ./input/deencap_bad_gse_length.pcap || ./test_deencap_fault verbose 0x0502 ./input/deencap_bad_gse_length.pcap
if [ "$?" -ne "0" ]; then
  exit 1
fi
./test_deencap_timeout 0x0602 ./input/deencap_frag.pcap || ./test_deencap_timeout verbose 0x0602 ./input/deencap_frag.pcap
if [ "$?" -ne "0" ]; then
  exit 1
fi
./test_deencap_fault 0x0505 ./input/deencap_invalid_label.pcap || ./test_deencap_fault verbose 0x0505 ./input/deencap_invalid_label.pcap
if [ "$?" -ne "0" ]; then
  exit 1
fi
./test_deencap_fault 0x0601 ./input/deencap_context_not_init.pcap || ./test_deencap_fault verbose 0x0601 ./input/deencap_context_not_init.pcap
if [ "$?" -ne "0" ]; then
  exit 1
fi
./test_deencap_fault 0x0501 ./input/deencap_lt_not_supported_frag.pcap || ./test_deencap_fault verbose 0x0501 ./input/deencap_lt_not_supported_frag.pcap
if [ "$?" -ne "0" ]; then
  exit 1
fi
./test_deencap_fault 0x0501 ./input/deencap_lt_not_supported_complete.pcap || ./test_deencap_fault verbose 0x0501 ./input/deencap_lt_not_supported_complete.pcap
if [ "$?" -ne "0" ]; then
  exit 1
fi
./test_deencap_fault 0x0501 ./input/deencap_wrong_lt.pcap || ./test_deencap_fault verbose 0x0501 ./input/deencap_wrong_lt.pcap
if [ "$?" -ne "0" ]; then
  exit 1
fi
./test_deencap_fault 0x0605 ./input/deencap_too_much_data.pcap || ./test_deencap_fault verbose 0x0605 ./input/deencap_too_much_data.pcap
if [ "$?" -ne "0" ]; then
  exit 1
fi
./test_deencap_fault 0x0402 ./input/deencap_too_small.pcap || ./test_deencap_fault verbose 0x0402 ./input/deencap_too_small.pcap
if [ "$?" -ne "0" ]; then
  exit 1
fi
./test_deencap_fault 0x0403 ./input/deencap_too_long.pcap || ./test_deencap_fault verbose 0x0403 ./input/deencap_too_long.pcap

