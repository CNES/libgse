#!/bin/sh

./test_encap_robust 0x0402 2 ./input/encap_frag.pcap || ./test_encap_robust verbose 0x0402 2 ./input/encap_frag.pcap
if [ "$?" -ne "0" ]; then
  exit 1
fi
./test_encap_robust 0x0403 4098 ./input/encap_frag.pcap || ./test_encap_robust verbose 0x0403 4098 ./input/encap_frag.pcap
if [ "$?" -ne "0" ]; then
  exit 1
fi
./test_encap_robust 0x0301 0 ./input/encap_fifo_full.pcap || ./test_encap_robust verbose 0x0301 0 ./input/encap_fifo_full.pcap
if [ "$?" -ne "0" ]; then
  exit 1
fi
./test_encap_robust 0x0401 0 ./input/encap_pdu_too_long.pcap || ./test_encap_robust verbose 0x0401 0 ./input/encap_pdu_too_long.pcap
if [ "$?" -ne "0" ]; then
  exit 1
fi
./test_encap_bad_zero_copy 0x0201 60 ./input/encap_complete.pcap || ./test_encap_bad_zero_copy verbose 0x0201 60 ./input/encap_complete.pcap

