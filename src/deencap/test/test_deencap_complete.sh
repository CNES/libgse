#!/bin/sh

./test_deencap ./output/deencap_complete.pcap ./input/deencap_complete.pcap || ./test_deencap verbose ./output/deencap_complete.pcap ./input/deencap_complete.pcap
if [ "$?" -ne "0" ]; then
  exit 1
fi
./test_deencap ./output/deencap_mult_complete.pcap ./input/deencap_mult_complete.pcap || ./test_deencap verbose ./output/deencap_mult_complete.pcap ./input/deencap_mult_complete.pcap

