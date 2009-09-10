#!/bin/sh

./test_deencap ./output/deencap_frag.pcap ./input/deencap_frag.pcap || ./test_deencap verbose ./output/deencap_frag.pcap ./input/deencap_frag.pcap
if [ "$?" -ne "0" ]; then
  exit 1
fi
./test_deencap ./output/deencap_mult_frag.pcap ./input/deencap_mult_frag.pcap || ./test_deencap verbose ./output/deencap_mult_frag.pcap ./input/deencap_mult_frag.pcap

