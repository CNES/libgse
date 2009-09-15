#!/bin/sh

./test_encap 0 ./output/encap_complete.pcap ./input/encap_complete.pcap || ./test_encap verbose 0 ./output/encap_complete.pcap ./input/encap_complete.pcap
if [ "$?" -ne "0" ]; then
  exit 1
fi
./test_encap 0 ./output/encap_mult_complete.pcap ./input/encap_mult_complete.pcap || ./test_encap verbose 0 ./output/encap_mult_complete.pcap ./input/encap_mult_complete.pcap

