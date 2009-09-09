#!/bin/sh

./test_encap 0 ./output/encap_frag_dflt_length.pcap ./input/encap_frag_dflt_length.pcap || ./test_encap verbose 0 ./output/encap_frag_dflt_length.pcap ./input/encap_frag_dflt_length.pcap
if [ "$?" -ne "0" ]; then
  exit 1
fi
./test_encap 0 ./output/encap_mult_frag_dflt_length.pcap ./input/encap_mult_frag_dflt_length.pcap || ./test_encap verbose 0 ./output/encap_mult_frag_dflt_length.pcap ./input/encap_mult_frag_dflt_length.pcap

