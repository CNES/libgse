#!/bin/sh

./test_refrag 39 ./output/refrag.pcap ./input/refrag.pcap || ./test_refrag verbose 39 ./output/refrag.pcap ./input/refrag.pcap
if [ "$?" -ne "0" ]; then
  exit 1
fi
./test_refrag 14 ./output/refrag_min.pcap ./input/refrag_min.pcap || ./test_refrag verbose 14 ./output/refrag_min.pcap ./input/refrag_min.pcap

