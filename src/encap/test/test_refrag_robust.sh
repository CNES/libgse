#!/bin/sh

./test_refrag_robust 0x402 1 ./input/refrag_one.pcap || ./test_refrag_robust verbose 0x402 1 ./input/refrag_one.pcap
if [ "$?" -ne "0" ]; then
  exit 1
fi
./test_refrag_robust 0x404 39 ./input/refrag_min.pcap || ./test_refrag_robust verbose 0x404 39 ./input/refrag_min.pcap
if [ "$?" -ne "0" ]; then
  exit 1
fi
./test_refrag_robust 0x404 50 ./input/refrag_min.pcap || ./test_refrag_robust verbose 0x404 50 ./input/refrag_min.pcap
if [ "$?" -ne "0" ]; then
  exit 1
fi
./test_refrag_robust 0x402 12 ./input/refrag_one.pcap || ./test_refrag_robust verbose 0x402 12 ./input/refrag_one.pcap
