#!/bin/sh

./test_fifo 1 ./output/encap_mult_frag.pcap ./input/encap_mult_frag.pcap || ./test_fifo 1 verbose ./output/encap_mult_frag.pcap ./input/encap_mult_frag.pcap

