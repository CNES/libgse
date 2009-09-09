#!/bin/sh

./test_fifo 3 ./output/encap_mult_fifo.pcap ./input/encap_mult_fifo.pcap || ./test_fifo 3 verbose ./output/encap_mult_fifo.pcap ./input/encap_mult_fifo.pcap

