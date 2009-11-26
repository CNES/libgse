#!/bin/sh

./test_deencap_fault 0x0801 ./input/deencap_padding.pcap || ./test_deencap_fault verbose 0x0801 ./input/deencap_padding.pcap

