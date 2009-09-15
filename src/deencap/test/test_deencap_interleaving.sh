#!/bin/sh

./test_deencap ./output/deencap_interleaving.pcap ./input/deencap_interleaving.pcap || ./test_deencap verbose ./output/deencap_interleaving.pcap ./input/deencap_interleaving.pcap

