#!/bin/sh

./test_deencap ./output/deencap_incomplete_pdu.pcap ./input/deencap_incomplete_pdu.pcap || ./test_deencap verbose ./output/deencap_incomplete_pdu.pcap ./input/deencap_incomplete_pdu.pcap

