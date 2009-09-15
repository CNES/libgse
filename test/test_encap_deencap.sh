#!/bin/sh

./test_encap_deencap 0 ./encap_deencap_max_pdu_length.pcap || ./test_encap_deencap verbose 0 ./encap_deencap_max_pdu_length.pcap
