#!/bin/sh

$(dirname $0)/non_regression_tests verbose -lvl 0 -r $PWD/refragmented.pcap $PWD/fragmented.pcap $PWD/source.pcap  || $(dirname $0)/non_regression_tests verbose -lvl 2 -r $PWD/refragmented.pcap $PWD/fragmented.pcap  $PWD/source.pcap
