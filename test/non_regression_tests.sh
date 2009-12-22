#!/bin/sh
args=" -r $PWD/refragmented.pcap $PWD/fragmented.pcap $PWD/source.pcap"

$(dirname $0)/non_regression_tests verbose -lvl 0 $args || $(dirname $0)/non_regression_tests verbose -lvl 2 $args
