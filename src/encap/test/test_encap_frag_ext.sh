#!/bin/sh

APP="test_encap"

# parse arguments
SCRIPT="$0"
if [ "x$MAKELEVEL" != "x" ] ; then
    BASEDIR="${srcdir}"
    APP="./${APP}"
else
    BASEDIR=$( dirname "${SCRIPT}" )
    APP="${BASEDIR}/${APP}"
fi


gse_args_ext1="-l 39 -c ${BASEDIR}/output/encap_frag_ext1.pcap -i ${BASEDIR}/input/encap_frag.pcap --ext 1"
gse_args_ext2="-l 39 -c ${BASEDIR}/output/encap_frag_ext2.pcap -i ${BASEDIR}/input/encap_frag.pcap --ext 2"


for args in "${gse_args_ext1}" \
            "${gse_args_ext2}"; do
  ${APP} ${args} || ${APP} --verbose ${args}
  if [ "$?" -ne "0" ]; then
    exit 1
  fi
done


