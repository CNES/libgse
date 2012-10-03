#!/bin/sh

APP="test_add_ext"

# parse arguments
SCRIPT="$0"
if [ "x$MAKELEVEL" != "x" ] ; then
    BASEDIR="${srcdir}"
    APP="./${APP}"
else
    BASEDIR=$( dirname "${SCRIPT}" )
    APP="${BASEDIR}/${APP}"
fi


# complete
gse_args_complete_ext1="-l 0 -c ${BASEDIR}/output/add_ext_complete_ext1.pcap -i ${BASEDIR}/output/encap_complete.pcap --ext 1"
gse_args_complete_ext2="-l 0 -c ${BASEDIR}/output/add_ext_complete_ext2.pcap -i ${BASEDIR}/output/encap_complete.pcap --ext 2"


# frag
gse_args_frag_ext1="-l 39 -c ${BASEDIR}/output/add_ext_frag_ext1.pcap -i ${BASEDIR}/output/encap_frag.pcap --ext 1"
gse_args_frag_ext2="-l 39 -c ${BASEDIR}/output/add_ext_frag_ext2.pcap -i ${BASEDIR}/output/encap_frag.pcap --ext 2"


for args in "${gse_args_complete_ext1}" \
            "${gse_args_complete_ext2}" \
            "${gse_args_frag_ext1}" \
            "${gse_args_frag_ext2}"; do
  ${APP} ${args} || ${APP} --verbose ${args}
  if [ "$?" -ne "0" ]; then
    exit 1
  fi
done


