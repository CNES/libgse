#!/bin/sh


APP="test_deencap"

# parse arguments
SCRIPT="$0"
if [ "x$MAKELEVEL" != "x" ] ; then
    BASEDIR="${srcdir}"
    APP="./${APP}"
else
    BASEDIR=$( dirname "${SCRIPT}" )
    APP="${BASEDIR}/${APP}"
fi

gse_args_ext1="${BASEDIR}/output/deencap_complete.pcap ${BASEDIR}/input/deencap_complete_ext1.pcap"
gse_args_ext2="${BASEDIR}/output/deencap_complete.pcap ${BASEDIR}/input/deencap_complete_ext2.pcap"


for args in "${gse_args_ext1}" \
            "${gse_args_ext2}"; do
  ${APP} ${args} || ${APP} verbose ${args}
  if [ "$?" -ne "0" ]; then
    exit 1
  fi
done

