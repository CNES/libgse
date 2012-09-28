#!/bin/bash

APP="non_regression_tests"

SCRIPT="$0"
if [ "x$MAKELEVEL" != "x" ] ; then
    BASEDIR="${srcdir}"
else
    BASEDIR=$( dirname "${SCRIPT}" )
fi
BASEDIR_APP=$( dirname "${SCRIPT}" )

# Try to determinate the path of the executable
if [ ! -x "${BASEDIR_APP}/${APP}" ] ; then
    if [ x"${builddir}" != "x" ] ; then
        APP="${builddir}/test/${APP}"
    else
        APP="${srcdir}/${APP}"
    fi
else
    APP="${BASEDIR_APP}/${APP}"
fi

gse_args=" -r ${BASEDIR}/refragmented.pcap -c ${BASEDIR}/fragmented.pcap -i ${BASEDIR}/source.pcap"
gse_args_label3=" -r ${BASEDIR}/refragmented_label_3.pcap -c ${BASEDIR}/fragmented_label_3.pcap -i ${BASEDIR}/source.pcap --label-type 1"
gse_args_label0=" -r ${BASEDIR}/refragmented_label_0.pcap -c ${BASEDIR}/fragmented_label_0.pcap -i ${BASEDIR}/source.pcap --label-type 2"


ARGS=( \
  "${gse_args}" \
  "${gse_args_label0}" \
  "${gse_args_label3}" \
  )

DESCRIPTION=( \
  "GSE test: " \
  "GSE test with LT='01': " \
  "GSE test with LT='11': " \
  )

GREEN="\\033[1;32m"
NORMAL="\\033[0;39m"
RED="\\033[1;31m"
BLUE="\\033[1;34m"
BLUE_U="\\033[4;34m"

/bin/echo -e ""
/bin/echo -e "${BLUE}${BLUE_U}Run tests in `pwd`${NORMAL}\n"

for index in "${!ARGS[@]}"; do
  /bin/echo -e -n "${BLUE}${DESCRIPTION[$index]}${NORMAL}"
  ${APP} ${ARGS[$index]} || (/bin/echo -e "${RED} FAIL${NORMAL}" && ${APP} --verbose 2 ${ARGS[$index]})
  if [ "$?" -ne "0" ]; then
    exit 1
  fi
  /bin/echo -e "${GREEN} SUCCESS${NORMAL}"
done

