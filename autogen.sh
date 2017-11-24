#!/bin/sh
# Script to generate all required files for `configure' when
# starting from a fresh repository checkout.

run()
{
  echo -n "Running $1... "
  $@ >/dev/null 2>&1
  if [ $? -eq 0 ] ; then
    echo "done"
  else
    echo "failed"
    echo "Running $1 again with errors unmasked:"
    $@
    exit 1
  fi
}

rm -f config.cache
rm -f config.log

OLD_PWD="$PWD"
NEW_PWD="`dirname $0`"
cd "${NEW_PWD}" >/dev/null

run aclocal
run libtoolize --force
run autoconf
run autoheader
run automake --add-missing

cd "${OLD_PWD}" >/dev/null

chmod +x ${NEW_PWD}/configure
${NEW_PWD}/configure --enable-fail-on-warning $@

