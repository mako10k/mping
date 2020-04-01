#!/bin/bash

set -e
cd "$(dirname "$0")"
autoreconf -iv
./configure
make dist
tarball="$(ls mping-*.tar.gz|sort -V|tail -n1)"
test -n "$tarball"
workdir="$(basename "$tarball" .tar.gz)"
tar xvzf "$tarball"
cp -r debian "$workdir/debian"
cd "$workdir"
debmake
debuild -uc -us

