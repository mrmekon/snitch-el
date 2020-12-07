#!/bin/bash
set -eux

VERSION=$(cat snitch.el |grep ";; Version:" | sed 's/.*: //')
PKG="snitch-$VERSION"

sh test_snitch.sh
if [[ $? -ne 0 ]]; then
    echo "Automated tests failed, not releasing."
    exit 1
fi
mkdir "$PKG"
sh gen_readme.sh
cp snitch*.el "$PKG"
rm "$PKG/snitch-test.el"
cp README.md "$PKG"
tar -cf "$PKG.tar" "$PKG"

if [[ "x$PKG" != "x" ]]; then
    rm -rf "$PKG"
fi
echo "Released $PKG"
