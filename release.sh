#!/bin/bash
set -eux

VERSION=$(cat snitch.el |grep ";; Version:" | sed 's/.*: //')
PKG="snitch-$VERSION"

sh test_snitch.sh
if [[ $? -ne 0 ]]; then
    echo "Automated tests failed, not releasing."
    exit 1
fi
rm *.elc
mkdir -p "$PKG"
sh gen_readme.sh
sh gen_pkgel.sh
cp snitch*.el "$PKG"
rm "$PKG/snitch-test.el"
cp README "$PKG"
tar -cf "$PKG.tar" "$PKG"
tar -tf "$PKG.tar"
rm snitch-pkg.el

if [[ "x$PKG" != "x" ]]; then
    rm -rf "$PKG"
fi
echo "Released $PKG"
