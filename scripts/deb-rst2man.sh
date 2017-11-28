#!/bin/sh

#
# Copyright 2015,2017 Cumulus Networks, Inc. All rights reserved.
#
# This file is licensed to You under the Eclipse Public License (EPL);
# You may not use this file except in compliance with the License. You
# may obtain a copy of the License at
# http://www.opensource.org/licenses/eclipse-1.0.php
#

# Creates nroff manpages from rst files in the rst dir in the source directory
# Add this script into the makefile for the build rule, before build_fnc

# Make sure to put manpages into rst and have the debian .manpages file
# look for manpages in /souredir/man/*

PKG_DIR="$1"

[ -d "$PKG_DIR/rst" ] || {
    echo "$0 Usage: $0 <package dir>"
    exit 1
}

man_dir="man"
mkdir "$1/$man_dir"

echo -n "Generating man pages "
#Loop over .rst files in package/rst
for p in $(ls $1/rst/*.rst) ; do
    dst_file=$PKG_DIR/${man_dir}/`basename "$p" .rst`
    rst2man --halt=2 "$p" > $dst_file || {
	echo
	echo "Error: problems genertaing man page: $p"
	exit 1
    }
    echo -n "."
done

echo " done."
exit 0
