#!/bin/sh

#
# Copyright 2016,2017 Cumulus Networks, Inc. All rights reserved.
#
# This file is licensed to You under the Eclipse Public License (EPL);
# You may not use this file except in compliance with the License. You
# may obtain a copy of the License at
# http://www.opensource.org/licenses/eclipse-1.0.php

LIBDIR="/usr/lib"
LLDPLIB="liblldpctl.so"
CGRAPHLIB="libcgraph.so"
CDTLIB="libcdt.so"

echo "making symbolic links"
if [ ! -f $LIBDIR/$LLDPLIB ]
then
    echo $LIBDIR/$LLDPLIB.4.3.0 $LIBDIR/$LLDPLIB
    curr=$PWD
    cd $LIBDIR
    sudo ln -sf $LLDPLIB.4.3.0 $LLDPLIB
    cd $curr
fi
if [ ! -f $LIBDIR/$CGRAPHLIB ]
then
    echo $LIBDIR/$CGRAPHLIB.6.0.0 $LIBDIR/$CGRAPHLIB
    curr=$PWD
    cd $LIBDIR
    sudo ln -sf $CGRAPHLIB.6.0.0 $CGRAPHLIB
    cd $curr
fi
if [ ! -f $LIBDIR/$CDTLIB ]
then
    echo $LIBDIR/$CDTLIB.5.0.0 $LIBDIR/$CDTLIB
    curr=$PWD
    cd $LIBDIR
    sudo ln -sf $CDTLIB.5.0.0 $CDTLIB
    cd $curr
fi

echo " done."
exit 0
