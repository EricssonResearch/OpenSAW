#!/bin/bash
:'
    Open Security Analysis Workbench (OpenSAW) - A concolic security test tool
    Copyright (C) 2016 Ericsson AB

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; version 2 of the License.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
'

#This script assumes:
# These are solved by Vagrant provisioning
#That OpenSAW is located under /opt/OpenSAW
#That pin has been extracted to /opt/pin-2.11-49306-gcc.3.4.6-ia32_intel64-linux
# These are solved by running get_bap.sh
#That bap has been extracted to /opt/bap-0.7/
#That bap-0.7/pintraces/gentrace.cpp has been replaced with /opt/OpenSAW/tools/pintool/gentrace.cpp
#That bap-0.7/pintraces/Makefile has been patched with /opt/OpenSAW/tools/pintool/makefile.patch

#Remove pre-compiled files so we don't think we have built them
rm /opt/OpenSAW-tools/iltrans
rm /opt/OpenSAW-tools/gentrace.so
#Abort script on error
set -e

cd /opt/bap-0.7
./configure
make


if [ ! -f /opt/OpenSAW-tools/ ]; then
    mkdir -p /opt/OpenSAW-tools/
fi
cp /opt/bap-0.7/utils/iltrans /opt/OpenSAW-tools/
cp /opt/bap-0.7/pintraces/obj-ia32/gentrace.so /opt/OpenSAW-tools/