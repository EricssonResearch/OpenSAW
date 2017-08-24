#!/bin/bash

#   Open Security Analysis Workbench (OpenSAW) - A concolic security test tool
#   Copyright (C) 2016 Ericsson AB
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; version 2 of the License.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License along
#   with this program; if not, write to the Free Software Foundation, Inc.,
#   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

set -e
echo "Extracting BAP"
tar xzf /opt/OpenSAW/tools/bap-0.7.tar.gz -C /opt
chown -R vagrant /opt/bap-0.7
# We have to link pin in for bap to build pintraces.
ln -s /opt/pin /opt/bap-0.7/

rm /opt/bap-0.7/pintraces/gentrace.cpp
rm /opt/bap-0.7/pintraces/Makefile
ln -s /opt/OpenSAW/dev/pintool/gentrace.cpp /opt/bap-0.7/pintraces/gentrace.cpp
ln -s /opt/OpenSAW/dev/pintool/makefile.rules /opt/bap-0.7/pintraces/makefile.rules
ln -s /opt/OpenSAW/dev/pintool/makefile /opt/bap-0.7/pintraces/makefile

add-apt-repository -y ppa:simple-theorem-prover
apt-get -q update
apt-get -q install -y zlib1g-dev build-essential ocaml libgmp-dev autoconf libpcre3-dev libcamomile-ocaml-dev camlidl ocaml-findlib camlp4-extra binutils-dev
