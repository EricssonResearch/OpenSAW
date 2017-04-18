<!---
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
--->
Building Bap and Pintool
====
Building iltrans and the corresponding pintool is not required for most users
as it is done automatically by the vagrant provisioning script.

Only users that want to modify iltrans or the pintool would need to do this.

The build of both iltrans and the pintool in the OpenSAW virtual machine is 
done by running ```sudo /opt/OpenSAW/tools/bin/build.sh```. This to builds 
iltrans and the pintool. The script also installs the tools that were 
compiled so that they are used the next run of OpenSAW.


