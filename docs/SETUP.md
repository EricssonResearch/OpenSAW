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
Running OpenSAW
===============
The preferred way of running OpenSAW is to use Vagrant to setup a virtual machine.
Another option is to run a provided virtual machine image directly. Both methods are described in this document.
When you are connected to the machine, read [```docs/Using OpenSAW.md```](Using OpenSAW.md)
## Vagrant
The setup has been tested on Windows 7 with VirtualBox 5.0.24 and Vagrant 1.8.5 but should also work on GNU/Linux and OS X.


To use vagrant version of OpenSAW you need to install Vagrant
and Virtualbox on your host machine. Choose the variant of
vagrant and virtualbox that matches your host machines OS.

Vagrant can be found here: https://www.vagrantup.com/downloads.html  
VirtualBox can be found here: https://www.virtualbox.org/wiki/Downloads

After both of these are installed, place the OpenSAW.tar.bz2
in an empty folder.

In this folder run
```sh
tar xjvf OpenSAW.tar.bz2
cp OpenSAW/tools/vagrant/Vagrantfile .
```

Your structure should look like
```sh
$ ls
OpenSAW/  Vagrantfile
```

To download an Ubuntu virtual machine, download PIN, compile the iltrans and pintool
and configure OpenSAW simply run the command.
```sh
vagrant up
```
This prepares and launches the virtual machine,
the first time this command can take around 15 minutes.
**_One word of warning; if you have less than 768MB ram free, virtualbox may pause
the machine without notification. Check the VirtualBox UI if nothing is happening._**

When vagrant up has finished, a new virtual machine has been prepared for you. 
Connect to the virtual machine by running  
```sh
vagrant ssh
```
If you do not have a ssh client installed vagrant will
give you suggestions on how to proceed. If you have issues with the
key file, use the username "vagrant" and password "vagrant"

Note that the folder containing `Vagrantfile` will be mounted read/write on the virtual machine at
`/vagrant/`

To suspend the machine run
```sh
vagrant suspend
```
To halt the machine run
```sh
vagrant halt
```
And to remove the machine completely and all the files on it run
```sh
vagrant destroy
```

After this initial setup you might want to modify the lines
```
    v.memory = 768
    v.cpus = 1
```
in the `Vagrantfile` to match your system. The changes take effect after running `vagrant reload` or `vagrant halt; vagrant up`

For more information on how to use vagrant see [https://www.vagrantup.com/docs/cli/](https://www.vagrantup.com/docs/cli/)

#### Vagrant F.A.Q.
#####  Do I need to run Vagrant in a Linux environment?  ##### 
No - Install Vagrant directly on your host machine alongside Virtualbox

##### How do I open cmd/a terminal on windows? #####
Open file explorer and, while holding shift, right click on the folder
contaning the Vagrantfile and select "Open command window here"
        
##### I want to connect with the private_key using PuTTY! ##### 
To use the private_key in PuTTY you need to convert the key using PuTTYgen, 
a tool available at the same location as PuTTY itself. Open the vagrant-generated 
private_key using File->Load Private Key and make sure the file extension is not 
set to ppk. Then save the private key in putty format.








