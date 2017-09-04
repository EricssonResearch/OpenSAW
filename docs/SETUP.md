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
When you are connected to the machine, read [```docs/Using OpenSAW.md```](Using%20OpenSAW.md)
## Vagrant
The setup has been tested on Windows 7 with VirtualBox 5.0.24 and Vagrant 1.8.5 but should also work on GNU/Linux and OS X.


To use vagrant version of OpenSAW you need to install Vagrant
and Virtualbox on your host machine. Choose the variant of
vagrant and virtualbox that matches your host machines OS.

Vagrant can be found here: https://www.vagrantup.com/downloads.html  
VirtualBox can be found here: https://www.virtualbox.org/wiki/Downloads

After both of these are installed, create a new folder and 
clone the OpenSAW repository into this folder using
```sh
$ mkdir OpenSAW_VM
$ cd OpenSAW_VM
$ git clone https://github.com/EricssonResearch/OpenSAW.git
```

For Windows (tested on Windows 7) one could install GitHub Desktop and clone 
the repository on a Windows folder. 
Then all the commands below could be executed on an instance of a CMD windows in
the appropriate folder. 
 
 After the repository is successfully cloned, copy the vagrant file into the current
 directory.
 
```sh
$ cp OpenSAW/tools/vagrant/Vagrantfile .
```

or on Windows 7 assuming the OpenSAW repository in installed on `C:\Users\test\Documents\GitHub`
```sh
C:\Users\test\Documents\GitHub>copy OpenSAW\tools\vagrant\Vagrantfile .
```

Your structure should look like
```sh
$ ls
OpenSAW/  Vagrantfile
```

On Windows 7 the structure should look like
```sh
C:\Users\test\Documents\GitHub>dir
...
2017-09-01  11:23    <DIR>          .
2017-09-01  11:23    <DIR>          ..
2017-09-01  11:22    <DIR>          OpenSAW
2017-09-01  11:22             3 410 Vagrantfile
...
```

To download an Ubuntu virtual machine, download PIN, compile the iltrans and pintool
and configure OpenSAW simply run the command.
```sh
$ vagrant up
```
This prepares and launches the virtual machine,
the first time this command can take around 15 minutes.
**_One word of warning; if you have less than 768MB ram free, virtualbox may pause
the machine without notification. Check the VirtualBox UI if nothing is happening._**

On a Windows 7 machine the command `vagrant up` invokes the PowerShell.
Two possible problems that may come up are the following:

a) The PowerShell executable is not included in the PATH environmental variable. 
In this case you will receive a relevant error message.
Open `Control Panel` -> `System And Security` -> `System` -> `Advanced System Settings` on the left -> 
`Advanced` tab -> `Environment Variables`.
From the `System variables` list choose the `Path` system variable and add the path to the PowerShell.
On our machines the path is `C:\Windows\System32\WindowsPowerShell\v1.0`

b) The PowerShell version may be old and the command `vagrant up` may hang without doing anything. 
Check the PowerShell version by invoking the following command in a PowerShell.   
```sh
PS C:\> $PSVersionTable

Name                           Value
----                           -----
PSVersion                      5.0.10586.117
...
```
The `PSVersion` value should be 5.0.x or higher. If you need to install the new PowerShell you can find it 
in the Windows Management Framework (WMF). Please check see the following link for your version of Windows and the 
different versions of the WMF: 

WMF: https://docs.microsoft.com/en-us/powershell/scripting/setup/installing-windows-powershell?view=powershell-5.1

When vagrant up has finished, a new virtual machine has been prepared for you. 
Connect to the virtual machine by running  
```sh
$ vagrant ssh
```
If you do not have a ssh client installed vagrant will
give you suggestions on how to proceed. If you have issues with the
key file, use the username "vagrant" and password "vagrant"

Note that the folder containing `Vagrantfile` will be mounted read/write on the virtual machine at
`/vagrant/`

To suspend the machine run
```sh
$ vagrant suspend
```
To halt the machine run
```sh
$ vagrant halt
```
And to remove the machine completely and all the files on it run
```sh
$ vagrant destroy
```

After this initial setup you might want to modify the lines
```
    v.memory = 768
    v.cpus = 1
```
in the `Vagrantfile` to match your system. The changes take effect after running `$ vagrant reload` or `$ vagrant halt; vagrant up`

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
