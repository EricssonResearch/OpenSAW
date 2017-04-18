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

#-----------------------------------------------------
# Vars
#-----------------------------------------------------

# Programs
MAZEPKG=opensaw.utils.mazes

# File names
MAZEFIG=figure
MAZECPP=program.cpp
MAZEIN=initial.in
MAKEFILE=makefile

# File content
TESTRULE="test: program.out\n\tpython -m opensaw -c -i $MAZEIN -- program.out {}\n"
PROGRULE="program.out: $MAZECPP\n\tg++ -Wall -Wextra $MAZECPP -o program.out"
CLEANRULE="clean:\n\trm *.out\n\trm -rf opensaw_dir/"

#-----------------------------------------------------
# Helpers
#-----------------------------------------------------
create_maze()
{
    python -m $MAZEPKG -s -x=$1 -y=$2 -f $MAZEFIG -c $MAZECPP --solve > $MAZEIN
    while [ $(wc -m < $MAZEIN) -lt `expr $1 \* $2` ]
    do
	echo -n "U" >> $MAZEIN
    done
    return
}

create_dir_makefile()
{
    echo -e $TESTRULE > $MAKEFILE
    echo -e $PROGRULE >> $MAKEFILE
    echo -e $CLEANRULE >> $MAKEFILE
    return
}

create_makefile()
{
    echo -e $TESTRULE > $MAKEFILE
    echo -e $PROGRULE >> $MAKEFILE
    echo -e $CLEANRULE >> $MAKEFILE
    return
}

build_maze_dir()
{
    [ -d $1 ] || mkdir $1
    cd $1
    create_maze $2 $3
    create_makefile
    cd ..
    return
}

build_maze_cat()
{
    [ $2 -ge 1 ] || return
    echo "Building catalog $1 with $2 mazes of size ($3, $4)."
    [ -d $1 ] || mkdir $1
    cd $1
    for (( i = 1 ; i <= $2 ; i++ ))
    do
	create_dir_makefile
	build_maze_dir $1_maze_$i $3 $4
    done
    cd ..
    return
}

#-----------------------------------------------------
# Main
#-----------------------------------------------------

build_maze_cat huge 1 100 50
build_maze_cat big 2 20 10
build_maze_cat medium 4 10 5
build_maze_cat small 10 5 5