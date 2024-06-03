#!/bin/bash

function func_name {
	echo "Function 1"
}

func_name2 () {
	echo "Function 2"
}


cat script.sh | while read LineFile
do
	echo $LineFile
done

if [ -n $1 ]
then
	echo "Parameter: $0 $1"
fi

func_name
func_name2
