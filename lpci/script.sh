#!/bin/bash

if ls /etc/s*.conf
	then echo "success"
	else echo "failed"
fi


for var in a b c d e f g
do
    echo "The letter is: " $var
    sleep 1
done
