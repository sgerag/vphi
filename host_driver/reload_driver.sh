#!/bin/bash


/etc/init.d/mpss stop; rmmod mic; insmod ./mic.ko; /etc/init.d/mpss start; ifconfig mic0 up; brctl addif br0 mic0;
