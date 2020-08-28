#!/bin/bash

ifconfig enp1s0 up
ip addr add 10.0.0.1/24 dev enp1s0

ethtool -K enp1s0 gso off
ethtool -K enp1s0 gro off

#echo 1 > /proc/irq/131/smp_affinity
#echo 2 > /proc/irq/132/smp_affinity
#echo 4 > /proc/irq/133/smp_affinity
#echo 8 > /proc/irq/134/smp_affinity
