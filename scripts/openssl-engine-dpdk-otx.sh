#!/bin/bash
if [ -n "$DPDK_DEVBIND_PATH" ]; then
    File=$DPDK_DEVBIND_PATH/dpdk-devbind.py
else
if [ -n "$1" ]; then
    File=$1
else
    File=/usr/share/dpdk/usertools/dpdk-devbind.py
fi
fi
if [ ! -f $File ]; then
    echo "provide /path/to/dpdk-devbind.py or set environment varaible DPDK_DEVBIND_PATH"
    exit 1
fi

echo 24 > /sys/bus/pci/drivers/octeontx-cpt/0000\:04\:00.0/sriov_numvfs
echo 24 > /sys/bus/pci/drivers/octeontx-cpt/0000\:05\:00.0/sriov_numvfs

python $File -b vfio-pci 0000:04:00.{1,2,3,4,5,6,7} 0000:04:0{1,2}.{0,1,2,3,4,5,6,7} 0000:04:03.0

python $File -b vfio-pci 0000:05:00.{1,2,3,4,5,6,7} 0000:05:0{1,2}.{0,1,2,3,4,5,6,7} 0000:05:03.0

python $File --status

#create and mount huge pages
echo 28 > /sys/kernel/mm/hugepages/hugepages-524288kB/nr_hugepages
mkdir -p /mnt/huge
mount -t hugetlbfs nodev /mnt/huge
