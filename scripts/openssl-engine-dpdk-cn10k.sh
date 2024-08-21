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

logicalCpuCount=$([ $(uname) = 'Darwin' ] && sysctl -n hw.logicalcpu_max ||
		lscpu -p | egrep -v '^#' | wc -l)

cptpf="$(lspci -d 177d:a0f2 | cut -d ' ' -f 1)"
cptdrv="$(lspci -k -d 177d:a0f2 | grep "cpt" | grep -oE '[^ ]+$')"
echo $cptpf > /sys/bus/pci/drivers/$cptdrv/unbind

echo $cptpf > /sys/bus/pci/drivers/$cptdrv/bind
export OTX2_BUS="$(lspci -d 177d:a0f2 | cut -d ':' -f 2 | cut -d ':' -f 1)"

# To enable  VF devices
echo 1 > /sys/bus/pci/drivers/$cptdrv/$cptpf/kvf_limits

#bind  vf devices
# VFs depend on number of queue_pairs available
echo 0 > /sys/bus/pci/drivers/$cptdrv/$cptpf/sriov_numvfs
echo $logicalCpuCount > /sys/bus/pci/drivers/$cptdrv/$cptpf/sriov_numvfs

CPT_VFS="$(lspci -d 177d:a0f3)"
for cptvf in $(echo "$CPT_VFS" | cut -d ' ' -f 1); do
# To enable 2 queue pairs for each VF
if [ -f /sys/bus/pci/devices/$cptvf/limits/cpt ]; then
	echo 2 > /sys/bus/pci/devices/$cptvf/limits/cpt
fi
python $File -b vfio-pci $cptvf
done

python $File --status

#create and mount huge pages
#for each core reversed one 512MB hugepage
echo $logicalCpuCount > /sys/kernel/mm/hugepages/hugepages-524288kB/nr_hugepages
mkdir -p /mnt/huge
mount -t hugetlbfs nodev /mnt/huge

echo "CPT device is found at the following PCI loc:"$cptpf
