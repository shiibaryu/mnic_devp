sudo sysctl vm.nr_hugepages=1024

echo 1024 | sudo tee /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
#echo 1024 | sudo tee /sys/devices/system/node/node1/hugepages/hugepages-2048kB/nr_hugepages

sudo modprobe uio_pci_generic
sudo ./bin/dpdk-devbind.py -b uio_pci_generic $1
