# Preamble to run a test. Hides the complexity of setting up tests.
# To be included first by the tests

[[ $(basename $0) = "preamble.sh" ]] &&
	echo "This script is only intended to be run by tests. Exiting." && exit 1

# If not in a VM, start one and execute self.
HYP=$(grep -c "^flags.* hypervisor" /proc/cpuinfo)

if [[ $HYP -eq 0 ]]; then
	. ./framework.sh

	startvm $(realpath $0)
	exit 0
fi

# sharness needs to write to some files and results. Put everything in
# a temporary directory that the VM can write to.
SHARNESS_TEST_DIRECTORY=$(pwd)/tmptests

modprobe ptp
modprobe amd_iommu_v2 || modprobe iommu_v2
