#
# Script to install the Marvell BMC.  Run from the same directory
# you ran Build_Marvell_BMC.sh in.
#

VERSION=1.0.0

# These are the things you must configure for your setup.  In general,
# you would set these in an override file 
AST1300=${HOME}/hhl/marvell/ast1300.ko
AXP_BOARD_FRU=${HOME}/hhl/marvell/axpfru-2.0.01.img
NTPSERVER=pool.ntp.org
MTIMEZONE=GMT
#MTIMEZONE=US/Central

if [ -e Install_Marvell_Overrides ]; then
	echo "Reading override file"
	source ./Install_Marvell_Overrides
fi

echo AST1300=$AST1300
echo AXP_BOARD_FRU=$AXP_BOARD_FRU
echo NTPSERVER=$NTPSERVER
echo MTIMEZONE=$MTIMEZONE

BUILDROOT=buildroot-2011.05-sdk5.1.2

# General variables we use
MBASEDIR=`pwd`
BRDIR=${MBASEDIR}/${BUILDROOT}

# Install openipmi into the image.  Some of this *MUST* be done as root,
# thus the sudo on those command.
cd ${MBASEDIR}

cd ${BRDIR}/output/images
sudo rm -rf rootfs
sudo mkdir rootfs
cd rootfs
sudo tar xf ../rootfs.tar
cd ${MBASEDIR}/openipmi
cd utils
sudo cp .libs/libOpenIPMIutils.so.0 ${BRDIR}/output/images/rootfs/usr/lib
cd ../unix
sudo cp .libs/libOpenIPMIposix.so.0 ${BRDIR}/output/images/rootfs/usr/lib
cd ../lanserv
sudo cp .libs/libIPMIlanserv.so.0 ${BRDIR}/output/images/rootfs/usr/lib
sudo cp .libs/ipmi_sim ${BRDIR}/output/images/rootfs/usr/sbin
cd marvell-bmc
sudo mkdir -p ${BRDIR}/output/images/rootfs/etc/ipmi
sudo cp lan.conf lancontrol marvell.emu marvell_node.emu netsrvc \
	${BRDIR}/output/images/rootfs/etc/ipmi
sudo cp interfaces ${BRDIR}/output/images/rootfs/etc/network
sudo cp S90ast1300 ${BRDIR}/output/images/rootfs/etc/init.d
sudo cp ntp.conf ${BRDIR}/output/images/rootfs/etc
sudo mkdir -p ${BRDIR}/output/images/rootfs/usr/lib/ipmi_sim
sudo cp .libs/marvell_mod.so ${BRDIR}/output/images/rootfs/usr/lib/ipmi_sim
sudo mkdir -p ${BRDIR}/output/images/rootfs/var/ipmi_sim
sudo mkdir -p ${BRDIR}/output/images/rootfs/var/ipmi_sim/AXP-SERVER
sudo cp sdrs.bin \
	${BRDIR}/output/images/rootfs/var/ipmi_sim/AXP-SERVER/sdr.20.main

# Now fix things up in the root filesystem
cd ${BRDIR}/output/images/rootfs

# Now install the board fru reference file in /etc/ipmi/axp_board_fru
sudo cp ${AXP_BOARD_FRU} etc/ipmi/axp_board_fru

# Now install ast1300.ko in root
sudo mkdir -p root
sudo cp ${AST1300} root/ast1300.ko


# Add the following to etc/inittab:
sudo sh -c 'echo "null::respawn:/usr/sbin/ipmi_sim -f /etc/ipmi/marvell.emu -n"\
	>>etc/inittab'

# Set the login prompt
sudo sh -c "echo \"Welcome to Marvell BMC ${VERSION}\" >etc/issue"

# Set the hostname.  No '.' allowed in hostname, so translate to '_'
sudo sh -c "echo \"BMC-${VERSION}\" | sed 's/\\./_/g' >etc/hostname"

# Fix a problem setting the hostname
sudo sed -i 's/hostname -F \/etc\/hostname/hostname "`cat \/etc\/hostname`"/' \
	etc/inittab

# Set the NTP server
sudo sed -i 's/NTPDATE=no/NTPDATE=yes/' etc/default/ntpd
sudo sed -i "s/pool\.ntp\.org/${NTPSERVER}/" etc/default/ntpd
sudo sed -i "s/pool\.ntp\.org/${NTPSERVER}/" etc/ntp.conf

# Set the time zone
sudo ln -sf /usr/share/zoneinfo/${MTIMEZONE} etc/localtime

# Create the event device for the AST1300
sudo mknod dev/event c 10 10

# The redirect for stdout is done so that the file is owned by the user,
# not root.sudo
sudo tar czf - * >${MBASEDIR}/rootfs-$VERSION.tar.gz
cd ..
sudo rm -rf rootfs

echo "Now you can install rootfs-$VERSION.tar.gz on the chassis."
echo ""
echo "You will need to edit etc/network/interfaces in the rootfs"
echo "to set it properly for your network."

