#
# Script to build the Marvell BMC.
#
# Copy this script and the Install_Marvell_BMC.sh to the place where you
# want to do the build and cd to there.
#
# Then you must get the software in the current directory:
# 
# armv5-marvell-linux-gnueabi-soft_i686.tar.bz2
# buildroot-2011.05-sdk5.1.2.tar.bz2
#
# then execute this script.  This only builds the software, use
# Install_Marvell_BMC.sh to isntall it into a rootfs.
#

TOOLCHAIN=armv5-marvell-linux-gnueabi-soft_i686
BUILDROOT=buildroot-2011.05-sdk5.1.2

# General variables we use
MBASEDIR=`pwd`
BRDIR=${MBASEDIR}/${BUILDROOT}

# Untar the toolchain and build system and get openipmi
tar xjf ${TOOLCHAIN}.tar.bz2
tar xjf ${BUILDROOT}.tar.bz2
git clone git://git.code.sf.net/p/openipmi/code openipmi

# Install the busybox config and set the toolchain path
cp openipmi/lanserv/marvell-bmc/marvell_bmc.config ${BRDIR}/.config
sed -i "s%BR2_TOOLCHAIN_EXTERNAL_PATH=.*\$%BR2_TOOLCHAIN_EXTERNAL_PATH=\"${MBASEDIR}/${TOOLCHAIN}\"%" ${BRDIR}/.config

cp openipmi/lanserv/marvell-bmc/busybox-1.18.4.config ${BRDIR}
cd ${BRDIR}
make
#  this will take a while

# Now check out and build openipmi
cd ${MBASEDIR}
export PATH=${MBASEDIR}/${TOOLCHAIN}/bin:$PATH
cd openipmi
libtoolize
aclocal
autoconf
automake -a
autoreconf
./configure --host=arm-mv5sft-linux-gnueabi --prefix=/usr --sysconfdir=/etc \
	--localstatedir=/var --with-glib=no --with-python=no --with-perl=no \
	host_alias=arm-mv5sft-linux-gnueabi --with-marvell-bmc \
	CC="arm-marvell-linux-gnueabi-gcc --sysroot=${BRDIR}/output/staging"
make
