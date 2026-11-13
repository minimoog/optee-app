# Build qemu with optee on Ubuntu
sudo apt install repo git make gcc python3-pyelftools python3-cryptography \
  libglib2.0-dev libpixman-1-dev libslirp-dev ninja-build flex bison \
  device-tree-compiler libssl-dev uuid-dev ccache cscope netcat expect \
  xterm rsync unzip curl

mkdir optee-qemu && cd optee-qemu
repo init -u https://github.com/OP-TEE/manifest.git -m qemu_v8.xml
repo sync -j4

cd build
make -j2 toolchains     # downloads the ARM cross-compilers
make -j$(nproc) run     # builds everything and launches QEMU


# To copy and run ta application on qemu-optee


make QEMU_VIRTFS_ENABLE=y QEMU_VIRTFS_HOST_DIR=$HOME/shared run

mkdir -p /mnt/host
mount -t 9p -o trans=virtio host /mnt/host
ls /mnt/host

cp /mnt/host/ef5a9bc1-251a-4081-9fbf-14694164610e.ta /lib/optee_armtz/
cp /mnt/host/my_app /usr/bin/
chmod +x /usr/bin/my_app

my_app