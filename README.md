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
