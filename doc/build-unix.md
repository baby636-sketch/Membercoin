# UNIX BUILD NOTES

Some notes on how to build Bitcoin Unlimited in Unix. Mostly with at Ubuntu / Debian focus. 

For RPM based distros, see [build-unix-rpm.md](build-unix-rpm.md).
For OpenBSD specific instructions, see [build-openbsd.md](build-openbsd.md).
For FreeBSD specific instructions, see [build-freebsd.md](build-freebsd.md).


# Installing dependencies

Run the following to install the base dependencies for building:


```bash
sudo apt-get install build-essential libtool autotools-dev autoconf automake pkg-config libssl-dev libevent-dev bsdmainutils git
```

On at least Ubuntu 14.04+ and Debian 7+ there are generic names for the
individual boost development packages, so the following can be used to only
install necessary parts of boost:

```bash
sudo apt-get install libboost-system-dev libboost-filesystem-dev libboost-chrono-dev libboost-program-options-dev libboost-test-dev libboost-thread-dev
```

If that doesn't work, you can install all boost development packages with:

```bash
sudo apt-get install libboost-all-dev
```

## Optional

### miniupnpc

[miniupnpc](http://miniupnp.free.fr/) may be used for UPnP port mapping.  It can be downloaded from [here](
http://miniupnp.tuxfamily.org/files/).  UPnP support is compiled in and
turned off by default.
To install the dependencies
```bash
sudo apt-get install libminiupnpc-dev
```

See the configure options for upnp behavior desired:
```bash
--without-miniupnpc      #No UPnP support miniupnp not required
--disable-upnp-default   #(the default) UPnP support turned off by default at runtime
--enable-upnp-default    #UPnP support turned on by default at runtime
```

### ZMQ

```bash
sudo apt-get install libzmq3-dev # provides ZMQ API 4.x
```


## Installing dependencies for wallet support


BerkeleyDB is required for the wallet. If you don't need wallet support, but just want a node, you don't need this.

db4.8 packages are available [here](https://launchpad.net/~bitcoin-unlimited/+archive/ubuntu/bucash).

You can add the repository and install using the following commands:

```bash
sudo add-apt-repository ppa:bitcoin-unlimited/bucash
sudo apt-get update
sudo apt-get install libdb4.8-dev libdb4.8++-dev
```

Ubuntu and Debian have their own libdb-dev and libdb++-dev packages, but these will install
BerkeleyDB 5.1 or later, which break binary wallet compatibility with the distributed executables which
are based on BerkeleyDB 4.8. If you do not care about wallet compatibility,
pass `--with-incompatible-bdb` to configure.

See the section "Disable-wallet mode" to build Bitcoin Unlimited without wallet.

You can also build BDB4.8 your self. See [below](#berkeley-db)


## Installing dependencies for the GUI

If you want to build Bitcoin-Qt, make sure that the required packages for Qt development
are installed. Qt 5.3 or higher is necessary to build the GUI.
To build without GUI pass `--without-gui`.

To build with Qt 5.3 or higher you need the following:

```bash
sudo apt-get install libqt5gui5 libqt5core5a libqt5dbus5 qttools5-dev qttools5-dev-tools libprotobuf-dev protobuf-compiler
```

libqrencode (optional) can be installed with:

```bash
sudo apt-get install libqrencode-dev
```

Once these are installed, they will be found by configure and a bitcoin-qt executable will be
built by default.

## Dependencies

These dependencies are required:

 Library     | Purpose          | Description
 ------------|------------------|----------------------
 libssl      | Crypto           | Random Number Generation, Elliptic Curve Cryptography
 libboost    | Utility          | Library for threading, data structures, etc
 libevent    | Networking       | OS independent asynchronous networking

Optional dependencies:

 Library     | Purpose          | Description
 ------------|------------------|----------------------
 miniupnpc   | UPnP Support     | Firewall-jumping support
 libdb4.8    | Berkeley DB      | Wallet storage (only needed when wallet enabled)
 qt          | GUI              | GUI toolkit (only needed when GUI enabled)
 protobuf    | Payments in GUI  | Data interchange format used for payment protocol (only needed when GUI enabled)
 libqrencode | QR codes in GUI  | Optional for generating QR codes (only needed when GUI enabled)
 libzmq3     | ZMQ notification | Optional, allows generating ZMQ notifications (requires ZMQ version >= 4.x)

For the versions used, see [dependencies.md](dependencies.md)

# Building Bitcoin Unlimited

Start out by fetching the code

```bash
git clone https://gitlab.com/bitcoinunlimited/BCHUnlimited.git
cd BCHUnlimited/
```
## To build without wallet

If you only need to run a node, and have no need for a wallet or GUI you can build the binaries with:

In this case there is no dependency on Berkeley DB 4.8 or Qt5.

Mining is also possible in disable-wallet mode, but only using the `getblocktemplate` RPC
call not `getwork`.



```bash
./autogen.sh
./configure --disable-wallet --with-gui=no
make
make install # optional
```

You will find the `bitcoind` binary in the `src/` folder.

## To build with wallet


It is recommended to use Berkeley DB 4.8.

If you install the package from the BU Launchpad ppa, as descibed [above](#installing-dependencies-for-wallet-support) you can build with


```bash
./autogen.sh
./configure
make
make install # optional
```

You will find the `bitcoind` binary in the `src/` folder. This will build `bitcoin-qt` as well (in `src/qt`), if the dependencies are met.



### Berkeley DB

If you want to build BDB4.8 yourself and then build Bitcoin Unlimited, do as follows from the Bitcoin Unlimited directory:

```bash
BITCOIN_ROOT=$(pwd)

# Pick some path to install BDB to, here we create a directory within the bitcoin directory
BDB_PREFIX="${BITCOIN_ROOT}/db4"
mkdir -p $BDB_PREFIX

# Fetch the source and verify that it is not tampered with
wget 'https://download.oracle.com/berkeley-db/db-4.8.30.NC.tar.gz'
echo '12edc0df75bf9abd7f82f821795bcee50f42cb2e5f76a6a281b85732798364ef  db-4.8.30.NC.tar.gz' | sha256sum -c
# MUST output: db-4.8.30.NC.tar.gz: OK
tar -xzvf db-4.8.30.NC.tar.gz

# Fetch, verify that it is not tampered with and apply clang related patch
cd db-4.8.30.NC
wget 'https://gist.githubusercontent.com/LnL7/5153b251fd525fe15de69b67e63a6075/raw/7778e9364679093a32dec2908656738e16b6bdcb/clang.patch'
echo '7a9a47b03fd5fb93a16ef42235fa9512db9b0829cfc3bdf90edd3ec1f44d637c clang.patch' | sha256sum -c
# MUTST output: clang.patch: OK

# Build the library and install to our prefix
cd build_unix/
#  Note: Do a static build so that it can be embedded into the executable, instead of having to find a .so at runtime
../dist/configure --enable-cxx --disable-shared --with-pic --prefix=$BDB_PREFIX
make install

# Build Bitcoin Unlimited with the BDB you just compiled.
cd $BITCOIN_ROOT
./autogen.sh
./configure LDFLAGS="-L${BDB_PREFIX}/lib/" CPPFLAGS="-I${BDB_PREFIX}/include/" # (other args...)
make
make install # optional
```

**Note**: You only need Berkeley DB if the wallet is enabled.


# Notes

## Additional Configure Flags

A list of additional configure flags can be displayed with:

```bash
./configure --help
```

## Absolute path

Always use absolute paths to configure and compile bitcoin and the dependencies,
for example, when specifying the path of the dependency:

```bash
../dist/configure --enable-cxx --disable-shared --with-pic --prefix=$BDB_PREFIX
```

Here BDB_PREFIX must absolute path - it is defined using $(pwd) which ensures
the usage of the absolute path.

## System requirements

C++ compilers are memory-hungry. It is recommended to have at least 1 GB of
memory available when compiling Bitcoin Unlimited. With 512MB of memory or less
compilation will take much longer due to swap thrashing.

## Strip debug symbols

The release is built with GCC and then `strip bitcoind` to strip the debug
symbols, which reduces the executable size by about 90%.



## Security

To help make your Bitcoin installation more secure by making certain attacks impossible to
exploit even if a vulnerability is found, binaries are hardened by default.
This can be disabled with:

Hardening Flags:

```bash
./configure --enable-hardening
./configure --disable-hardening
```


Hardening enables the following features:

* Position Independent Executable
    Build position independent code to take advantage of Address Space Layout Randomization
    offered by some kernels. Attackers who can cause execution of code at an arbitrary memory
    location are thwarted if they don't know where anything useful is located.
    The stack and heap are randomly located by default but this allows the code section to be
    randomly located as well.

    On an AMD64 processor where a library was not compiled with -fPIC, this will cause an error
    such as: "relocation R_X86_64_32 against `......' can not be used when making a shared object;"

    To test that you have built PIE executable, install `scanelf`, part of `pax-utils`, and use:

```bash
scanelf -e ./bitcoind
```

    The output should contain:

     TYPE
    ET_DYN

* Non-executable Stack
    If the stack is executable then trivial stack based buffer overflow exploits are possible if
    vulnerable buffers are found. By default, bitcoin should be built with a non-executable stack
    but if one of the libraries it uses asks for an executable stack or someone makes a mistake
    and uses a compiler extension which requires an executable stack, it will silently build an
    executable without the non-executable stack protection.

    To verify that the stack is non-executable after compiling use:
    `scanelf -e ./bitcoind`

    the output should contain:
	STK/REL/PTL
	RW- R-- RW-

    The STK RW- means that the stack is readable and writeable but not executable.


## Produce Static Binaries

If you want to build statically linked binaries so that you could compile in one machine
and deploy in same parch/platform boxes without the need of installing all the dependencies
just follow these steps. You will need to install `curl`.

```bash
git clone https://github.com/BitcoinUnlimited/BitcoinUnlimited.git BU
cd BU/depends
make HOST=x86_64-pc-linux-gnu -j4
cd ..
./autogen.sh
./configure --prefix=$PWD/depends/x86_64-pc-linux-gnu --disable-tests CFLAGS="-msse4.1 -mavx2"
make -j4
```

in the above commands we are statically compiling headless 64 bit Linux binaries. If you want to compile
32 bit binaries just use `i686-pc-linux-gnu` rather than `x86_64-pc-linux-gnu`

## ARM Cross-compilation

These steps can be performed on, for example, an Ubuntu VM. The depends system
will also work on other Linux distributions, however the commands for
installing the toolchain will be different.

Make sure you install the build requirements mentioned above.
Then, install the toolchain and curl:

```bash
sudo apt-get install g++-arm-linux-gnueabihf curl
```

To build executables for ARM:

```bash
cd depends
make HOST=arm-linux-gnueabihf NO_QT=1
cd ..
./autogen.sh
./configure --prefix=$PWD/depends/arm-linux-gnueabihf --enable-glibc-back-compat --enable-reduce-exports LDFLAGS=-static-libstdc++
make
```


For further documentation on the depends system see [README.md](../depends/README.md) in the depends directory.
