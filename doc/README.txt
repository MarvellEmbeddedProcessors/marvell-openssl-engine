01. Introduction

02. DPDK based Openssl Engine Directory Structure

03. Supported Platforms

    - OCTEONTX/OCTEONTX2

04. Testing DPDK based Openssl Engine

05. Benchmarking DPDK based Openssl Engine

06. Making Engine as static engine

07. Notes

08. Known Issues


01. Introduction
================
  This README gives overview of contents of this release, supported platform, known issues
  and pre-requisite to build and run DPDK based Openssl engine.

  For sake of simplicity, DPDK based Openssl engine in this release will be referred as
  'Openssl engine' in rest of the document.

02. DPDK based Openssl Engine Directory Structure
=================================================
  Openssl engine directory structure looks like:

  openssl-engine-dpdk
      | \|
      | \|---.c
      | \|      (engine sources)
      | \|---patches/
      | \|      (contain patches to be applied on dependent sources)
      | \|---scripts/
      | \|      (contain board setup scripts)
      | \|---doc/
      | \|      (contain README.txt and openssl.cnf)

03. Supported Platforms
=======================
  This release supports OCTEONTX2 CN96XX, CN98XX, CN10XX
  The cryptodev PMDs supported on each platform are:
  1. CN96XX, CN98XX - librte_crypto_octeontx2, librte_crypto_openssl
  2. CN10XX - librte_crypto_cn10k
  3. Intel X86 - librte_crypto_openssl

I) Dependencies
---------------
  Following sources are pre-requisite for Openssl Engine solution and should be
  built beforehand:

  | a) SDK : Base SDK, engine release supported with. See Release Notes.
  | b) DPDK : Provided in SDK package (Supported versions: 20.11, 21.11, 22.11, 23.11)
  | c) OpenSSL : openssl-1.1.1q
  | d) Require ninja, meson utilities.

  The SDK is not used on the Intel X86 platform and is optional

II) Building and Running Instructions
-------------------------------------
  Openssl engine is released in two modes:
   * Generic Solution in SDK package
   * Standalone

  i) Building openssl engine in 'Generic Solution' release mode for OCTEONTX2 CN96XX

  If released as 'generic solution' with SDK package, engine sources would be provided in
  SDK release package. Refer to SDK documentation for build instructions of engine solution.
  SDK build procedure will build dependencies too. Final libs and bins are available in build
  directory.

  If released as 'standalone', user would need to install and setup dependencies
  manually, refer to following section for manual building

  ii) Building dependencies manually in 'Standalone' mode for OCTEONTX2 CN96XX

    | Note:
    | - <PACKAGE_DIR> - directory where SDK is untarred
    | - <SDK_PATH> in following subsections refers to path to <PACKAGE_DIR>/base_sdk/sources
    | - <TOOLCHAIN_PATH> refers to <SDK_PATH>/toolchain/marvell-tools-XXX.0/bin
    | - <OPENSSL_DIR> refers to compiled openssl-1.1.1q directory generated after following
      openssl-1.1.1q build instructions
    | - <DPDK_DIR> refers to directory where dpdk sources are untarred
    | - <ENGINE_DIR> refers to directory containing Openssl engine sources
    | - <SDK_NAME> is name of SDK , example, SDK10.0-ED1001 while building with SDK10.0-ED1001

    Following subsections covers instructions for building dependent packages.
    a) Building SDK

       Refer to SDK documentation for build instruction of SDK

    b) Building OpenSSL

        Cross compile openssl-1.1.1q.tar.gz package:

        # tar -zxf openssl-1.1.1q.tar.gz

        # cd openssl-1.1.1q

        # ./Configure linux-aarch64 --cross-compile-prefix= <TOOLCHAIN_PATH>/aarch64-marvell-linux-gnu-

        # make

    c) DPDK

      Setting up DPDK sources

      # cd <SDK_PATH>/base-sources-<SDK_NAME>/dpdk/

      # tar -xjf sources-dpdk-<DPDK_VERSION>-<SDK_NAME>.tar.bz2,

      # cd <DPDK_DIR>

      Building DPDK sources

	  SDK_DIR $ source env_setup

	  dpdk_src $ meson cross_build --cross-file config/arm/arm64_octeontx2_linux_gcc
	  				&& ninja-build -C cross_build

	  dpdk_src $ mkdir install_dir
	  dpdk_src $ export DESTDIR=/absolute/path/till/install_dir
	  dpdk_src $ cd cross_build/
	  cross_build $ ninja install
	  export DPDK_INSTALL=/absolute/path/till/install_dir


    d) Building Engine

	  export OPENSSL_INSTALL=/path/to/openssl/build/directory

      # cd <ENGINE_DIR>

      # cross-compile for OCTEONTX

        make CROSS=<TOOLCHAIN_PATH>/aarch64-marvell-linux-gnu-

      # cross-compile for OCTEONTX2

        make CROSS=<TOOLCHAIN_PATH>/aarch64-marvell-linux-gnu- OTX2=y

    NOTE : Please add DPDK_PC="/absoule/path/till/pkgconfig" to make command if
           prefix is used with meson command while building engine.
      ex:
        dpdk_src $ meson cross_build --cross-file config/arm/arm64_octeontx2_linux_gcc
                   --prefix=/usr/lib && ninja-build -C cross_build

        while building engine
        #make CROSS=<TOOLCHAIN_PATH>/aarch64-marvell-linux-gnu- OTX2=y
         DPDK_PC=/absolute/path/till/install_dir/usr/lib/pkgconfig

      # to enable openssl.cnf support for dpdk_engine
      # engine compiled with OSSL_CONF=y cannot be run without openssl.cnf file

        make CROSS=<TOOLCHAIN_PATH>/aarch64-marvell-linux-gnu- OTX2=y OSSL_CONF=y


III) Setting up board to run Openssl Engine
-------------------------------------------
  This section covers steps required to set up target to run engine.

  a) Setting up openssl engine in 'Generic Solution' release mode

  If openssl engine solution is provided as 'generic solution' along with SDK
  release package, then all of libs and binaries would be available as part of
  built rootfs images. User should boot board with that rootfs image and find
  following libraries inside /usr directory

     # Openssl engine library dpdk_engine.so at /usr/local/lib/engines-1.1/
     # Openssl libraries libcrypto.so, libssl.so at /usr/lib/
     # Openssl application library openssl at /usr/bin/
     # Scripts to setup CPT VFS and hugepages at /usr/share/openssl-engine-dpdk/
     # DPDK library libdpdk.so at /usr/lib/
     # DPDK PMD libraries under /usr/lib/dpdk/pmds-<ABI_VERSION>/

  User should run platform specific scripts to setup required resources before
  launching engine:
      - for OCTEON10,

          source /usr/share/openssl-engine-dpdk/openssl-engine-dpdk-cn10k.sh /bin/dpdk-devbind.py

      - for OCTEONTX2,

          source /usr/share/openssl-engine-dpdk/openssl-engine-dpdk-otx2.sh /bin/dpdk-devbind.py

  Since the binaries and libraries are present at their expected locations in rootfs,
  all the testing and benchmarking commands mentioned in sections (4) and (5)
  of this README can now be run directly from any directory, for example

          openssl speed -engine dpdk_engine -elapsed rsa2048

  b) Setting up openssl engine in 'Standalone' release mode

  If openssl engine solution is provided standalone, then user manually need to copy
  libs and binaries on to the board. Following steps describes manual way to copy
  binaries

    # copy compiled DPDK and openssl sources on to target board

      <DPDK_DIR>/build/lib on to the target board as <DPDK_LIB_DIR>

      <OPENSSL_DIR> on to the target board as <OPENSSL_LIB_DIR>

    # copy DPDK PMDs to <DPDK_PMD_PATH>

      find <ABI_VERSION>
        cat <DPDK_DIR>/ABI_VERSION

      default <DPDK_PMD_PATH> might be one of the below based on dpdk meson config
        - /usr/lib/dpdk/pmds-<ABI_VERSION>/
        - /usr/local/lib/dpdk/pmds-<ABI_VERSION>/

      Use below command to find the <DPDK_PMD_PATH> (in build system)
        $ strings <DPDK_LIB_DIR>/librte_eal.so | grep DPDK_PLUGIN_PATH

      copy required PMD *.so (librte_crypto_cnxk) files
        from <DPDK_LIB_DIR>/dpdk/pmds-<ABI_VERSION>/ to <DPDK_PMD_PATH>

    # copy compiled <ENGINE_DIR> on to target board as <ENGINE_LIB_DIR>

    # mkdir -p /usr/local/lib/engines-1.1/

    # cp <ENGINE_LIB_DIR>/build/lib/dpdk_engine.so /usr/local/lib/engines-1.1/

    # export LD_LIBRARY_PATH=<DPDK_LIB_DIR>:<OPENSSL_LIB_DIR>

    # run the platform specific scripts (requires Python)

      copy <DPDK_DIR>/usertools/dpdk-devbind.py to the target board

      cd <ENGINE_LIB_DIR>/scripts

        - for OCTEONTX2 (cn96xx and cn98xx),

          sh openssl-engine-dpdk-otx2.sh <path to dpdk-devbind.py>

        - for OCTEON10 (cn106xx),

          sh openssl-engine-dpdk-cn10k.sh <path to dpdk-devbind.py>


IV) Supported Features
-----------------------
  This section lists supported features of Openssl engine on OCTEONTX/OCTEONTX2 platform.

  a) RSA async mode with following modulus lengths(in bits):

    i.   512
    ii.  1024
    iii. 2048
    iv.  3072
    v.   4096

  b) AES128/256-CBC async mode
  c) AES128/256-GCM async mode
  d) openssl speed app -multi option
  e) ECDSA and ECDH offload in async mode with the following NIST recommended Elliptic Curves
     over Prime field (reference, https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf):

    i.   NIST P-192
    ii.  NIST P-224
    iii. NIST P-256
    iv.  NIST P-384
    v.   NIST P-521

  f) Support Chacha20-poly1305 cipher on OCTEONTX2 96XX(rev:C0) and 98XX.
  g) OpenSSL pipeline feature - allows submission of batch requests to dpdk layer.

04. Testing DPDK based Openssl Engine
=====================================
  a) Run OpenSSL engine command to check engine capabilities

    # openssl engine dpdk_engine -c

    Result of the above command is as below:

    (dpdk_engine) OpenSSL Test engine support

     [RSA, ECDH, ECDSA, ChaCha20-Poly1305, id-aes128-GCM, id-aes256-GCM,
         AES-128-CBC, AES-256-CBC, AES-128-CBC-HMAC-SHA1, AES-256-CBC-HMAC-SHA1]

    If we run above command on OCTEONTX2 96XX(rev:C0) and 98XX, then we will see
    one more supported cipher. [ChaCha20-Poly1305]

  b) Run OpenSSL s_server with engine

    # openssl s_server -engine dpdk_engine -cert <CertificateFile> -key <KeyFile> -port 4433

  c) Run OpenSSL s_client on peer machine to connect to s_server running
     on the board

    # openssl s_client -connect <ip>:<port> -cipher <cipher_name>

  d) Using ENV variables to configure openssl engine.
      OTX2_BUS - Override the bus id of CPT device (Default: 20, use 10 for OCTEONTX2)
      CRYPTO_DRIVER - Override the crypto driver name to use (Default: crypto_cn10k)

    For DPDK 20.11,
    # OTX2_BUS=10 openssl engine dpdk_engine -c
    For DPDK 21.11 & beyond,
    (cn96xx) # OTX2_BUS=10 CRYPTO_DRIVER=crypto_cn9k openssl engine dpdk_engine -c
    (cn106xx) # OTX2_BUS=10 CRYPTO_DRIVER=crypto_cn10k openssl engine dpdk_engine -c

  e) Using dpdk_engine with openssl.cnf file (-engine argument should not be used)

    # OPENSSL_CONF=openssl.cnf openssl speed -elapsed rsa2048
    # OPENSSL_CONF=openssl.cnf openssl s_server -cert <CertificateFile> -key <KeyFile> -port 4433

  f) Running multi-process applications with openssl.cnf file
     Due to the limitations of DPDK, forking applications need to ensure that openssl.cnf file is loaded after fork().
     With openssl speed with -multi option, use OPENSSL_CONF_MULTI env instead of OPENSSL_CONF for this reason.
     Engine is loaded from openssl.cnf, do not use -engine argument when OPENSSL_CONF_MULTI is employed.

    # OPENSSL_CONF_MULTI=openssl.cnf openssl speed -multi 4 -elapsed rsa2048

05. Benchmarking DPDK based Openssl Engine
==========================================
  Openssl engine can be benchmarked using openssl speed application.

  (See man openssl speed on its usage). Example commands:

  \*Change to <OPENSSL_LIB_DIR>/apps before running these commands.

  a) Benchmark RSA

    # openssl speed -engine dpdk_engine -elapsed rsa2048

  b) Benchmark RSA async mode

    # openssl speed -engine dpdk_engine -async_jobs +26 -elapsed rsa2048

  c) Benchmark ECDSA on nistp256

    # openssl speed -engine dpdk_engine -elapsed ecdsap256

  d) Benchmark ECDSA on nistp256 in async mode

    # openssl speed -engine dpdk_engine -async_jobs +8 -elapsed ecdsap256

  e) Benchmark ECDH on nistp256

    # openssl speed -engine dpdk_engine -elapsed ecdhp256

  f) Benchmark ECDH on nistp256 in async mode

    # openssl speed -engine dpdk_engine -async_jobs +8 -elapsed ecdhp256

  g) Benchmark AES-128-CBC

    # openssl speed -engine dpdk_engine -elapsed -evp aes-128-cbc

  h) Benchmark AES-128-CBC async mode

    # openssl speed -engine dpdk_engine -elapsed -async_jobs +24 -evp aes-128-cbc

  i) Benchmark AES-128-GCM

    # openssl speed -engine dpdk_engine -elapsed -evp aes-128-gcm

  j) Benchmark AES-128-GCM async mode

    # openssl speed -engine dpdk_engine -elapsed -async_jobs +24 -evp aes-128-gcm

  k) Benchmark CHACHA20-POLY1305 async mode

    # openssl speed -engine dpdk_engine -elapsed -async_jobs +24 -evp
    # 	chacha20-poly1305

  l) Running openssl speed with -multi option

    Example for speed command with -multi option for RSA:

    # openssl speed -engine dpdk_engine -multi 18 -async_jobs +26 -elapsed rsa2048

   m) Benchmark AES-CBC-HMAC-SHA1 in async mode

    # openssl speed -engine dpdk_engine -elapsed -async_jobs +24 -evp aes-128-cbc-hmac-sha1

    # openssl speed -engine dpdk_engine -elapsed -async_jobs +24 -evp aes-256-cbc-hmac-sha1


06.  Notes
=================

    I. Configuring OpenSSL engine using 'openssl.cnf' file
          OpenSSL engine can be configured using OPENSSL CONF FILE.
        [ref: https://www.openssl.org/docs/man1.1.1/man5/config.html]. Some
        parameters that can be configured via conf file are

         a) 'eal params' for DPDK driver initialisation
         b) DPDK crypto driver to be used for crypto acceleration
         c) Number of VFs to be initialised
         d) Distribution of queues between VFs

       Please refer to sample 'openssl.cnf', part of OpenSSL ENGINE sources,
       for syntatical and semantical information on setting up parameters and
       configuration.

   II. Composite Ciphersuites
          For using composite cipher AES-CBC-HMAC-SHA1 on TLS applications,
        The application must set SSL_OP_NO_ENCRYPT_THEN_MAC option on SSL CTX.
        s_client and s_server provides '-no_etm' command line option to do this. (Only in OpenSSL 3.0.0)

07. Known Issues
================
  a) Multi Call for RSA, AES-GCM and Chacha20-Poly1305 not supported
  b) While running in async mode, OpenSSL s_client waits for a read event
     at socket before proceeding. This is an expected application behaviour.
  c) RSA verify operation is not supported in x86 (crypto_openssl PMD)
  d) Speed application with async mode is not supported for below:
     - ECDSA
     - ECDH
  e) Speed application with AES-CBC is not supported with sync mode.
  f) Speed is not supported for AES-CBC-HMAC-SHA1.

..........................................
