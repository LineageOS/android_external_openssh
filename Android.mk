LOCAL_PATH:= $(call my-dir)

###################### libssh ######################
include $(CLEAR_VARS)

LOCAL_MODULE_TAGS := optional

LOCAL_SRC_FILES := \
    addrmatch.c \
    atomicio.c \
    authfd.c \
    authfile.c \
    bitmap.c \
    canohost.c \
    chacha.c \
    channels.c \
    cipher-aes.c \
    cipher-aesctr.c \
    cipher.c \
    cipher-chachapoly.c \
    cipher-ctr.c \
    cleanup.c \
    compat.c \
    crc32.c \
    dh.c \
    digest-openssl.c \
    dispatch.c \
    dns.c \
    ed25519.c \
    entropy.c \
    fatal.c \
    fe25519.c \
    ge25519.c \
    gss-genr.c \
    hash.c \
    hmac.c \
    hostfile.c \
    kex.c \
    kexc25519.c \
    kexdh.c \
    kexecdh.c \
    kexgen.c \
    kexgex.c \
    kexgexc.c \
    kexsntrup4591761x25519.c \
    krl.c \
    log.c \
    mac.c \
    match.c \
    misc.c \
    moduli.c \
    monitor_fdpass.c \
    msg.c \
    nchan.c \
    openbsd-compat/bcrypt_pbkdf.c \
    openbsd-compat/bindresvport.c \
    openbsd-compat/blowfish.c \
    openbsd-compat/bsd-closefrom.c \
    openbsd-compat/bsd-getpeereid.c \
    openbsd-compat/bsd-misc.c \
    openbsd-compat/bsd-openpty.c \
    openbsd-compat/bsd-signal.c \
    openbsd-compat/bsd-statvfs.c \
    openbsd-compat/explicit_bzero.c \
    openbsd-compat/freezero.c \
    openbsd-compat/fmt_scaled.c \
    openbsd-compat/getopt_long.c \
    openbsd-compat/glob.c \
    openbsd-compat/boringssl-api-compat.c \
    openbsd-compat/openssl-compat.c \
    openbsd-compat/port-linux.c \
    openbsd-compat/port-net.c \
    openbsd-compat/pwcache.c \
    openbsd-compat/readpassphrase.c \
    openbsd-compat/reallocarray.c \
    openbsd-compat/recallocarray.c \
    openbsd-compat/rresvport.c \
    openbsd-compat/setproctitle.c \
    openbsd-compat/strmode.c \
    openbsd-compat/strtonum.c \
    openbsd-compat/timingsafe_bcmp.c \
    openbsd-compat/vis.c \
    packet.c \
    platform-misc.c \
    platform-pledge.c \
    platform-tracing.c \
    poly1305.c \
    readpass.c \
    rijndael.c \
    sc25519.c \
    smult_curve25519_ref.c \
    sshbuf.c \
    sshbuf-getput-basic.c \
    sshbuf-getput-crypto.c \
    sshbuf-misc.c \
    ssh-dss.c \
    ssh-ecdsa.c \
    ssh-ed25519.c \
    ssherr.c \
    sshkey.c \
    sshkey-xmss.c \
    ssh-rsa.c \
    ssh-xmss.c \
    sntrup4591761.c \
    ttymodes.c \
    uidswap.c \
    umac128.c \
    umac.c \
    utf8.c \
    uuencode.c \
    verify.c \
    xmalloc.c \
    xmss_commons.c \
    xmss_fast.c \
    xmss_hash_address.c \
    xmss_hash.c \
    xmss_wots.c

LOCAL_C_INCLUDES := \
    external/zlib \
    external/openssl/include \
    external/openssh/openbsd-compat

LOCAL_SHARED_LIBRARIES += libssl libcrypto libdl libz

LOCAL_MODULE := libssh

LOCAL_CFLAGS += \
    -O3 \
    -Wno-macro-redefined \
    -Wno-pointer-sign \
    -Wno-sign-compare \
    -Wno-tautological-compare \
    -Wno-unused-parameter

LOCAL_CFLAGS += -DGCE_PLATFORM_SDK_VERSION=$(PLATFORM_SDK_VERSION)
ifneq ($(filter gce_x86 calypso, $(TARGET_DEVICE)),)
LOCAL_CFLAGS += -DANDROID_GCE -DSSHDIR=\"/var/run/ssh\"
endif

ifneq (,$(SSHDIR))
LOCAL_CFLAGS += -DSSHDIR=\"$(SSHDIR)\"
endif

include $(BUILD_SHARED_LIBRARY)

###################### ssh ######################

include $(CLEAR_VARS)

LOCAL_MODULE_TAGS := optional

LOCAL_SRC_FILES := \
    clientloop.c \
    readconf.c \
    mux.c \
    ssh.c \
    sshconnect2.c \
    sshconnect.c \
    sshtty.c \
    uidswap.c

LOCAL_MODULE := ssh

LOCAL_CFLAGS += \
    -Wno-macro-redefined \
    -Wno-pointer-sign \
    -Wno-sign-compare \
    -Wno-unused-parameter

LOCAL_C_INCLUDES := \
    external/zlib \
    external/openssl/include \
    external/openssh/openbsd-compat

LOCAL_SHARED_LIBRARIES += libssh libssl libcrypto libdl libz

include $(BUILD_EXECUTABLE)

###################### sftp ######################

include $(CLEAR_VARS)

LOCAL_MODULE_TAGS := optional

LOCAL_SRC_FILES := \
    sftp.c sftp-client.c sftp-common.c sftp-glob.c progressmeter.c

LOCAL_MODULE := sftp

LOCAL_CFLAGS += -Wno-unused-parameter -Wno-macro-redefined

LOCAL_C_INCLUDES := \
    external/zlib \
    external/openssl/include \
    external/openssh/openbsd-compat

LOCAL_SHARED_LIBRARIES += libssh libssl libcrypto libdl libz

include $(BUILD_EXECUTABLE)

###################### scp ######################

include $(CLEAR_VARS)

LOCAL_MODULE_TAGS := optional

LOCAL_SRC_FILES := \
    scp.c progressmeter.c

LOCAL_MODULE := scp

LOCAL_CFLAGS += -Wno-unused-parameter -Wno-macro-redefined

LOCAL_C_INCLUDES := \
    external/zlib \
    external/openssl/include \
    external/openssh/openbsd-compat

LOCAL_SHARED_LIBRARIES += libssh libssl libcrypto libdl libz

include $(BUILD_EXECUTABLE)

###################### sshd ######################

include $(CLEAR_VARS)

LOCAL_MODULE_TAGS := optional

LOCAL_SRC_FILES := \
    audit-bsm.c \
    audit-linux.c \
    audit.c \
    auth-bsdauth.c \
    auth-krb5.c \
    auth-options.c \
    auth-pam.c \
    auth-rhosts.c \
    auth-shadow.c \
    auth-sia.c \
    auth.c \
    auth2-chall.c \
    auth2-gss.c \
    auth2-hostbased.c \
    auth2-kbdint.c \
    auth2-none.c \
    auth2-passwd.c \
    auth2-pubkey.c \
    auth2.c \
    groupaccess.c \
    gss-serv-krb5.c \
    gss-serv.c \
    kexgexs.c \
    loginrec.c \
    md5crypt.c \
    monitor.c \
    monitor_wrap.c \
    platform.c \
    sandbox-null.c \
    sandbox-rlimit.c \
    sandbox-systrace.c \
    servconf.c \
    serverloop.c \
    session.c \
    sftp-common.c \
    sftp-server.c \
    sshd.c \
    sshlogin.c \
    sshpty.c

LOCAL_MODULE := sshd

LOCAL_CFLAGS += \
    -Wno-implicit-function-declaration \
    -Wno-macro-redefined \
    -Wno-pointer-sign \
    -Wno-unused-parameter \
    -Wno-unused-variable

LOCAL_C_INCLUDES := \
    external/zlib \
    external/openssl/include \
    external/openssh/openbsd-compat

LOCAL_SHARED_LIBRARIES += libssh libssl libcrypto libdl libz libcutils

include $(BUILD_EXECUTABLE)

###################### ssh-keygen ######################

include $(CLEAR_VARS)

LOCAL_MODULE_TAGS := optional

LOCAL_SRC_FILES := \
    ssh-keygen.c

LOCAL_MODULE := ssh-keygen

LOCAL_CFLAGS += -Wno-unused-parameter -Wno-macro-redefined

LOCAL_C_INCLUDES := \
    external/zlib \
    external/openssl/include \
    external/openssh/openbsd-compat

LOCAL_SHARED_LIBRARIES += libssh libssl libcrypto libdl libz

include $(BUILD_EXECUTABLE)

###################### sshd_config ######################

include $(CLEAR_VARS)
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := sshd_config
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT_ETC)/ssh
LOCAL_SRC_FILES := sshd_config.android
include $(BUILD_PREBUILT)

###################### start-ssh ######################

include $(CLEAR_VARS)
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := start-ssh
LOCAL_MODULE_CLASS := EXECUTABLES
LOCAL_SRC_FILES := start-ssh
include $(BUILD_PREBUILT)
