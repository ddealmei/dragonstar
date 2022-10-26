ALL=dragonstar
CONFIG_FILE = .config

include ../src/build.rules

CFLAGS += $(EXTRA_CFLAGS)
CFLAGS += -I$(abspath ../src)
CFLAGS += -I$(abspath ../src/utils)

ifndef CONFIG_OS
ifdef CONFIG_NATIVE_WINDOWS
CONFIG_OS=win32
else
CONFIG_OS=unix
endif
endif

ifeq ($(CONFIG_OS), internal)
CFLAGS += -DOS_NO_C_LIB_DEFINES
endif

ifdef CONFIG_NATIVE_WINDOWS
CFLAGS += -DCONFIG_NATIVE_WINDOWS
LIBS += -lws2_32
endif

# By default for Dragonstar Tester
CONFIG_SAE=y
OBJS = dragonstar.o

ifdef CONFIG_PERF
CFLAGS += -O3 -DPERF
BIN_DIR="perf"
else # DEBUG Printing for differential tests
CFLAGS += -O3 -DDRAGONSTAR_DEBUG
BIN_DIR="debug"
OBJS += ../src/common/common_module_tests.o
CFLAGS += -DCONFIG_MODULE_TESTS
endif

NEED_RC4=y
NEED_AES=y
NEED_MD5=y
NEED_SHA1=y

OBJS += ../src/utils/common.o
OBJS += ../src/utils/wpa_debug.o
OBJS += ../src/utils/wpabuf.o
OBJS += ../src/utils/os_$(CONFIG_OS).o

ifdef CONFIG_SAE
CFLAGS += -DCONFIG_SAE
OBJS += ../src/common/sae.o
ifdef CONFIG_SAE_PK
CFLAGS += -DCONFIG_SAE_PK
OBJS += ../src/common/sae_pk.o
endif
NEED_ECC=y
NEED_DH_GROUPS=y
NEED_HMAC_SHA256_KDF=y
NEED_AP_MLME=y
NEED_DRAGONFLY=y
endif

ifdef CONFIG_EAP
CFLAGS += -DEAP_SERVER
endif

ifdef CONFIG_PKCS12
CFLAGS += -DPKCS12_FUNCS
endif

ifdef NEED_DRAGONFLY
OBJS += ../src/common/dragonfly.o
endif

ifndef CONFIG_CRYPTO
CONFIG_CRYPTO=hacl
endif

ifeq ($(CONFIG_CRYPTO), openssl)
OBJS += ../src/crypto/crypto_$(CONFIG_CRYPTO).o
LIBS += -lcrypto
endif

ifeq ($(CONFIG_CRYPTO), openssl_noasm)
OBJS += ../src/crypto/crypto_openssl.o

#TODO: move to config file for patch submission
OPENSSL_local_dir=/opt/local_install
LDFLAGS_OPENSSL=-L$(OPENSSL_local_dir)/lib -Wl,-rpath=$(OPENSSL_local_dir)/lib
INCLUDE_OPENSSL=-I$(OPENSSL_local_dir)/include
#TODO END

CFLAGS += $(INCLUDE_OPENSSL)
LIBS += $(LDFLAGS_OPENSSL)
LIBS += -lcrypto
endif

ifeq ($(CONFIG_CRYPTO), hacl)
OBJS += ../src/crypto/crypto_$(CONFIG_CRYPTO).o
CFLAGS += -DCONFIG_HACL

#TODO: move to config file for patch submission
HACL_dir=../../haclstar
LDFLAGS_HACL=-L$(HACL_dir)/gcc-compatible -Wl,-rpath=$(HACL_dir)/gcc-compatible -levercrypt
INCLUDE_HACL=-I$(HACL_dir)/gcc-compatible -I$(HACL_dir)/kremlin/kremlib/dist/minimal/
#TODO END

CFLAGS += -DCONFIG_CRYPTO_INTERNAL
CFLAGS += $(INCLUDE_HACL)
LIBS += $(LDFLAGS_HACL)
CONFIG_INTERNAL_AES=y
CONFIG_INTERNAL_DES=y
CONFIG_INTERNAL_SHA1=y
CONFIG_INTERNAL_MD4=y
CONFIG_INTERNAL_MD5=y
CONFIG_INTERNAL_SHA256=y
CONFIG_INTERNAL_SHA384=y
CONFIG_INTERNAL_SHA512=y
CONFIG_INTERNAL_RC4=y
CONFIG_INTERNAL_DH_GROUP5=y
endif

ifdef NEED_SHA1
ifneq ($(CONFIG_CRYPTO), openssl)
ifneq ($(CONFIG_CRYPTO), openssl_noasm)
SHA1OBJS += ../src/crypto/sha1.o
endif
endif
SHA1OBJS += ../src/crypto/sha1-prf.o
ifdef CONFIG_INTERNAL_SHA1
SHA1OBJS += ../src/crypto/sha1-internal.o
endif
OBJS += $(SHA1OBJS)
endif

CFLAGS += -DCONFIG_SHA256
OBJS += ../src/crypto/sha256-prf.o
ifdef CONFIG_INTERNAL_SHA256
OBJS += ../src/crypto/sha256-internal.o
endif
ifdef NEED_TLS_PRF_SHA256
OBJS += ../src/crypto/sha256-tlsprf.o
endif
ifdef NEED_TLS_PRF_SHA384
OBJS += ../src/crypto/sha384-tlsprf.o
endif
ifdef NEED_HMAC_SHA256_KDF
OBJS += ../src/crypto/sha256-kdf.o
endif
ifdef NEED_HMAC_SHA384_KDF
OBJS += ../src/crypto/sha384-kdf.o
endif
ifdef NEED_HMAC_SHA512_KDF
OBJS += ../src/crypto/sha512-kdf.o
endif
ifdef NEED_SHA384
CFLAGS += -DCONFIG_SHA384
OBJS += ../src/crypto/sha384-prf.o
endif
ifdef NEED_SHA512
CFLAGS += -DCONFIG_SHA512
OBJS += ../src/crypto/sha512-prf.o
endif

ifneq ($(CONFIG_CRYPTO), hacl)
ifdef NEED_DH_GROUPS
OBJS += ../src/crypto/dh_groups.o
endif
ifdef NEED_DH_GROUPS_ALL
CFLAGS += -DALL_DH_GROUPS
endif
ifdef CONFIG_INTERNAL_DH_GROUP5
ifdef NEED_DH_GROUPS
OBJS += ../src/crypto/dh_group5.o
endif
endif
endif

ifdef NEED_ECC
CFLAGS += -DCONFIG_ECC
endif

ifdef CONFIG_NO_RANDOM_POOL
CFLAGS += -DCONFIG_NO_RANDOM_POOL
else
ifdef CONFIG_GETRANDOM
CFLAGS += -DCONFIG_GETRANDOM
endif
OBJS += ../src/crypto/random.o
OBJS += ../src/utils/eloop.o
endif

ifdef CONFIG_DEBUG_SYSLOG
CFLAGS += -DCONFIG_DEBUG_SYSLOG
endif

_OBJS_VAR := OBJS
include ../src/objs.mk

dragonstar: $(OBJS)
	mkdir -p $(BIN_DIR)
	$(Q)$(CC) $(LDFLAGS) -o $(BIN_DIR)/dragonstar_$(CONFIG_CRYPTO) $(OBJS) $(LIBS)
	@$(E) "  LD " $@

clean: common-clean
	rm -f $(BIN_DIR)/dragonstar_$(CONFIG_CRYPTO)
