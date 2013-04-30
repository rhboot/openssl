#
# OpenSSL/crypto/fips/Makefile
#

DIR=	fips
TOP=	../..
CC=	cc
INCLUDES=
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=fips_test_suite.c fips_randtest.c
APPS=

PROGRAM= fips_standalone_hmac
EXE= $(PROGRAM)$(EXE_EXT)

LIB=$(TOP)/libcrypto.a
LIBSRC=fips_aes_selftest.c fips_des_selftest.c fips_hmac_selftest.c fips_rand_selftest.c \
    fips_rsa_selftest.c fips_sha_selftest.c fips.c fips_dsa_selftest.c  fips_rand.c \
    fips_rsa_x931g.c fips_post.c fips_drbg_ctr.c fips_drbg_hash.c fips_drbg_hmac.c \
    fips_drbg_lib.c fips_drbg_rand.c fips_drbg_selftest.c fips_rand_lib.c \
    fips_cmac_selftest.c fips_ecdh_selftest.c fips_ecdsa_selftest.c fips_enc.c fips_md.c

LIBOBJ=fips_aes_selftest.o fips_des_selftest.o fips_hmac_selftest.o fips_rand_selftest.o \
    fips_rsa_selftest.o fips_sha_selftest.o fips.o fips_dsa_selftest.o  fips_rand.o \
    fips_rsa_x931g.o fips_post.o fips_drbg_ctr.o fips_drbg_hash.o fips_drbg_hmac.o \
    fips_drbg_lib.o fips_drbg_rand.o fips_drbg_selftest.o fips_rand_lib.o \
    fips_cmac_selftest.o fips_ecdh_selftest.o fips_ecdsa_selftest.o fips_enc.o fips_md.o

LIBCRYPTO=-L.. -lcrypto

SRC= $(LIBSRC) fips_standalone_hmac.c

EXHEADER= fips.h fips_rand.h
HEADER=	$(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib exe

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

exe:	$(EXE)

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

links:
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags:
	ctags $(SRC)

tests:

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

depend:
	@[ -n "$(MAKEDEPEND)" ] # should be set by upper Makefile...
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

$(EXE): $(PROGRAM).o
	FIPS_SHA_ASM=""; for i in $(SHA1_ASM_OBJ) sha256.o; do FIPS_SHA_ASM="$$FIPS_SHA_ASM ../sha/$$i" ; done; \
	for i in $(CPUID_OBJ); do FIPS_SHA_ASM="$$FIPS_SHA_ASM ../$$i" ; done; \
	$(CC) -o $@ $(CFLAGS) $(PROGRAM).o $$FIPS_SHA_ASM

# DO NOT DELETE THIS LINE -- make depend depends on it.

fips.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
fips.o: ../../include/openssl/bio.h ../../include/openssl/crypto.h
fips.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
fips.o: ../../include/openssl/evp.h ../../include/openssl/fips.h
fips.o: ../../include/openssl/fips_rand.h ../../include/openssl/hmac.h
fips.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
fips.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
fips.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
fips.o: ../../include/openssl/rand.h ../../include/openssl/rsa.h
fips.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
fips.o: ../../include/openssl/symhacks.h fips.c fips_locl.h
fips_aes_selftest.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
fips_aes_selftest.o: ../../include/openssl/crypto.h
fips_aes_selftest.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
fips_aes_selftest.o: ../../include/openssl/evp.h ../../include/openssl/fips.h
fips_aes_selftest.o: ../../include/openssl/lhash.h
fips_aes_selftest.o: ../../include/openssl/obj_mac.h
fips_aes_selftest.o: ../../include/openssl/objects.h
fips_aes_selftest.o: ../../include/openssl/opensslconf.h
fips_aes_selftest.o: ../../include/openssl/opensslv.h
fips_aes_selftest.o: ../../include/openssl/ossl_typ.h
fips_aes_selftest.o: ../../include/openssl/safestack.h
fips_aes_selftest.o: ../../include/openssl/stack.h
fips_aes_selftest.o: ../../include/openssl/symhacks.h fips_aes_selftest.c
fips_cmac_selftest.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
fips_cmac_selftest.o: ../../include/openssl/cmac.h
fips_cmac_selftest.o: ../../include/openssl/crypto.h
fips_cmac_selftest.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
fips_cmac_selftest.o: ../../include/openssl/evp.h ../../include/openssl/fips.h
fips_cmac_selftest.o: ../../include/openssl/lhash.h
fips_cmac_selftest.o: ../../include/openssl/obj_mac.h
fips_cmac_selftest.o: ../../include/openssl/objects.h
fips_cmac_selftest.o: ../../include/openssl/opensslconf.h
fips_cmac_selftest.o: ../../include/openssl/opensslv.h
fips_cmac_selftest.o: ../../include/openssl/ossl_typ.h
fips_cmac_selftest.o: ../../include/openssl/safestack.h
fips_cmac_selftest.o: ../../include/openssl/stack.h
fips_cmac_selftest.o: ../../include/openssl/symhacks.h fips_cmac_selftest.c
fips_cmac_selftest.o: fips_locl.h
fips_des_selftest.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
fips_des_selftest.o: ../../include/openssl/crypto.h
fips_des_selftest.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
fips_des_selftest.o: ../../include/openssl/evp.h ../../include/openssl/fips.h
fips_des_selftest.o: ../../include/openssl/lhash.h
fips_des_selftest.o: ../../include/openssl/obj_mac.h
fips_des_selftest.o: ../../include/openssl/objects.h
fips_des_selftest.o: ../../include/openssl/opensslconf.h
fips_des_selftest.o: ../../include/openssl/opensslv.h
fips_des_selftest.o: ../../include/openssl/ossl_typ.h
fips_des_selftest.o: ../../include/openssl/safestack.h
fips_des_selftest.o: ../../include/openssl/stack.h
fips_des_selftest.o: ../../include/openssl/symhacks.h fips_des_selftest.c
fips_drbg_ctr.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
fips_drbg_ctr.o: ../../include/openssl/bio.h ../../include/openssl/crypto.h
fips_drbg_ctr.o: ../../include/openssl/e_os2.h ../../include/openssl/evp.h
fips_drbg_ctr.o: ../../include/openssl/fips.h ../../include/openssl/fips_rand.h
fips_drbg_ctr.o: ../../include/openssl/hmac.h ../../include/openssl/obj_mac.h
fips_drbg_ctr.o: ../../include/openssl/objects.h
fips_drbg_ctr.o: ../../include/openssl/opensslconf.h
fips_drbg_ctr.o: ../../include/openssl/opensslv.h
fips_drbg_ctr.o: ../../include/openssl/ossl_typ.h ../../include/openssl/rand.h
fips_drbg_ctr.o: ../../include/openssl/safestack.h
fips_drbg_ctr.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
fips_drbg_ctr.o: fips_drbg_ctr.c fips_rand_lcl.h
fips_drbg_hash.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
fips_drbg_hash.o: ../../include/openssl/bio.h ../../include/openssl/crypto.h
fips_drbg_hash.o: ../../include/openssl/e_os2.h ../../include/openssl/evp.h
fips_drbg_hash.o: ../../include/openssl/fips.h
fips_drbg_hash.o: ../../include/openssl/fips_rand.h
fips_drbg_hash.o: ../../include/openssl/hmac.h ../../include/openssl/obj_mac.h
fips_drbg_hash.o: ../../include/openssl/objects.h
fips_drbg_hash.o: ../../include/openssl/opensslconf.h
fips_drbg_hash.o: ../../include/openssl/opensslv.h
fips_drbg_hash.o: ../../include/openssl/ossl_typ.h ../../include/openssl/rand.h
fips_drbg_hash.o: ../../include/openssl/safestack.h
fips_drbg_hash.o: ../../include/openssl/stack.h
fips_drbg_hash.o: ../../include/openssl/symhacks.h fips_drbg_hash.c
fips_drbg_hash.o: fips_rand_lcl.h
fips_drbg_hmac.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
fips_drbg_hmac.o: ../../include/openssl/bio.h ../../include/openssl/crypto.h
fips_drbg_hmac.o: ../../include/openssl/e_os2.h ../../include/openssl/evp.h
fips_drbg_hmac.o: ../../include/openssl/fips.h
fips_drbg_hmac.o: ../../include/openssl/fips_rand.h
fips_drbg_hmac.o: ../../include/openssl/hmac.h ../../include/openssl/obj_mac.h
fips_drbg_hmac.o: ../../include/openssl/objects.h
fips_drbg_hmac.o: ../../include/openssl/opensslconf.h
fips_drbg_hmac.o: ../../include/openssl/opensslv.h
fips_drbg_hmac.o: ../../include/openssl/ossl_typ.h ../../include/openssl/rand.h
fips_drbg_hmac.o: ../../include/openssl/safestack.h
fips_drbg_hmac.o: ../../include/openssl/stack.h
fips_drbg_hmac.o: ../../include/openssl/symhacks.h fips_drbg_hmac.c
fips_drbg_hmac.o: fips_rand_lcl.h
fips_drbg_lib.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
fips_drbg_lib.o: ../../include/openssl/bio.h ../../include/openssl/crypto.h
fips_drbg_lib.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
fips_drbg_lib.o: ../../include/openssl/evp.h ../../include/openssl/fips.h
fips_drbg_lib.o: ../../include/openssl/fips_rand.h ../../include/openssl/hmac.h
fips_drbg_lib.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
fips_drbg_lib.o: ../../include/openssl/objects.h
fips_drbg_lib.o: ../../include/openssl/opensslconf.h
fips_drbg_lib.o: ../../include/openssl/opensslv.h
fips_drbg_lib.o: ../../include/openssl/ossl_typ.h ../../include/openssl/rand.h
fips_drbg_lib.o: ../../include/openssl/safestack.h
fips_drbg_lib.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
fips_drbg_lib.o: fips_drbg_lib.c fips_locl.h fips_rand_lcl.h
fips_drbg_rand.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
fips_drbg_rand.o: ../../include/openssl/bio.h ../../include/openssl/crypto.h
fips_drbg_rand.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
fips_drbg_rand.o: ../../include/openssl/evp.h ../../include/openssl/fips.h
fips_drbg_rand.o: ../../include/openssl/fips_rand.h
fips_drbg_rand.o: ../../include/openssl/hmac.h ../../include/openssl/lhash.h
fips_drbg_rand.o: ../../include/openssl/obj_mac.h
fips_drbg_rand.o: ../../include/openssl/objects.h
fips_drbg_rand.o: ../../include/openssl/opensslconf.h
fips_drbg_rand.o: ../../include/openssl/opensslv.h
fips_drbg_rand.o: ../../include/openssl/ossl_typ.h ../../include/openssl/rand.h
fips_drbg_rand.o: ../../include/openssl/safestack.h
fips_drbg_rand.o: ../../include/openssl/stack.h
fips_drbg_rand.o: ../../include/openssl/symhacks.h fips_drbg_rand.c
fips_drbg_rand.o: fips_rand_lcl.h
fips_drbg_selftest.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
fips_drbg_selftest.o: ../../include/openssl/bio.h
fips_drbg_selftest.o: ../../include/openssl/crypto.h
fips_drbg_selftest.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
fips_drbg_selftest.o: ../../include/openssl/evp.h ../../include/openssl/fips.h
fips_drbg_selftest.o: ../../include/openssl/fips_rand.h
fips_drbg_selftest.o: ../../include/openssl/hmac.h
fips_drbg_selftest.o: ../../include/openssl/lhash.h
fips_drbg_selftest.o: ../../include/openssl/obj_mac.h
fips_drbg_selftest.o: ../../include/openssl/objects.h
fips_drbg_selftest.o: ../../include/openssl/opensslconf.h
fips_drbg_selftest.o: ../../include/openssl/opensslv.h
fips_drbg_selftest.o: ../../include/openssl/ossl_typ.h
fips_drbg_selftest.o: ../../include/openssl/rand.h
fips_drbg_selftest.o: ../../include/openssl/safestack.h
fips_drbg_selftest.o: ../../include/openssl/stack.h
fips_drbg_selftest.o: ../../include/openssl/symhacks.h fips_drbg_selftest.c
fips_drbg_selftest.o: fips_drbg_selftest.h fips_locl.h fips_rand_lcl.h
fips_dsa_selftest.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
fips_dsa_selftest.o: ../../include/openssl/bn.h ../../include/openssl/crypto.h
fips_dsa_selftest.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
fips_dsa_selftest.o: ../../include/openssl/err.h ../../include/openssl/evp.h
fips_dsa_selftest.o: ../../include/openssl/fips.h ../../include/openssl/lhash.h
fips_dsa_selftest.o: ../../include/openssl/obj_mac.h
fips_dsa_selftest.o: ../../include/openssl/objects.h
fips_dsa_selftest.o: ../../include/openssl/opensslconf.h
fips_dsa_selftest.o: ../../include/openssl/opensslv.h
fips_dsa_selftest.o: ../../include/openssl/ossl_typ.h
fips_dsa_selftest.o: ../../include/openssl/safestack.h
fips_dsa_selftest.o: ../../include/openssl/stack.h
fips_dsa_selftest.o: ../../include/openssl/symhacks.h fips_dsa_selftest.c
fips_dsa_selftest.o: fips_locl.h
fips_ecdh_selftest.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
fips_ecdh_selftest.o: ../../include/openssl/bn.h ../../include/openssl/crypto.h
fips_ecdh_selftest.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
fips_ecdh_selftest.o: ../../include/openssl/ecdh.h ../../include/openssl/err.h
fips_ecdh_selftest.o: ../../include/openssl/evp.h ../../include/openssl/fips.h
fips_ecdh_selftest.o: ../../include/openssl/lhash.h
fips_ecdh_selftest.o: ../../include/openssl/obj_mac.h
fips_ecdh_selftest.o: ../../include/openssl/objects.h
fips_ecdh_selftest.o: ../../include/openssl/opensslconf.h
fips_ecdh_selftest.o: ../../include/openssl/opensslv.h
fips_ecdh_selftest.o: ../../include/openssl/ossl_typ.h
fips_ecdh_selftest.o: ../../include/openssl/safestack.h
fips_ecdh_selftest.o: ../../include/openssl/stack.h
fips_ecdh_selftest.o: ../../include/openssl/symhacks.h fips_ecdh_selftest.c
fips_ecdh_selftest.o: fips_locl.h
fips_ecdsa_selftest.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
fips_ecdsa_selftest.o: ../../include/openssl/bn.h
fips_ecdsa_selftest.o: ../../include/openssl/crypto.h
fips_ecdsa_selftest.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
fips_ecdsa_selftest.o: ../../include/openssl/ecdsa.h
fips_ecdsa_selftest.o: ../../include/openssl/err.h ../../include/openssl/evp.h
fips_ecdsa_selftest.o: ../../include/openssl/fips.h
fips_ecdsa_selftest.o: ../../include/openssl/lhash.h
fips_ecdsa_selftest.o: ../../include/openssl/obj_mac.h
fips_ecdsa_selftest.o: ../../include/openssl/objects.h
fips_ecdsa_selftest.o: ../../include/openssl/opensslconf.h
fips_ecdsa_selftest.o: ../../include/openssl/opensslv.h
fips_ecdsa_selftest.o: ../../include/openssl/ossl_typ.h
fips_ecdsa_selftest.o: ../../include/openssl/safestack.h
fips_ecdsa_selftest.o: ../../include/openssl/stack.h
fips_ecdsa_selftest.o: ../../include/openssl/symhacks.h fips_ecdsa_selftest.c
fips_enc.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
fips_enc.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
fips_enc.o: ../../include/openssl/err.h ../../include/openssl/evp.h
fips_enc.o: ../../include/openssl/fips.h ../../include/openssl/lhash.h
fips_enc.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
fips_enc.o: ../../include/openssl/opensslconf.h
fips_enc.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
fips_enc.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
fips_enc.o: ../../include/openssl/symhacks.h fips_enc.c
fips_hmac_selftest.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
fips_hmac_selftest.o: ../../include/openssl/crypto.h
fips_hmac_selftest.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
fips_hmac_selftest.o: ../../include/openssl/evp.h ../../include/openssl/fips.h
fips_hmac_selftest.o: ../../include/openssl/hmac.h
fips_hmac_selftest.o: ../../include/openssl/lhash.h
fips_hmac_selftest.o: ../../include/openssl/obj_mac.h
fips_hmac_selftest.o: ../../include/openssl/objects.h
fips_hmac_selftest.o: ../../include/openssl/opensslconf.h
fips_hmac_selftest.o: ../../include/openssl/opensslv.h
fips_hmac_selftest.o: ../../include/openssl/ossl_typ.h
fips_hmac_selftest.o: ../../include/openssl/safestack.h
fips_hmac_selftest.o: ../../include/openssl/stack.h
fips_hmac_selftest.o: ../../include/openssl/symhacks.h fips_hmac_selftest.c
fips_md.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
fips_md.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
fips_md.o: ../../include/openssl/err.h ../../include/openssl/evp.h
fips_md.o: ../../include/openssl/fips.h ../../include/openssl/lhash.h
fips_md.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
fips_md.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
fips_md.o: ../../include/openssl/ossl_typ.h ../../include/openssl/safestack.h
fips_md.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
fips_md.o: fips_md.c
fips_post.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
fips_post.o: ../../include/openssl/bio.h ../../include/openssl/crypto.h
fips_post.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
fips_post.o: ../../include/openssl/err.h ../../include/openssl/evp.h
fips_post.o: ../../include/openssl/fips.h ../../include/openssl/fips_rand.h
fips_post.o: ../../include/openssl/hmac.h ../../include/openssl/lhash.h
fips_post.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
fips_post.o: ../../include/openssl/opensslconf.h
fips_post.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
fips_post.o: ../../include/openssl/rand.h ../../include/openssl/rsa.h
fips_post.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
fips_post.o: ../../include/openssl/symhacks.h fips_locl.h fips_post.c
fips_rand.o: ../../e_os.h ../../include/openssl/aes.h
fips_rand.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
fips_rand.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
fips_rand.o: ../../include/openssl/err.h ../../include/openssl/evp.h
fips_rand.o: ../../include/openssl/fips.h ../../include/openssl/fips_rand.h
fips_rand.o: ../../include/openssl/hmac.h ../../include/openssl/lhash.h
fips_rand.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
fips_rand.o: ../../include/openssl/opensslconf.h
fips_rand.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
fips_rand.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
fips_rand.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
fips_rand.o: fips_locl.h fips_rand.c
fips_rand_lib.o: ../../e_os.h ../../include/openssl/aes.h
fips_rand_lib.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
fips_rand_lib.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
fips_rand_lib.o: ../../include/openssl/err.h ../../include/openssl/evp.h
fips_rand_lib.o: ../../include/openssl/fips.h ../../include/openssl/fips_rand.h
fips_rand_lib.o: ../../include/openssl/hmac.h ../../include/openssl/lhash.h
fips_rand_lib.o: ../../include/openssl/obj_mac.h
fips_rand_lib.o: ../../include/openssl/objects.h
fips_rand_lib.o: ../../include/openssl/opensslconf.h
fips_rand_lib.o: ../../include/openssl/opensslv.h
fips_rand_lib.o: ../../include/openssl/ossl_typ.h ../../include/openssl/rand.h
fips_rand_lib.o: ../../include/openssl/safestack.h
fips_rand_lib.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
fips_rand_lib.o: fips_rand_lib.c
fips_rand_selftest.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
fips_rand_selftest.o: ../../include/openssl/bio.h
fips_rand_selftest.o: ../../include/openssl/crypto.h
fips_rand_selftest.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
fips_rand_selftest.o: ../../include/openssl/evp.h ../../include/openssl/fips.h
fips_rand_selftest.o: ../../include/openssl/fips_rand.h
fips_rand_selftest.o: ../../include/openssl/hmac.h
fips_rand_selftest.o: ../../include/openssl/lhash.h
fips_rand_selftest.o: ../../include/openssl/obj_mac.h
fips_rand_selftest.o: ../../include/openssl/objects.h
fips_rand_selftest.o: ../../include/openssl/opensslconf.h
fips_rand_selftest.o: ../../include/openssl/opensslv.h
fips_rand_selftest.o: ../../include/openssl/ossl_typ.h
fips_rand_selftest.o: ../../include/openssl/rand.h
fips_rand_selftest.o: ../../include/openssl/safestack.h
fips_rand_selftest.o: ../../include/openssl/stack.h
fips_rand_selftest.o: ../../include/openssl/symhacks.h fips_locl.h
fips_rand_selftest.o: fips_rand_selftest.c
fips_rsa_selftest.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
fips_rsa_selftest.o: ../../include/openssl/bn.h ../../include/openssl/crypto.h
fips_rsa_selftest.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
fips_rsa_selftest.o: ../../include/openssl/evp.h ../../include/openssl/fips.h
fips_rsa_selftest.o: ../../include/openssl/lhash.h
fips_rsa_selftest.o: ../../include/openssl/obj_mac.h
fips_rsa_selftest.o: ../../include/openssl/objects.h
fips_rsa_selftest.o: ../../include/openssl/opensslconf.h
fips_rsa_selftest.o: ../../include/openssl/opensslv.h
fips_rsa_selftest.o: ../../include/openssl/ossl_typ.h
fips_rsa_selftest.o: ../../include/openssl/rsa.h
fips_rsa_selftest.o: ../../include/openssl/safestack.h
fips_rsa_selftest.o: ../../include/openssl/stack.h
fips_rsa_selftest.o: ../../include/openssl/symhacks.h fips_rsa_selftest.c
fips_rsa_x931g.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
fips_rsa_x931g.o: ../../include/openssl/bn.h ../../include/openssl/crypto.h
fips_rsa_x931g.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
fips_rsa_x931g.o: ../../include/openssl/fips.h ../../include/openssl/lhash.h
fips_rsa_x931g.o: ../../include/openssl/opensslconf.h
fips_rsa_x931g.o: ../../include/openssl/opensslv.h
fips_rsa_x931g.o: ../../include/openssl/ossl_typ.h ../../include/openssl/rsa.h
fips_rsa_x931g.o: ../../include/openssl/safestack.h
fips_rsa_x931g.o: ../../include/openssl/stack.h
fips_rsa_x931g.o: ../../include/openssl/symhacks.h fips_rsa_x931g.c
fips_sha_selftest.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
fips_sha_selftest.o: ../../include/openssl/crypto.h
fips_sha_selftest.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
fips_sha_selftest.o: ../../include/openssl/evp.h ../../include/openssl/fips.h
fips_sha_selftest.o: ../../include/openssl/lhash.h
fips_sha_selftest.o: ../../include/openssl/obj_mac.h
fips_sha_selftest.o: ../../include/openssl/objects.h
fips_sha_selftest.o: ../../include/openssl/opensslconf.h
fips_sha_selftest.o: ../../include/openssl/opensslv.h
fips_sha_selftest.o: ../../include/openssl/ossl_typ.h
fips_sha_selftest.o: ../../include/openssl/safestack.h
fips_sha_selftest.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
fips_sha_selftest.o: ../../include/openssl/symhacks.h fips_sha_selftest.c
