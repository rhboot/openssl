%define m2crypto_version 0.05-snap4
%define swig_version 1.1p5
%define soversion 1

Summary: Secure Sockets Layer Toolkit
Name: openssl
Version: 0.9.6
Release: 10
Source: openssl-%{version}-usa.tar.bz2
Source1: hobble-openssl
Source2: Makefile.certificate
Source3: http://download.sourceforge.net/swig/swig%{swig_version}.tar.gz
Source4: http://mars.post1.com/home/ngps/m2/m2crypto-%{m2crypto_version}.zip
Source5: ca-bundle.crt
Source6: RHNS-CA-CERT
Patch0: openssl-0.9.6-redhat.patch
Patch1: openssl-0.9.5-rsanull.patch
Patch2: openssl-0.9.5a-64.patch
Patch3: openssl-0.9.5a-defaults.patch
Patch4: openssl-0.9.5a-ia64.patch
Patch5: openssl-0.9.5a-glibc.patch
Patch6: openssl-0.9.6-soversion.patch
Patch7: m2crypto-0.05-snap4-include.patch
Patch8: openssl-0.9.6-bleichenbacher.patch
Patch9: openssl-crt.patch
Patch10: openssl-setugid.patch
Patch11: openssl-zero-premaster.patch
Patch12: openssl-0.9.6-memmove.patch
Patch13: openssl096a-prng.patch
Patch14: openssl096a-prng-2.patch
Patch15: openssl-0.9.6b-sec.patch
License: BSDish
Group: System Environment/Libraries
URL: http://www.openssl.org/
BuildRoot: %{_tmppath}/%{name}-%{version}-root
BuildPreReq: perl, python-devel, unzip

%description
The OpenSSL certificate management tool and the shared libraries that
provide various cryptographic algorithms and protocols.

%package devel
Summary: OpenSSL libraries and development headers.
Group: Development/Libraries
Requires: %{name} = %{version}-%{release}

%description devel
The static libraries and include files needed to compile apps
with support for various cryptographic algorithms and protocols.

Patches for many networking apps can be found at:
ftp://ftp.psy.uq.oz.au/pub/Crypto/SSLapps/

%package perl
Summary: OpenSSL scripts which require Perl.
Group: Applications/Internet
Requires: perl
Requires: %{name} = %{version}-%{release}

%description perl
Perl scripts provided with OpenSSL for converting certificates and keys
from other formats to those used by OpenSSL.

%package python
Summary: Support for using OpenSSL in python scripts.
Group: Applications/Internet
Requires: python
Requires: %{name} = %{version}-%{release}

%description python
This package allows you to call OpenSSL functions from python scripts.

%prep
%setup -q
%{SOURCE1}
%patch0 -p1 -b .redhat
%patch1 -p1 -b .rsanull
%ifarch alpha ia64
%patch2 -p1 -b .64
%endif
%patch3 -p1 -b .defaults
%patch4 -p1 -b .ia64
%patch5 -p1 -b .glibc
%patch6 -p1 -b .soversion

# Extract what we need for building extensions.
gzip -dc %{SOURCE3} | tar xf -
unzip -q %{SOURCE4}
pushd m2crypto-%{m2crypto_version}
%patch7 -p1 -b .include
    for file in demo/evp_ciph_test.py demo/bio_ciph_test.py swig/_evp.i ; do
	grep -v idea_ ${file} > ${file}.tmp
	grep -v rc5_  ${file}.tmp > ${file}
    done
popd
%patch8  -p1 -b .bleichenbacher
%patch9  -p1 -b .crt
%patch10 -p1 -b .setugid
%patch11 -p1 -b .zero-premaster
%patch12 -p1 -b .memmove
pushd crypto/rand
%patch13 -p0 -b .rand
popd
pushd doc/crypto
%patch14 -p0 -b .rand-2
popd
%patch15 -p0 -b .sec

chmod 644 FAQ LICENSE CHANGES NEWS INSTALL README
chmod 644 doc/README doc/c-indentation.el doc/openssl.txt
chmod 644 doc/openssl_button.html doc/openssl_button.gif
chmod 644 doc/ssleay.txt

# Link the configuration header to the one we're going to make.
ln -sf ../../crypto/opensslconf.h include/openssl/
# Link the ssl.h header to the one we're going to make.
ln -sf ../../ssl/ssl.h include/openssl/

%build 
PATH=${PATH}:${PWD}/bin
TOPDIR=${PWD}
LD_LIBRARY_PATH=${TOPDIR}:${PATH} ; export LD_LIBRARY_PATH

# Figure out which flags we want to use.  Assembly is broken on some platforms,
# required on others.
perl util/perlpath.pl `dirname %{__perl}`
%ifarch %ix86
sslarch=linux-elf
sslflags=no-asm
%endif
%ifarch sparc
sslarch=linux-sparcv9
sslflags=no-asm
%endif
%ifarch ia64
sslarch=linux-ia64
sslflags=no-asm
RPM_OPT_FLAGS="$RPM_OPT_FLAGS -O1"
%endif
%ifarch alpha
sslarch=alpha-gcc
sslflags=no-asm
%endif
%ifarch s390
sslarch=linux-s390
%endif
# Configure the build tree.  Override OpenSSL defaults with known-good defaults
# usable on all platforms.  The Configure script already knows to use -fPIC and
# RPM_OPT_FLAGS, so we can skip specifiying them here.
./config --prefix=%{_prefix} --openssldir=%{_datadir}/ssl ${sslflags} no-idea no-mdc2 no-rc5
make all libcrypto.so libssl.so

# Build the Perl bindings.
#pushd perl
#perl Makefile.PL
#make
#popd

# Verify that what was compiled actually works.
make -C test apps tests

# Build a copy of swig with which to build the extensions.
pushd SWIG%{swig_version}
autoconf
./configure --prefix=${TOPDIR}
make all install
popd

# Build the python extensions.
pushd m2crypto-%{m2crypto_version}/swig
export PATH=`pwd`/../../bin:$PATH
make \
	INCLUDE="-I. -I../../include" \
	LIBS="-L${TOPDIR} -lssl -lcrypto -lc" \
	PYINCLUDE="-DHAVE_CONFIG_H -I/usr/include/python1.5 -I/usr/lib/python1.5/config" \
	PYLIB=/usr/lib/python1.5/config
cd ../doc
sh -x go
popd

# Relink the main binary to get it dynamically linked.
rm apps/openssl
make all

%install
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT
# Install OpenSSL.
install -d $RPM_BUILD_ROOT{%{_bindir},%{_includedir},%{_libdir},%{_mandir}}
make INSTALL_PREFIX=$RPM_BUILD_ROOT install
mv $RPM_BUILD_ROOT%{_datadir}/ssl/man/* $RPM_BUILD_ROOT%{_mandir}
rmdir $RPM_BUILD_ROOT%{_datadir}/ssl/man
install -m 755 *.so.* $RPM_BUILD_ROOT%{_libdir}
for lib in $RPM_BUILD_ROOT%{_libdir}/*.so.%{version} ; do
	ln -s -f `basename ${lib}` $RPM_BUILD_ROOT%{_libdir}/`basename ${lib} .%{version}`
done

mkdir -p $RPM_BUILD_ROOT%{_datadir}/ssl/certs
install -m644 $RPM_SOURCE_DIR/Makefile.certificate $RPM_BUILD_ROOT%{_datadir}/ssl/certs/Makefile

strip    $RPM_BUILD_ROOT%{_bindir}/*    ||:
strip -g $RPM_BUILD_ROOT%{_libdir}/lib* ||:

# Make sure we actually include the headers we built against.
for header in $RPM_BUILD_ROOT%{_includedir}/openssl/* ; do
	if [ -f ${header} -a -f include/openssl/$(basename ${header}) ] ; then
		install -m644 include/openssl/`basename ${header}` ${header}
	fi
done

# Fudge this.
mv $RPM_BUILD_ROOT%{_mandir}/man1/passwd.1 $RPM_BUILD_ROOT%{_mandir}/man1/sslpasswd.1
mv $RPM_BUILD_ROOT%{_mandir}/man3/rand.3 $RPM_BUILD_ROOT%{_mandir}/man3/sslrand.3

# Pick a CA script.
pushd  $RPM_BUILD_ROOT%{_datadir}/ssl/misc
mv CA.sh CA
mv der_chop der_chop.pl
popd

# Install root CA stuffs.
cat << EOF > RHNS-blurb.txt
#
#  RHNS CA certificate.  Appended to the ca-bundle at package build-time.
#
EOF
cat %{SOURCE5} RHNS-blurb.txt %{SOURCE6} > ca-bundle.crt
install -m644 ca-bundle.crt $RPM_BUILD_ROOT%{_datadir}/ssl/certs/
ln -s certs/ca-bundle.crt $RPM_BUILD_ROOT%{_datadir}/ssl/cert.pem

# Install the python extensions.
pushd m2crypto-%{m2crypto_version}/M2Crypto
mkdir -p $RPM_BUILD_ROOT/usr/lib/python1.5/site-packages/M2Crypto/{PGP,SSL}
find -name "*.py" | xargs -i install -m644 '{}' $RPM_BUILD_ROOT/usr/lib/python1.5/site-packages/M2Crypto/'{}'
find -name "*.so" | xargs -i install -m755 '{}' $RPM_BUILD_ROOT/usr/lib/python1.5/site-packages/M2Crypto/'{}'
python -c "import compileall; compileall.compile_dir('"$RPM_BUILD_ROOT/usr/lib/python1.5/site-packages/M2Crypto"', 3, '/usr/lib/python1.5/site-packages/M2Crypto')"
popd

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

%files 
%defattr(-,root,root)
%doc FAQ LICENSE CHANGES NEWS INSTALL README
%doc doc/README doc/c-indentation.el doc/openssl.txt
%doc doc/openssl_button.html doc/openssl_button.gif
%doc doc/ssleay.txt
%dir %{_datadir}/ssl
%{_datadir}/ssl/certs
%{_datadir}/ssl/cert.pem
%{_datadir}/ssl/lib
%{_datadir}/ssl/misc/CA
%{_datadir}/ssl/misc/c_*
%{_datadir}/ssl/private

%config %{_datadir}/ssl/openssl.cnf

%attr(0755,root,root) %{_bindir}/openssl
%attr(0755,root,root) %{_libdir}/*.so.%{version}
%attr(0644,root,root) %{_mandir}/man1/[a-z]*
%attr(0644,root,root) %{_mandir}/man5/*
%attr(0644,root,root) %{_mandir}/man7/*

%files devel
%defattr(-,root,root)
%{_prefix}/include/openssl
%attr(0644,root,root) %{_libdir}/*.a
%attr(0755,root,root) %{_libdir}/*.so
%attr(0644,root,root) %{_mandir}/man3/*

%files perl
%defattr(-,root,root)
%attr(0755,root,root) %{_bindir}/c_rehash
%attr(0644,root,root) %{_mandir}/man1/*.pl*
%{_datadir}/ssl/misc/*.pl

%files python
%defattr(-,root,root)
%doc m2crypto-%{m2crypto_version}/{BUGS,CHANGES,LIC*,README,TODO}
%doc m2crypto-%{m2crypto_version}/doc/{README,*.html}
%{_libdir}/python1.5/site-packages/M2Crypto

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%changelog
* Thu Jul 25 2002 Nalin Dahyabhai <nalin@redhat.com> 0.9.6-10
- add backport of Ben Laurie's patches for OpenSSL 0.9.6d

* Wed Jul 11 2001 Nalin Dahyabhai <nalin@redhat.com>
- add patches to fix PRNG flaws, supplied by Bodo Moeller and the OpenSSL Group

* Fri Jun  1 2001 Nalin Dahyabhai <nalin@redhat.com>
- change two memcpy() calls to memmove()

* Sun May 27 2001 Philip Copeland <bryce@redhat.com>
- Removed -DL_ENDIAN for the alpha builds as unsigned long = 8 not 4
  which both L_ENDIAN / B_ENDIAN require to work correctly

* Tue May 15 2001 Nalin Dahyabhai <nalin@redhat.com>
- make subpackages depend on the main package

* Thu Apr 26 2001 Nalin Dahyabhai <nalin@redhat.com>
- rebuild

* Fri Apr 20 2001 Nalin Dahyabhai <nalin@redhat.com>
- use __libc_enable_secure in OPENSSL_setugid (suggested by solar@openwall.com)
- make backported OPENSSL_setugid, BN_bntest_rand, and BN_rand_range static
  functions, which keeps them away from client applications more cleanly

* Tue Apr 17 2001 Nalin Dahyabhai <nalin@redhat.com>
- backport security fixes from 0.9.6a

* Tue Mar 13 2001 Nalin Dahyabhai <nalin@redhat.com>
- use BN_LLONG on s390

* Mon Mar 12 2001 Nalin Dahyabhai <nalin@redhat.com>
- fix the s390 changes for 0.9.6 (isn't supposed to be marked as 64-bit)

* Sat Mar  3 2001 Nalin Dahyabhai <nalin@redhat.com>
- move c_rehash to the perl subpackage, because it's a perl script now

* Fri Mar  2 2001 Nalin Dahyabhai <nalin@redhat.com>
- update to 0.9.6
- enable MD2
- use the libcrypto.so and libssl.so targets to build shared libs with
- bump the soversion to 1 because we're no longer compatible with any of
  the various 0.9.5a packages circulating around, which provide lib*.so.0

* Wed Feb 28 2001 Florian La Roche <Florian.LaRoche@redhat.de>
- change hobble-openssl for disabling MD2 again

* Tue Feb 27 2001 Nalin Dahyabhai <nalin@redhat.com>
- re-disable MD2 -- the EVP_MD_CTX structure would grow from 100 to 152
  bytes or so, causing EVP_DigestInit() to zero out stack variables in
  apps built against a version of the library without it

* Mon Feb 26 2001 Nalin Dahyabhai <nalin@redhat.com>
- disable some inline assembly, which on x86 is Pentium-specific
- re-enable MD2 (see http://www.ietf.org/ietf/IPR/RSA-MD-all)

* Thu Feb 08 2001 Florian La Roche <Florian.LaRoche@redhat.de>
- fix s390 patch

* Fri Dec 8 2000 Than Ngo <than@redhat.com>
- added support s390

* Mon Nov 20 2000 Nalin Dahyabhai <nalin@redhat.com>
- remove -Wa,* and -m* compiler flags from the default Configure file (#20656)
- add the CA.pl man page to the perl subpackage

* Thu Nov  2 2000 Nalin Dahyabhai <nalin@redhat.com>
- always build with -mcpu=ev5 on alpha

* Tue Oct 31 2000 Nalin Dahyabhai <nalin@redhat.com>
- add a symlink from cert.pem to ca-bundle.crt

* Wed Oct 25 2000 Nalin Dahyabhai <nalin@redhat.com>
- add a ca-bundle file for packages like Samba to reference for CA certificates

* Tue Oct 24 2000 Nalin Dahyabhai <nalin@redhat.com>
- remove libcrypto's crypt(), which doesn't handle md5crypt (#19295)

* Mon Oct  2 2000 Nalin Dahyabhai <nalin@redhat.com>
- add unzip as a buildprereq (#17662)
- update m2crypto to 0.05-snap4

* Tue Sep 26 2000 Bill Nottingham <notting@redhat.com>
- fix some issues in building when it's not installed

* Wed Sep  6 2000 Nalin Dahyabhai <nalin@redhat.com>
- make sure the headers we include are the ones we built with (aaaaarrgh!)

* Fri Sep  1 2000 Nalin Dahyabhai <nalin@redhat.com>
- add Richard Henderson's patch for BN on ia64
- clean up the changelog

* Tue Aug 29 2000 Nalin Dahyabhai <nalin@redhat.com>
- fix the building of python modules without openssl-devel already installed

* Wed Aug 23 2000 Nalin Dahyabhai <nalin@redhat.com>
- byte-compile python extensions without the build-root
- adjust the makefile to not remove temporary files (like .key files when
  building .csr files) by marking them as .PRECIOUS

* Sat Aug 19 2000 Nalin Dahyabhai <nalin@redhat.com>
- break out python extensions into a subpackage

* Mon Jul 17 2000 Nalin Dahyabhai <nalin@redhat.com>
- tweak the makefile some more

* Tue Jul 11 2000 Nalin Dahyabhai <nalin@redhat.com>
- disable MD2 support

* Thu Jul  6 2000 Nalin Dahyabhai <nalin@redhat.com>
- disable MDC2 support

* Sun Jul  2 2000 Nalin Dahyabhai <nalin@redhat.com>
- tweak the disabling of RC5, IDEA support
- tweak the makefile

* Thu Jun 29 2000 Nalin Dahyabhai <nalin@redhat.com>
- strip binaries and libraries
- rework certificate makefile to have the right parts for Apache

* Wed Jun 28 2000 Nalin Dahyabhai <nalin@redhat.com>
- use %%{_perl} instead of /usr/bin/perl
- disable alpha until it passes its own test suite

* Fri Jun  9 2000 Nalin Dahyabhai <nalin@redhat.com>
- move the passwd.1 man page out of the passwd package's way

* Fri Jun  2 2000 Nalin Dahyabhai <nalin@redhat.com>
- update to 0.9.5a, modified for U.S.
- add perl as a build-time requirement
- move certificate makefile to another package
- disable RC5, IDEA, RSA support
- remove optimizations for now

* Wed Mar  1 2000 Florian La Roche <Florian.LaRoche@redhat.de>
- Bero told me to move the Makefile into this package

* Wed Mar  1 2000 Florian La Roche <Florian.LaRoche@redhat.de>
- add lib*.so symlinks to link dynamically against shared libs

* Tue Feb 29 2000 Florian La Roche <Florian.LaRoche@redhat.de>
- update to 0.9.5
- run ldconfig directly in post/postun
- add FAQ

* Sat Dec 18 1999 Bernhard Rosenkr)Bänzer <bero@redhat.de>
- Fix build on non-x86 platforms

* Fri Nov 12 1999 Bernhard Rosenkr)Bänzer <bero@redhat.de>
- move /usr/share/ssl/* from -devel to main package

* Tue Oct 26 1999 Bernhard Rosenkr)Bänzer <bero@redhat.de>
- inital packaging
- changes from base:
  - Move /usr/local/ssl to /usr/share/ssl for FHS compliance
  - handle RPM_OPT_FLAGS
