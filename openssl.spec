%define soversion 2

Summary: The OpenSSL toolkit.
Name: openssl
Version: 0.9.6b
Release: 33
Source: openssl-engine-%{version}-usa.tar.bz2
Source1: hobble-openssl
Source2: Makefile.certificate
Source3: ca-bundle.crt
Source4: RHNS-CA-CERT
Source5: make-dummy-cert
Source6: hw_ubsec.c
Source7: hw_ubsec.h
Source8: ia64.S
Patch0: openssl-engine-0.9.6b-redhat.patch
Patch1: openssl-0.9.5a-64.patch
Patch2: openssl-engine-0.9.6b-defaults.patch
Patch3: openssl-0.9.5a-ia64.patch
Patch4: openssl-0.9.5a-glibc.patch
Patch5: openssl-0.9.6a-soversion.patch
Patch6: openssl-engine-0.9.6b-add-aep.patch
Patch7: openssl-engine-0.9.6b-hw_ubsec.patch
Patch8: openssl-0.9.6-x509.patch
Patch9: openssl-engine-0.9.6b-default-engine.patch
Patch10: openssl-engine-0.9.6b-ubsec_failover.patch
Patch11: openssl-engine-0.9.6b-ubsec_rand.patch
Patch12: openssl-0.9.6b-mkdepend.patch
Patch13: openssl-0.9.6a-conf.patch
Patch14: openssl-0.9.6a-add-engine-version.patch
Patch15: openssl-0.9.6a-add-ia64-asm.patch
Patch16: openssl-0.9.6a-add-baltimore.patch
Patch17: openssl-0.9.6c-aep.patch
Patch18: openssl-0.9.6c-add-luna.patch
Patch19: openssl-0.9.6b-sec.patch
Patch20: openssl-0.9.6c-asn.patch.3
Patch21: openssl-engine-0.9.6b-4096.patch
Patch22: openssl-0.9.6-malloc-negative.patch
Patch23: openssl-0.9.6-vaudenay.patch
Patch24: openssl-sec3-blinding-0.9.6b.patch
Patch25: openssl-0.9.7a-klima-pokorny-rosa.patch
License: BSDish
Group: System Environment/Libraries
URL: http://www.openssl.org/
BuildRoot: %{_tmppath}/%{name}-%{version}-root
BuildPreReq: perl, sed
Requires: mktemp

%define solibbase %(echo %version | sed 's/[[:alpha:]]//g')

%description
The OpenSSL toolkit provides support for secure communications between
machines. OpenSSL includes a certificate management tool and shared
libraries which provide various cryptographic algorithms and
protocols.

%package devel
Summary: Files for development of applications which will use OpenSSL.
Group: Development/Libraries
Requires: %{name} = %{version}-%{release}

%description devel
OpenSSL is a toolkit for supporting cryptography. The openssl-devel
package contains static libraries and include files needed to develop
applications which support various cryptographic algorithms and
protocols.

%package perl
Summary: Perl scripts provided with OpenSSL.
Group: Applications/Internet
Requires: perl
Requires: %{name} = %{version}-%{release}

%description perl
OpenSSL is a toolkit for supporting cryptography. The openssl-perl
package provides Perl scripts for converting certificates and keys
from other formats to the formats used by the OpenSSL toolkit.

%prep
%setup -q -n openssl-engine-%{version}
%{SOURCE1}
cp %{SOURCE6} crypto/engine/
cp %{SOURCE7} crypto/engine/vendor_defns/
cp %{SOURCE8} crypto/bn/asm/
%patch0 -p1 -b .redhat
%patch1 -p1 -b .64
%patch2 -p1 -b .defaults
%patch3 -p1 -b .ia64
%patch4 -p1 -b .glibc
%patch5 -p1 -b .soversion
%patch6 -p1 -b .add-aep
%patch7 -p1 -b .hw_ubsec
%patch8 -p1 -b .x509
%patch9 -p1 -b .default-engine
%patch10 -p1 -b .ubsec_failover
%patch11 -p1 -b .rand
# skip patch 12
%patch13 -p0 -b .conf
%patch14 -p1 -b .engver
%patch15 -p1 -b .ia64
%patch16 -p1 -b .baltimore
%patch17 -p1 -b .aep
%patch18 -p1 -b .luna
%patch19 -p1 -b .sec
%patch20 -p1 -b .asn
%patch21 -p1 -b .4096
%patch22 -p1 -b .malloc-negative
%patch23 -p1 -b .vaudenay
%patch24 -p0 -b .sec3-blinding
pushd ssl
%patch25 -p0 -b .klima-pokorny-rosa
popd

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
LD_LIBRARY_PATH=${TOPDIR}:${TOPDIR}/bin ; export LD_LIBRARY_PATH

# Figure out which flags we want to use.
perl util/perlpath.pl `dirname %{__perl}`
%ifarch %ix86
sslarch=linux-elf
if ! echo %{_target} | grep -q i686 ; then
	sslflags="no-asm 386"
fi
%endif
%ifarch sparc
sslarch=linux-sparcv9
sslflags=no-asm
%endif
%ifarch ia64
sslarch=linux-ia64
%endif
%ifarch alpha
sslarch=alpha-gcc
sslflags=no-asm
%endif
%ifarch s390
sslarch=linux-s390
%endif
%ifarch s390x
sslarch=linux-s390x
%endif
%ifarch x86_64
sslarch=linux-x86_64
sslflags=no-asm
%endif
%ifarch ppc
sslarch=linux-ppc
sslflags=no-asm
%endif
%ifarch ppc64
sslarch=linux-ppc64
sslflags=no-asm
%endif
# Configure the build tree.  Override OpenSSL defaults with known-good defaults
# usable on all platforms.  The Configure script already knows to use -fPIC and
# RPM_OPT_FLAGS, so we can skip specifiying them here.
./config --prefix=%{_prefix} --openssldir=%{_datadir}/ssl ${sslflags} no-idea no-mdc2 no-rc5 shared
%{__patch} -p1 -b --suffix .mkdepend -s < %{PATCH12}
make all build-shared

# Generate hashes for the included certs.
make rehash build-shared

# Verify that what was compiled actually works.
make -C test apps tests

%install
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT
# Install OpenSSL.
install -d $RPM_BUILD_ROOT/{%{_lib},%{_bindir},%{_includedir},%{_libdir},%{_mandir}}
make INSTALL_PREFIX=$RPM_BUILD_ROOT install build-shared
mv $RPM_BUILD_ROOT/usr/lib/lib*.so.%{solibbase} $RPM_BUILD_ROOT/%{_lib}/
mv $RPM_BUILD_ROOT%{_datadir}/ssl/man/* $RPM_BUILD_ROOT%{_mandir}/
rmdir $RPM_BUILD_ROOT%{_datadir}/ssl/man
mv $RPM_BUILD_ROOT/usr/lib/* $RPM_BUILD_ROOT%{_libdir}/ || :
rename so.%{solibbase} so.%{version} $RPM_BUILD_ROOT/%{_lib}/*.so.%{solibbase}
for lib in $RPM_BUILD_ROOT/%{_lib}/*.so.%{version} ; do
	chmod 755 ${lib}
	ln -s -f ../../%{_lib}/`basename ${lib}` $RPM_BUILD_ROOT%{_libdir}/`basename ${lib} .%{version}`
	ln -s -f ../../%{_lib}/`basename ${lib}` $RPM_BUILD_ROOT%{_libdir}/`basename ${lib} .%{version}`.%{soversion}
done

# Install a makefile for generating keys and self-signed certs, and a script
# for generating them on the fly.
mkdir -p $RPM_BUILD_ROOT%{_datadir}/ssl/certs
install -m644 $RPM_SOURCE_DIR/Makefile.certificate $RPM_BUILD_ROOT%{_datadir}/ssl/certs/Makefile
install -m644 $RPM_SOURCE_DIR/make-dummy-cert      $RPM_BUILD_ROOT%{_datadir}/ssl/certs/make-dummy-cert

# Make sure we actually include the headers we built against.
for header in $RPM_BUILD_ROOT%{_includedir}/openssl/* ; do
	if [ -f ${header} -a -f include/openssl/$(basename ${header}) ] ; then
		install -m644 include/openssl/`basename ${header}` ${header}
	fi
done

# Rename man pages so that they don't conflict with other system man pages.
for manpage in $RPM_BUILD_ROOT%{_mandir}/man*/* ; do
	mv ${manpage} ${manpage}ssl
done
for conflict in passwd rand ; do
	rename ${conflict} ssl${conflict} $RPM_BUILD_ROOT%{_mandir}/man*/${conflict}*
done

# Pick a CA script.
pushd  $RPM_BUILD_ROOT%{_datadir}/ssl/misc
mv CA.sh CA
mv der_chop der_chop.pl
popd

mkdir -m700 $RPM_BUILD_ROOT%{_datadir}/ssl/CA
mkdir -m700 $RPM_BUILD_ROOT%{_datadir}/ssl/CA/private

# Install root CA stuffs.
cat << EOF > RHNS-blurb.txt
#
#  RHNS CA certificate.  Appended to the ca-bundle at package build-time.
#
EOF
cat %{SOURCE3} RHNS-blurb.txt %{SOURCE4} > ca-bundle.crt
install -m644 ca-bundle.crt $RPM_BUILD_ROOT%{_datadir}/ssl/certs/
ln -s certs/ca-bundle.crt $RPM_BUILD_ROOT%{_datadir}/ssl/cert.pem

%ifarch i686
rm -rf $RPM_BUILD_ROOT/%{_prefix}/include/openssl
rm -rf $RPM_BUILD_ROOT/%{_libdir}/*.a
rm -rf $RPM_BUILD_ROOT/%{_libdir}/*.so
rm -rf $RPM_BUILD_ROOT/%{_mandir}/man3/*

rm -rf $RPM_BUILD_ROOT/%{_bindir}/c_rehash
rm -rf $RPM_BUILD_ROOT/%{_mandir}/man1*/*.pl*
rm -rf $RPM_BUILD_ROOT/%{_datadir}/ssl/misc/*.pl
%endif

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
%dir %{_datadir}/ssl/misc
%{_datadir}/ssl/misc/CA
%dir %{_datadir}/ssl/CA
%dir %{_datadir}/ssl/CA/private
%{_datadir}/ssl/misc/c_*
%{_datadir}/ssl/private

%config(noreplace) %{_datadir}/ssl/openssl.cnf

%attr(0755,root,root) %{_bindir}/openssl
%attr(0755,root,root) /%{_lib}/*.so.%{version}
%attr(0644,root,root) %{_mandir}/man1*/[ABD-Zabcd-z]*
%attr(0644,root,root) %{_mandir}/man5*/*
%attr(0644,root,root) %{_mandir}/man7*/*

%ifnarch i686
%files devel
%defattr(-,root,root)
%{_prefix}/include/openssl
%attr(0644,root,root) %{_libdir}/*.a
%attr(0755,root,root) %{_libdir}/*.so
%attr(0644,root,root) %{_mandir}/man3*/*

%files perl
%defattr(-,root,root)
%attr(0755,root,root) %{_bindir}/c_rehash
%attr(0644,root,root) %{_mandir}/man1*/*.pl*
%dir %{_datadir}/ssl/misc
%{_datadir}/ssl/misc/*.pl
%endif

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%changelog
* Wed Mar 19 2003 Nalin Dahyabhai <nalin@redhat.com> 0.9.6b-33
- add backported patch to harden against Klima-Pokorny-Rosa extension
  of Bleichenbacher's attack (CAN-2003-0131)

* Mon Mar 17 2003 Nalin Dahyabhai <nalin@redhat.com> 0.9.6b-32
- add patch to enable RSA blinding by default, closing a timing attack
  (CAN-2003-0147)

* Wed Feb 19 2003 Nalin Dahyabhai <nalin@redhat.com> 0.9.6b-31
- add fix to guard against attempts to allocate negative amounts of memory
- add patch for CAN-2003-0078, fixing a timing attack

* Tue Feb 11 2003 Nalin Dahyabhai <nalin@redhat.com>
- incorporate fix for verifying client certs with 4096-bit keys (#77225)

* Tue Oct 22 2002 Nalin Dahyabhai <nalin@redhat.com> 0.9.6b-30
- add configuration stanza for x86_64 and use it on x86_64
- build for linux-ppc on ppc
- start running the self-tests again

* Wed Oct 02 2002 Elliot Lee <sopwith@redhat.com> 0.9.6b-29hammer.3
- Merge fixes from previous hammer packages, including general x86-64 and
  multilib

* Tue Aug  6 2002 Nalin Dahyabhai <nalin@redhat.com> 0.9.6b-29
- rebuild

* Thu Aug  1 2002 Nalin Dahyabhai <nalin@redhat.com> 0.9.6b-28
- update asn patch to fix accidental reversal of a logic check

* Wed Jul 31 2002 Nalin Dahyabhai <nalin@redhat.com> 0.9.6b-27
- update asn patch to reduce chance that compiler optimization will remove
  one of the added tests

* Wed Jul 31 2002 Nalin Dahyabhai <nalin@redhat.com> 0.9.6b-26
- rebuild

* Mon Jul 29 2002 Nalin Dahyabhai <nalin@redhat.com> 0.9.6b-25
- add patch to fix ASN.1 vulnerabilities

* Thu Jul 25 2002 Nalin Dahyabhai <nalin@redhat.com> 0.9.6b-24
- add backport of Ben Laurie's patches for OpenSSL 0.9.6d

* Wed Jul 17 2002 Nalin Dahyabhai <nalin@redhat.com> 0.9.6b-23
- own %{_datadir}/ssl/misc

* Fri Jun 21 2002 Tim Powers <timp@redhat.com>
- automated rebuild

* Sun May 26 2002 Tim Powers <timp@redhat.com>
- automated rebuild

* Fri May 17 2002 Nalin Dahyabhai <nalin@redhat.com> 0.9.6b-20
- free ride through the build system (whee!)

* Thu May 16 2002 Nalin Dahyabhai <nalin@redhat.com> 0.9.6b-19
- rebuild in new environment

* Thu Apr  4 2002 Nalin Dahyabhai <nalin@redhat.com> 0.9.6b-17, 0.9.6b-18
- merge RHL-specific bits into stronghold package, rename

* Tue Apr 02 2002 Gary Benson <gbenson@redhat.com> stronghold-0.9.6c-2
- add support for Chrysalis Luna token

* Tue Mar 26 2002 Gary Benson <gbenson@redhat.com>
- disable AEP random number generation, other AEP fixes

* Fri Mar 15 2002 Nalin Dahyabhai <nalin@redhat.com> 0.9.6b-15
- only build subpackages on primary arches

* Thu Mar 14 2002 Nalin Dahyabhai <nalin@redhat.com> 0.9.6b-13
- on ia32, only disable use of assembler on i386
- enable assembly on ia64

* Mon Jan  7 2002 Florian La Roche <Florian.LaRoche@redhat.de> 0.9.6b-11
- fix sparcv9 entry

* Mon Jan  7 2002 Gary Benson <gbenson@redhat.com> stronghold-0.9.6c-1
- upgrade to 0.9.6c
- bump BuildArch to i686 and enable assembler on all platforms
- synchronise with shrimpy and rawhide
- bump soversion to 3

* Wed Oct 10 2001 Florian La Roche <Florian.LaRoche@redhat.de>
- delete BN_LLONG for s390x, patch from Oliver Paukstadt

* Mon Sep 17 2001 Nalin Dahyabhai <nalin@redhat.com> 0.9.6b-9
- update AEP driver patch

* Mon Sep 10 2001 Nalin Dahyabhai <nalin@redhat.com>
- adjust RNG disabling patch to match version of patch from Broadcom

* Fri Sep  7 2001 Nalin Dahyabhai <nalin@redhat.com> 0.9.6b-8
- disable the RNG in the ubsec engine driver

* Tue Aug 28 2001 Nalin Dahyabhai <nalin@redhat.com> 0.9.6b-7
- tweaks to the ubsec engine driver

* Fri Aug 24 2001 Nalin Dahyabhai <nalin@redhat.com> 0.9.6b-6
- tweaks to the ubsec engine driver

* Thu Aug 23 2001 Nalin Dahyabhai <nalin@redhat.com> 0.9.6b-5
- update ubsec engine driver from Broadcom

* Fri Aug 10 2001 Nalin Dahyabhai <nalin@redhat.com> 0.9.6b-4
- move man pages back to %%{_mandir}/man?/foo.?ssl from
  %%{_mandir}/man?ssl/foo.?
- add an [ engine ] section to the default configuration file

* Thu Aug  9 2001 Nalin Dahyabhai <nalin@redhat.com>
- add a patch for selecting a default engine in SSL_library_init()

* Mon Jul 23 2001 Nalin Dahyabhai <nalin@redhat.com> 0.9.6b-3
- add patches for AEP hardware support
- add patch to keep trying when we fail to load a cert from a file and
  there are more in the file
- add missing prototype for ENGINE_ubsec() in engine_int.h

* Wed Jul 18 2001 Nalin Dahyabhai <nalin@redhat.com> 0.9.6b-2
- actually add hw_ubsec to the engine list

* Tue Jul 17 2001 Nalin Dahyabhai <nalin@redhat.com>
- add in the hw_ubsec driver from CVS

* Wed Jul 11 2001 Nalin Dahyabhai <nalin@redhat.com> 0.9.6b-1
- update to 0.9.6b

* Thu Jul  5 2001 Nalin Dahyabhai <nalin@redhat.com>
- move .so symlinks back to %%{_libdir}

* Tue Jul  3 2001 Nalin Dahyabhai <nalin@redhat.com>
- move shared libraries to /lib (#38410)

* Mon Jun 25 2001 Nalin Dahyabhai <nalin@redhat.com>
- switch to engine code base

* Mon Jun 18 2001 Nalin Dahyabhai <nalin@redhat.com>
- add a script for creating dummy certificates
- move man pages from %%{_mandir}/man?/foo.?ssl to %%{_mandir}/man?ssl/foo.?

* Thu Jun 07 2001 Florian La Roche <Florian.LaRoche@redhat.de>
- add s390x support

* Fri Jun  1 2001 Nalin Dahyabhai <nalin@redhat.com>
- change two memcpy() calls to memmove()
- don't define L_ENDIAN on alpha

* Wed May 23 2001 Joe Orton <jorton@redhat.com> stronghold-0.9.6a-1
- Add 'stronghold-' prefix to package names.
- Obsolete standard openssl packages.

* Wed May 16 2001 Joe Orton <jorton@redhat.com>
- Add BuildArch: i586 as per Nalin's advice.

* Tue May 15 2001 Joe Orton <jorton@redhat.com>
- Enable assembler on ix86 (using new .tar.bz2 which does
  include the asm directories).

* Tue May 15 2001 Nalin Dahyabhai <nalin@redhat.com>
- make subpackages depend on the main package

* Tue May  1 2001 Nalin Dahyabhai <nalin@redhat.com>
- adjust the hobble script to not disturb symlinks in include/ (fix from
  Joe Orton)

* Fri Apr 26 2001 Nalin Dahyabhai <nalin@redhat.com>
- drop the m2crypo patch we weren't using

* Tue Apr 24 2001 Nalin Dahyabhai <nalin@redhat.com>
- configure using "shared" as well

* Sun Apr  8 2001 Nalin Dahyabhai <nalin@redhat.com>
- update to 0.9.6a
- use the build-shared target to build shared libraries
- bump the soversion to 2 because we're no longer compatible with
  our 0.9.5a packages or our 0.9.6 packages
- drop the patch for making rsatest a no-op when rsa null support is used
- put all man pages into <section>ssl instead of <section>
- break the m2crypto modules into a separate package

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

* Sat Dec 18 1999 Bernhard Rosenkrdnzer <bero@redhat.de>
- Fix build on non-x86 platforms

* Fri Nov 12 1999 Bernhard Rosenkrdnzer <bero@redhat.de>
- move /usr/share/ssl/* from -devel to main package

* Tue Oct 26 1999 Bernhard Rosenkrdnzer <bero@redhat.de>
- inital packaging
- changes from base:
  - Move /usr/local/ssl to /usr/share/ssl for FHS compliance
  - handle RPM_OPT_FLAGS
