%define m2crypto_version 0.05-snap3
%define swig_version 1.1p5

Summary: Secure Sockets Layer Toolkit
Name: openssl
Version: 0.9.5a
Release: 17
Source: openssl-%{version}-usa.tar.bz2
Source1: hobble-openssl
Source2: Makefile.certificate
Source3: http://download.sourceforge.net/swig/swig%{swig_version}.tar.gz
Source4: http://mars.post1.com/home/ngps/m2/m2crypto-%{m2crypto_version}.zip
Patch0: openssl-0.9.5-redhat.patch
Patch1: openssl-0.9.5-rsanull.patch
Patch2: openssl-0.9.5a-64.patch
Patch3: openssl-0.9.5a-defaults.patch
Patch4: openssl-0.9.5a-ia64.patch
Copyright: BSDish
Group: System Environment/Libraries
URL: http://www.openssl.org/
BuildRoot: %{_tmppath}/%{name}-%{version}-root
BuildPreReq: perl, python-devel

%description
The OpenSSL certificate management tool and the shared libraries that
provide various cryptographic algorithms and protocols.

%package devel
Summary: OpenSSL libraries and development headers.
Group: Development/Libraries

%description devel
The static libraries and include files needed to compile apps
with support for various cryptographic algorithms and protocols.

Patches for many networking apps can be found at:
ftp://ftp.psy.uq.oz.au/pub/Crypto/SSLapps/

%package perl
Summary: OpenSSL scripts which require Perl.
Group: Applications/Internet
Requires: perl

%description perl
Perl scripts provided with OpenSSL for converting certificates and keys
from other formats to those used by OpenSSL.

%package python
Summary: Support for using OpenSSL in python scripts.
Group: Applications/Internet
Requires: python

%description python
This package allows you to call OpenSSL functions from python scripts.

%prep
%setup -q
#%{SOURCE1}
%patch0 -p1 -b .redhat
%patch1 -p1 -b .rsanull
%ifarch alpha
%patch2 -p1
%endif
%ifarch ia64
%patch2 -p1
%endif
%patch3 -p1
%patch4 -p1

# Extract what we need for building extensions.
gzip -dc %{SOURCE3} | tar xf -
unzip -q %{SOURCE4}
pushd m2crypto-%{m2crypto_version}
    for file in demo/evp_ciph_test.py demo/bio_ciph_test.py swig/_evp.i ; do
	grep -v idea_ ${file} > ${file}.tmp
	grep -v rc5_  ${file}.tmp > ${file}
    done
popd

chmod 644 FAQ LICENSE CHANGES NEWS INSTALL README
chmod 644 doc/README doc/c-indentation.el doc/openssl.txt
chmod 644 doc/openssl_button.html doc/openssl_button.gif
chmod 644 doc/ssleay.txt

%build 
PATH=${PATH}:${PWD}/bin
TOPDIR=${PWD}

# Figure out which flags we want to use.  Assembly is broken on some platforms,
# required on others.
perl util/perlpath.pl `dirname %{__perl}`
%ifarch %ix86
sslarch=linux-elf
%endif
%ifarch sparc
sslarch=linux-sparcv9
%endif
%ifarch ia64
sslarch=linux-ia64
sslflags=no-asm
%endif
%ifarch alpha
sslarch=alpha-gcc
sslflags=no-asm
%endif
# Configure the build tree.  Override OpenSSL defaults with known-good defaults
# usable on all platforms.
CFLAGS="-fPIC -ggdb"; export CFLAGS
#./Configure --prefix=%{_prefix} --openssldir=%{_datadir}/ssl ${sslarch}
./config --prefix=%{_prefix} --openssldir=%{_datadir}/ssl ${sslflags} $CFLAGS no-idea no-mdc2 no-rc5 no-md2
make all

# Build the Perl bindings.
#pushd perl
#perl Makefile.PL
#make
#popd

# Verify that what was compiled actually works.
make -C test apps tests

# Build shared libraries.
majorver=`echo %{version} | cut -f1 -d.`
for shlib in crypto ssl ; do
	pushd $shlib
		objs=`ar t ../lib${shlib}.a | xargs -n 1 find . -name`
		%{__cc} -shared -o ../lib${shlib}.so.%{version} \
			-Wl,-soname=lib${shlib}.so.${majorver} $objs && \
		ln -sf lib${shlib}.so.%{version} ../lib${shlib}.so
	popd
done

# Build a copy of swig with which to build the extensions.
pushd SWIG%{swig_version}
autoconf
CFLAGS="%{optflags}" \
CCFLAGS="%{optflags}" \
FFLAGS="%{optflags}" \
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
%{_datadir}/ssl/lib
%{_datadir}/ssl/misc/c_*
%{_datadir}/ssl/private

%config %{_datadir}/ssl/openssl.cnf

%attr(0755,root,root) %{_bindir}/*
%attr(0755,root,root) %{_libdir}/*.so.*
%attr(0644,root,root) %{_mandir}/man1/*
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
%{_datadir}/ssl/misc/*.pl

%files python
%defattr(-,root,root)
%doc m2crypto-%{m2crypto_version}/{BUGS,CHANGES,LIC*,README,TODO}
%doc m2crypto-%{m2crypto_version}/doc/{README,*.html}
%{_libdir}/python1.5/site-packages/M2Crypto

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%changelog
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

* Sat Dec 18 1999 Bernhard Rosenkränzer <bero@redhat.de>
- Fix build on non-x86 platforms

* Fri Nov 12 1999 Bernhard Rosenkränzer <bero@redhat.de>
- move /usr/share/ssl/* from -devel to main package

* Tue Oct 26 1999 Bernhard Rosenkränzer <bero@redhat.de>
- inital packaging
- changes from base:
  - Move /usr/local/ssl to /usr/share/ssl for FHS compliance
  - handle RPM_OPT_FLAGS
