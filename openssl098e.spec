# For the curious:
# 0.9.5a soversion = 0
# 0.9.6 soversion = 1
# 0.9.6a soversion = 2
# 0.9.6c soversion = 3
# 0.9.7a soversion = 4
# 0.9.7ef soversion = 5
# 0.9.8abe soversion = 6
%define soversion 6

# Number of threads to spawn when testing some threading fixes.
%define thread_test_threads %{?threads:%{threads}}%{!?threads:1}

# Arches on which we need to prevent arch conflicts on opensslconf.h, must
# also be handled in opensslconf-new.h.
%define multilib_arches %{ix86} ia64 ppc ppc64 s390 s390x x86_64

Summary: A compatibility version of a general cryptography and TLS library
Name: openssl098e
Version: 0.9.8e
Release: 17%{?dist}
# The tarball is based on the openssl-fips-1.2.0-test.tar.gz tarball
Source: openssl-fips-%{version}-usa.tar.bz2
Source1: hobble-openssl
Source8: openssl-thread-test.c
Source9: opensslconf-new.h
Source10: opensslconf-new-warning.h
Source11: README.FIPS
# Build changes
Patch0: openssl-fips-0.9.8e-redhat.patch
Patch1: openssl-0.9.8a-defaults.patch
Patch2: openssl-0.9.8a-link-krb5.patch
Patch3: openssl-0.9.8b-soversion.patch
Patch4: openssl-fips-0.9.8e-enginesdir.patch
Patch5: openssl-0.9.8a-no-rpath.patch
# Functionality changes
Patch32: openssl-fips-0.9.8e-ia64.patch
Patch34: openssl-0.9.6-x509.patch
Patch35: openssl-0.9.7-beta5-version-add-engines.patch
Patch38: openssl-0.9.8a-reuse-cipher-change.patch
Patch39: openssl-0.9.8b-ipv6-apps.patch
# Backported fixes including security fixes
Patch61: openssl-0.9.8b-aliasing-bug.patch
Patch62: openssl-0.9.8b-x509-name-cmp.patch
Patch64: openssl-fips-0.9.8e-dtls-fixes.patch
Patch65: openssl-0.9.8b-cve-2007-5135.patch
Patch67: openssl-fips-0.9.8e-aescfb.patch
Patch68: openssl-fips-0.9.8e-abi.patch
Patch69: openssl-fips-0.9.8e-fipsmode.patch
Patch70: openssl-fips-0.9.8e-bn-fixes.patch
Patch71: openssl-fips-0.9.8e-use-fipscheck.patch
Patch72: openssl-fips-0.9.8e-env-nozlib.patch
Patch73: openssl-fips-0.9.8e-default-paths.patch
Patch74: openssl-fips-0.9.8e-evp-nonfips.patch
Patch75: openssl-fips-0.9.8e-cve-2008-5077.patch
Patch76: openssl-fips-0.9.8e-multi-crl.patch
Patch77: openssl-fips-0.9.8e-no-pairwise.patch
Patch78: openssl-fips-0.9.8e-rng-seed.patch
Patch79: openssl-fips-0.9.8e-bad-mime.patch
Patch80: openssl-fips-0.9.8e-cve-2009-0590.patch
Patch81: openssl-fips-0.9.8e-dtls-dos.patch
Patch82: openssl-fips-0.9.8e-algo-doc.patch
Patch83: openssl-fips-0.9.8e-cve-2009-2409.patch
Patch84: openssl-fips-0.9.8e-cve-2009-4355.patch
Patch85: openssl-fips-0.9.8e-cve-2009-3555.patch
Patch86: openssl-fips-0.9.8e-cve-2010-0433.patch
Patch87: openssl-fips-0.9.8e-cve-2009-3245.patch
Patch88: openssl-fips-0.9.8e-casts.patch
Patch89: openssl-fips-0.9.8e-asm-sign.patch

License: OpenSSL
Group: System Environment/Libraries
URL: http://www.openssl.org/
BuildRoot: %{_tmppath}/%{name}-%{version}-root
BuildRequires: mktemp, krb5-devel, perl, sed, zlib-devel, /usr/bin/cmp
BuildRequires: /usr/bin/rename
Requires: mktemp, ca-certificates >= 2008-5

%description
The OpenSSL toolkit provides support for secure communications between
machines. OpenSSL includes a certificate management tool and shared
libraries which provide various cryptographic algorithms and
protocols. This version of OpenSSL package is provided for compatibility
with the previous Red Hat Enterprise Linux release.


%prep
%setup -q -n openssl-fips-%{version}

%{SOURCE1} > /dev/null
%patch0 -p1 -b .redhat
%patch1 -p1 -b .defaults
# Fix link line for libssl (bug #111154).
%patch2 -p1 -b .krb5
%patch3 -p1 -b .soversion
%patch4 -p1 -b .enginesdir
%patch5 -p1 -b .no-rpath


%patch32 -p1 -b .ia64
%patch34 -p1 -b .x509
%patch35 -p1 -b .version-add-engines
%patch38 -p1 -b .cipher-change
%patch39 -p1 -b .ipv6-apps

%patch61 -p1 -b .aliasing-bug
%patch62 -p1 -b .name-cmp
%patch64 -p1 -b .dtls-fixes
%patch65 -p1 -b .shciphers
%patch67 -p1 -b .aescfb
%patch68 -p1 -b .abi
%patch69 -p1 -b .fipsmode
%patch70 -p1 -b .bn-fixes
%patch71 -p1 -b .use-fipscheck
%patch72 -p1 -b .env-nozlib
%patch73 -p1 -b .default-paths
%patch74 -p1 -b .nonfips
%patch75 -p1 -b .verifysig
%patch76 -p1 -b .multi-crl
%patch77 -p1 -b .no-pairwise
%patch78 -p1 -b .rng-seed
%patch79 -p1 -b .bad-mime
%patch80 -p1 -b .bad-string
%patch81 -p1 -b .dtls-dos
%patch82 -p1 -b .algo-doc
%patch83 -p1 -b .nomd2
%patch84 -p1 -b .compleak
%patch85 -p1 -b .reneg
%patch86 -p1 -b .nullprinc
%patch87 -p1 -b .wexpand
%patch88 -p1 -b .casts
%patch89 -p1 -b .sign

# Modify the various perl scripts to reference perl in the right location.
perl util/perlpath.pl `dirname %{__perl}`

# Generate a table with the compile settings for my perusal.
touch Makefile
make TABLE PERL=%{__perl}

%build 
# Figure out which flags we want to use.
# default
sslarch=%{_os}-%{_arch}
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
%ifarch alpha
sslarch=linux-alpha-gcc
%endif
%ifarch s390
# The -fno-regmove is a workaround for bug #199604
sslarch="linux-generic32 -DB_ENDIAN -DNO_ASM -march=z900 -fno-regmove"
%endif
%ifarch s390x
sslarch="linux-generic64 -DB_ENDIAN -DNO_ASM"
%endif
# ia64, x86_64, ppc, ppc64 are OK by default
# Configure the build tree.  Override OpenSSL defaults with known-good defaults
# usable on all platforms.  The Configure script already knows to use -fPIC and
# RPM_OPT_FLAGS, so we can skip specifiying them here.
./Configure \
	--prefix=/usr --openssldir=%{_sysconfdir}/pki/tls ${sslflags} \
	zlib no-idea no-mdc2 no-rc5 no-ec no-ecdh no-ecdsa \
	--with-krb5-flavor=MIT --enginesdir=%{_libdir}/openssl098e/engines \
	-with-krb5-dir=/usr shared \
	${sslarch} fipscanisterbuild

# Add -Wa,--noexecstack here so that libcrypto's assembler modules will be
# marked as not requiring an executable stack.
RPM_OPT_FLAGS="$RPM_OPT_FLAGS -Wa,--noexecstack -DOPENSSL_USE_NEW_FUNCTIONS -fno-strict-aliasing"
make depend
make all

# Generate hashes for the included certs.
make rehash

# Overwrite FIPS README
cp -f %{SOURCE11} .

%check
# Verify that what was compiled actually works.
LD_LIBRARY_PATH=`pwd`${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}
export LD_LIBRARY_PATH
make -C test apps tests
%{__cc} -o openssl-thread-test \
	`krb5-config --cflags` \
	-I./include \
	$RPM_OPT_FLAGS \
	%{SOURCE8} \
	-L. \
	-lssl -lcrypto \
	`krb5-config --libs` \
	-lpthread -lz -ldl
./openssl-thread-test --threads %{thread_test_threads}

# Add generation of HMAC checksum of the final stripped library
%define __spec_install_post \
	%{?__debug_package:%{__debug_install_post}} \
	%{__arch_install_post} \
	%{__os_install_post} \
	fips/fips_standalone_sha1 $RPM_BUILD_ROOT%{_libdir}/libcrypto.so.%{version} >$RPM_BUILD_ROOT%{_libdir}/.libcrypto.so.%{version}.hmac \
	ln -sf .libcrypto.so.%{version}.hmac $RPM_BUILD_ROOT%{_libdir}/.libcrypto.so.%{soversion}.hmac \
	fips/fips_standalone_sha1 $RPM_BUILD_ROOT%{_libdir}/libssl.so.%{version} >$RPM_BUILD_ROOT%{_libdir}/.libssl.so.%{version}.hmac \
	ln -sf .libssl.so.%{version}.hmac $RPM_BUILD_ROOT%{_libdir}/.libssl.so.%{soversion}.hmac \
%{nil}

%install
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT
# Install OpenSSL.
install -d $RPM_BUILD_ROOT{%{_bindir},%{_includedir},%{_libdir},%{_mandir},%{_libdir}/openssl098e}
make INSTALL_PREFIX=$RPM_BUILD_ROOT install
make INSTALL_PREFIX=$RPM_BUILD_ROOT install_docs
# OpenSSL install doesn't use correct _libdir on 64 bit archs
[ "%{_libdir}" != /usr/lib ] && mv $RPM_BUILD_ROOT/usr/lib/lib*.so.%{soversion} $RPM_BUILD_ROOT%{_libdir}/
mv $RPM_BUILD_ROOT/usr/lib/engines $RPM_BUILD_ROOT%{_libdir}/openssl098e
rm -rf $RPM_BUILD_ROOT%{_sysconfdir}/pki/tls/man
rm -f $RPM_BUILD_ROOT/usr/lib/*.{a,so} || :
rename so.%{soversion} so.%{version} $RPM_BUILD_ROOT%{_libdir}/*.so.%{soversion}
for lib in $RPM_BUILD_ROOT%{_libdir}/*.so.%{version} ; do
	chmod 755 ${lib}
	ln -s -f `basename ${lib}` $RPM_BUILD_ROOT%{_libdir}/`basename ${lib} .%{version}`.%{soversion}
done

# Delete man pages in the compat package
rm -rf $RPM_BUILD_ROOT%{_mandir}

# Delete configuration files
rm -rf  $RPM_BUILD_ROOT%{_sysconfdir}/pki

# Remove devel stuff
rm -rf $RPM_BUILD_ROOT/usr/lib/pkgconfig
rm -rf $RPM_BUILD_ROOT/%{_includedir}

# Remove binaries
rm -rf $RPM_BUILD_ROOT/%{_bindir}

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

%files 
%defattr(-,root,root)
%doc FAQ LICENSE CHANGES NEWS INSTALL README
%doc README.FIPS

%attr(0755,root,root) %{_libdir}/*.so.%{version}
%attr(0755,root,root) %{_libdir}/*.so.%{soversion}
%attr(0644,root,root) %{_libdir}/.libcrypto.so.*.hmac
%attr(0644,root,root) %{_libdir}/.libssl.so.*.hmac
%dir %{_libdir}/openssl098e
%attr(0755,root,root) %{_libdir}/openssl098e/engines

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%changelog
* Fri Apr 16 2010 Tomas Mraz <tmraz@redhat.com> 0.9.8e-17
- create compat package

* Fri Mar 12 2010 Tomas Mraz <tmraz@redhat.com> 0.9.8e-16
- fix CVE-2009-3245 - add missing bn_wexpand return checks (#570924)

* Thu Mar  4 2010 Tomas Mraz <tmraz@redhat.com> 0.9.8e-15
- fix CVE-2010-0433 - do not pass NULL princ to krb5_kt_get_entry which
  in the RHEL-5 and newer versions will crash in such case (#569774)

* Thu Feb 18 2010 Tomas Mraz <tmraz@redhat.com> 0.9.8e-14
- fix CVE-2009-3555 - support the safe renegotiation extension and
  do not allow legacy renegotiation on the server by default (#533125)

* Thu Jan 14 2010 Tomas Mraz <tmraz@redhat.com> 0.9.8e-13
- fix CVE-2009-2409 - drop MD2 algorithm from EVP tables (#510197)
- fix CVE-2009-4355 - do not leak memory when CRYPTO_cleanup_all_ex_data()
  is called prematurely by application (#546707)

* Mon Jun 29 2009 Tomas Mraz <tmraz@redhat.com> 0.9.8e-12
- abort if selftests failed and random number generator is polled
- mention EVP_aes and EVP_sha2xx routines in the manpages
- add README.FIPS

* Thu May 21 2009 Tomas Mraz <tmraz@redhat.com> 0.9.8e-10
- fix CVE-2009-1386 CVE-2009-1387 (DTLS DoS problems)
  (#503685, #503688)

* Thu May 21 2009 Tomas Mraz <tmraz@redhat.com> 0.9.8e-9
- fix CVE-2009-1377 CVE-2009-1378 CVE-2009-1379
  (DTLS DoS problems) (#501253, #501254, #501572)

* Wed Apr 15 2009 Tomas Mraz <tmraz@redhat.com> 0.9.8e-8
- support multiple CRLs with same subject in a store (#457134)
- fix CVE-2009-0590 - reject incorrectly encoded ASN.1 strings (#492304)
- seed FIPS rng directly from kernel random device
- do not require fipscheck to build the package (#475798)
- call pairwise key tests in FIPS mode only (#479817)
- do not crash when parsing bad mime data (#472440)

* Tue Dec 16 2008 Tomas Mraz <tmraz@redhat.com> 0.9.8e-7
- fix CVE-2008-5077 - incorrect checks for malformed signatures (#476671)

* Fri Oct 31 2008 Tomas Mraz <tmraz@redhat.com> 0.9.8e-6
- allow lookup of algorithms in engine

* Fri Oct 24 2008 Tomas Mraz <tmraz@redhat.com> 0.9.8e-5
- implement the integrity checking inside libcrypto so OpenSSL
  can be used in FIPS mode by the fipscheck library

* Thu Oct  9 2008 Tomas Mraz <tmraz@redhat.com> 0.9.8e-4
- FIPS mode kernel flag is /proc/sys/crypto/fips_enabled

* Wed Sep 10 2008 Tomas Mraz <tmraz@redhat.com> 0.9.8e-3
- disable strict aliasing

* Tue Sep  9 2008 Tomas Mraz <tmraz@redhat.com> 0.9.8e-2
- more changes for FIPS validation (#444800)
- correctly initialize default CA paths (#450987)
- allow disabling zlib support through environment (#442624)

* Tue Jul 15 2008 Tomas Mraz <tmraz@redhat.com> 0.9.8e-1
- rebase to version undergoing FIPS validation (#455634)

* Tue Jan 15 2008 Tomas Mraz <tmraz@redhat.com> 0.9.8b-10
- compile with -march=z900 on s390 for performance improvements (#250818)
- make ssl session ID matching strict (#233599)

* Mon Oct  8 2007 Tomas Mraz <tmraz@redhat.com> 0.9.8b-9
- fix CVE-2007-3108 - side channel attack on private keys (#250581)
- fix CVE-2007-5135 - off-by-one in SSL_get_shared_ciphers (#309881)
- fix CVE-2007-4995 - out of order DTLS fragments buffer overflow (#321221)

* Thu Nov 30 2006 Tomas Mraz <tmraz@redhat.com> 0.9.8b-8.3
- the previous change still didn't make X509_NAME_cmp transitive

* Thu Nov 23 2006 Tomas Mraz <tmraz@redhat.com> 0.9.8b-8.2
- make X509_NAME_cmp transitive otherwise certificate lookup
  is broken (#216050)

* Fri Nov  3 2006 Tomas Mraz <tmraz@redhat.com> 0.9.8b-8.1
- aliasing bug in engine loading, patch by IBM (#213216)

* Mon Oct  2 2006 Tomas Mraz <tmraz@redhat.com> 0.9.8b-8
- CVE-2006-2940 fix was incorrect (#208744)

* Mon Sep 25 2006 Tomas Mraz <tmraz@redhat.com> 0.9.8b-7
- fix CVE-2006-2937 - mishandled error on ASN.1 parsing (#207276)
- fix CVE-2006-2940 - parasitic public keys DoS (#207274)
- fix CVE-2006-3738 - buffer overflow in SSL_get_shared_ciphers (#206940)
- fix CVE-2006-4343 - sslv2 client DoS (#206940)

* Tue Sep  5 2006 Tomas Mraz <tmraz@redhat.com> 0.9.8b-6
- fix CVE-2006-4339 - prevent attack on PKCS#1 v1.5 signatures (#205180)

* Wed Aug  2 2006 Tomas Mraz <tmraz@redhat.com> - 0.9.8b-5
- set buffering to none on stdio/stdout FILE when bufsize is set (#200580)
  patch by IBM

* Fri Jul 28 2006 Alexandre Oliva <aoliva@redhat.com> - 0.9.8b-4.1
- rebuild with new binutils (#200330)

* Fri Jul 21 2006 Tomas Mraz <tmraz@redhat.com> - 0.9.8b-4
- add a temporary workaround for sha512 test failure on s390 (#199604)

* Thu Jul 20 2006 Tomas Mraz <tmraz@redhat.com>
- add ipv6 support to s_client and s_server (by Jan Pazdziora) (#198737)
- add patches for BN threadsafety, AES cache collision attack hazard fix and
  pkcs7 code memleak fix from upstream CVS

* Wed Jul 12 2006 Jesse Keating <jkeating@redhat.com> - 0.9.8b-3.1
- rebuild

* Wed Jun 21 2006 Tomas Mraz <tmraz@redhat.com> - 0.9.8b-3
- dropped libica and ica engine from build

* Wed Jun 21 2006 Joe Orton <jorton@redhat.com>
- update to new CA bundle from mozilla.org; adds CA certificates
  from netlock.hu and startcom.org

* Mon Jun  5 2006 Tomas Mraz <tmraz@redhat.com> - 0.9.8b-2
- fixed a few rpmlint warnings
- better fix for #173399 from upstream
- upstream fix for pkcs12

* Thu May 11 2006 Tomas Mraz <tmraz@redhat.com> - 0.9.8b-1
- upgrade to new version, stays ABI compatible
- there is no more linux/config.h (it was empty anyway)

* Tue Apr  4 2006 Tomas Mraz <tmraz@redhat.com> - 0.9.8a-6
- fix stale open handles in libica (#177155)
- fix build if 'rand' or 'passwd' in buildroot path (#178782)
- initialize VIA Padlock engine (#186857)

* Fri Feb 10 2006 Jesse Keating <jkeating@redhat.com> - 0.9.8a-5.2
- bump again for double-long bug on ppc(64)

* Tue Feb 07 2006 Jesse Keating <jkeating@redhat.com> - 0.9.8a-5.1
- rebuilt for new gcc4.1 snapshot and glibc changes

* Thu Dec 15 2005 Tomas Mraz <tmraz@redhat.com> 0.9.8a-5
- don't include SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG
  in SSL_OP_ALL (#175779)

* Fri Dec 09 2005 Jesse Keating <jkeating@redhat.com>
- rebuilt

* Tue Nov 29 2005 Tomas Mraz <tmraz@redhat.com> 0.9.8a-4
- fix build (-lcrypto was erroneusly dropped) of the updated libica
- updated ICA engine to 1.3.6-rc3

* Tue Nov 22 2005 Tomas Mraz <tmraz@redhat.com> 0.9.8a-3
- disable builtin compression methods for now until they work
  properly (#173399)

* Wed Nov 16 2005 Tomas Mraz <tmraz@redhat.com> 0.9.8a-2
- don't set -rpath for openssl binary

* Tue Nov  8 2005 Tomas Mraz <tmraz@redhat.com> 0.9.8a-1
- new upstream version
- patches partially renumbered

* Fri Oct 21 2005 Tomas Mraz <tmraz@redhat.com> 0.9.7f-11
- updated IBM ICA engine library and patch to latest upstream version

* Wed Oct 12 2005 Tomas Mraz <tmraz@redhat.com> 0.9.7f-10
- fix CAN-2005-2969 - remove SSL_OP_MSIE_SSLV2_RSA_PADDING which
  disables the countermeasure against man in the middle attack in SSLv2
  (#169863)
- use sha1 as default for CA and cert requests - CAN-2005-2946 (#169803)

* Tue Aug 23 2005 Tomas Mraz <tmraz@redhat.com> 0.9.7f-9
- add *.so.soversion as symlinks in /lib (#165264)
- remove unpackaged symlinks (#159595)
- fixes from upstream (constant time fixes for DSA,
  bn assembler div on ppc arch, initialize memory on realloc)

* Thu Aug 11 2005 Phil Knirsch <pknirsch@redhat.com> 0.9.7f-8
- Updated ICA engine IBM patch to latest upstream version.

* Thu May 19 2005 Tomas Mraz <tmraz@redhat.com> 0.9.7f-7
- fix CAN-2005-0109 - use constant time/memory access mod_exp
  so bits of private key aren't leaked by cache eviction (#157631)
- a few more fixes from upstream 0.9.7g

* Wed Apr 27 2005 Tomas Mraz <tmraz@redhat.com> 0.9.7f-6
- use poll instead of select in rand (#128285)
- fix Makefile.certificate to point to /etc/pki/tls
- change the default string mask in ASN1 to PrintableString+UTF8String

* Mon Apr 25 2005 Joe Orton <jorton@redhat.com> 0.9.7f-5
- update to revision 1.37 of Mozilla CA bundle

* Thu Apr 21 2005 Tomas Mraz <tmraz@redhat.com> 0.9.7f-4
- move certificates to _sysconfdir/pki/tls (#143392)
- move CA directories to _sysconfdir/pki/CA
- patch the CA script and the default config so it points to the
  CA directories

* Fri Apr  1 2005 Tomas Mraz <tmraz@redhat.com> 0.9.7f-3
- uninitialized variable mustn't be used as input in inline
  assembly
- reenable the x86_64 assembly again

* Thu Mar 31 2005 Tomas Mraz <tmraz@redhat.com> 0.9.7f-2
- add back RC4_CHAR on ia64 and x86_64 so the ABI isn't broken
- disable broken bignum assembly on x86_64

* Wed Mar 30 2005 Tomas Mraz <tmraz@redhat.com> 0.9.7f-1
- reenable optimizations on ppc64 and assembly code on ia64
- upgrade to new upstream version (no soname bump needed)
- disable thread test - it was testing the backport of the
  RSA blinding - no longer needed
- added support for changing serial number to 
  Makefile.certificate (#151188)
- make ca-bundle.crt a config file (#118903)

* Tue Mar  1 2005 Tomas Mraz <tmraz@redhat.com> 0.9.7e-3
- libcrypto shouldn't depend on libkrb5 (#135961)

* Mon Feb 28 2005 Tomas Mraz <tmraz@redhat.com> 0.9.7e-2
- rebuild

* Mon Feb 28 2005 Tomas Mraz <tmraz@redhat.com> 0.9.7e-1
- new upstream source, updated patches
- added patch so we are hopefully ABI compatible with upcoming
  0.9.7f

* Thu Feb 10 2005 Tomas Mraz <tmraz@redhat.com>
- Support UTF-8 charset in the Makefile.certificate (#134944)
- Added cmp to BuildPrereq

* Thu Jan 27 2005 Joe Orton <jorton@redhat.com> 0.9.7a-46
- generate new ca-bundle.crt from Mozilla certdata.txt (revision 1.32)

* Thu Dec 23 2004 Phil Knirsch <pknirsch@redhat.com> 0.9.7a-45
- Fixed and updated libica-1.3.4-urandom.patch patch (#122967)

* Fri Nov 19 2004 Nalin Dahyabhai <nalin@redhat.com> 0.9.7a-44
- rebuild

* Fri Nov 19 2004 Nalin Dahyabhai <nalin@redhat.com> 0.9.7a-43
- rebuild

* Fri Nov 19 2004 Nalin Dahyabhai <nalin@redhat.com> 0.9.7a-42
- rebuild

* Fri Nov 19 2004 Nalin Dahyabhai <nalin@redhat.com> 0.9.7a-41
- remove der_chop, as upstream cvs has done (CAN-2004-0975, #140040)

* Tue Oct 05 2004 Phil Knirsch <pknirsch@redhat.com> 0.9.7a-40
- Include latest libica version with important bugfixes

* Tue Jun 15 2004 Elliot Lee <sopwith@redhat.com>
- rebuilt

* Mon Jun 14 2004 Phil Knirsch <pknirsch@redhat.com> 0.9.7a-38
- Updated ICA engine IBM patch to latest upstream version.

* Mon Jun  7 2004 Nalin Dahyabhai <nalin@redhat.com> 0.9.7a-37
- build for linux-alpha-gcc instead of alpha-gcc on alpha (Jeff Garzik)

* Tue May 25 2004 Nalin Dahyabhai <nalin@redhat.com> 0.9.7a-36
- handle %%{_arch}=i486/i586/i686/athlon cases in the intermediate
  header (#124303)

* Thu Mar 25 2004 Joe Orton <jorton@redhat.com> 0.9.7a-35
- add security fixes for CAN-2004-0079, CAN-2004-0112

* Tue Mar 16 2004 Phil Knirsch <pknirsch@redhat.com>
- Fixed libica filespec.

* Thu Mar 10 2004 Nalin Dahyabhai <nalin@redhat.com> 0.9.7a-34
- ppc/ppc64 define __powerpc__/__powerpc64__, not __ppc__/__ppc64__, fix
  the intermediate header

* Wed Mar 10 2004 Nalin Dahyabhai <nalin@redhat.com> 0.9.7a-33
- add an intermediate <openssl/opensslconf.h> which points to the right
  arch-specific opensslconf.h on multilib arches

* Tue Mar 02 2004 Elliot Lee <sopwith@redhat.com>
- rebuilt

* Thu Feb 26 2004 Phil Knirsch <pknirsch@redhat.com> 0.9.7a-32
- Updated libica to latest upstream version 1.3.5.

* Tue Feb 17 2004 Phil Knirsch <pknirsch@redhat.com> 0.9.7a-31
- Update ICA crypto engine patch from IBM to latest version.

* Fri Feb 13 2004 Elliot Lee <sopwith@redhat.com>
- rebuilt

* Fri Feb 13 2004 Phil Knirsch <pknirsch@redhat.com> 0.9.7a-29
- rebuilt

* Wed Feb 11 2004 Phil Knirsch <pknirsch@redhat.com> 0.9.7a-28
- Fixed libica build.

* Wed Feb  4 2004 Nalin Dahyabhai <nalin@redhat.com>
- add "-ldl" to link flags added for Linux-on-ARM (#99313)

* Wed Feb  4 2004 Joe Orton <jorton@redhat.com> 0.9.7a-27
- updated ca-bundle.crt: removed expired GeoTrust roots, added
  freessl.com root, removed trustcenter.de Class 0 root

* Sun Nov 30 2003 Tim Waugh <twaugh@redhat.com> 0.9.7a-26
- Fix link line for libssl (bug #111154).

* Fri Oct 24 2003 Nalin Dahyabhai <nalin@redhat.com> 0.9.7a-25
- add dependency on zlib-devel for the -devel package, which depends on zlib
  symbols because we enable zlib for libssl (#102962)

* Fri Oct 24 2003 Phil Knirsch <pknirsch@redhat.com> 0.9.7a-24
- Use /dev/urandom instead of PRNG for libica.
- Apply libica-1.3.5 fix for /dev/urandom in icalinux.c
- Use latest ICA engine patch from IBM.

* Sat Oct  4 2003 Nalin Dahyabhai <nalin@redhat.com> 0.9.7a-22.1
- rebuild

* Wed Oct  1 2003 Nalin Dahyabhai <nalin@redhat.com> 0.9.7a-22
- rebuild (22 wasn't actually built, fun eh?)

* Tue Sep 30 2003 Nalin Dahyabhai <nalin@redhat.com> 0.9.7a-23
- re-disable optimizations on ppc64

* Tue Sep 30 2003 Joe Orton <jorton@redhat.com>
- add a_mbstr.c fix for 64-bit platforms from CVS

* Tue Sep 30 2003 Nalin Dahyabhai <nalin@redhat.com> 0.9.7a-22
- add -Wa,--noexecstack to RPM_OPT_FLAGS so that assembled modules get tagged
  as not needing executable stacks

* Mon Sep 29 2003 Nalin Dahyabhai <nalin@redhat.com> 0.9.7a-21
- rebuild

* Thu Sep 25 2003 Nalin Dahyabhai <nalin@redhat.com>
- re-enable optimizations on ppc64

* Thu Sep 25 2003 Nalin Dahyabhai <nalin@redhat.com>
- remove exclusivearch

* Wed Sep 24 2003 Nalin Dahyabhai <nalin@redhat.com> 0.9.7a-20
- only parse a client cert if one was requested
- temporarily exclusivearch for %%{ix86}

* Tue Sep 23 2003 Nalin Dahyabhai <nalin@redhat.com>
- add security fixes for protocol parsing bugs (CAN-2003-0543, CAN-2003-0544)
  and heap corruption (CAN-2003-0545)
- update RHNS-CA-CERT files
- ease back on the number of threads used in the threading test

* Wed Sep 17 2003 Matt Wilson <msw@redhat.com> 0.9.7a-19
- rebuild to fix gzipped file md5sums (#91211)

* Mon Aug 25 2003 Phil Knirsch <pknirsch@redhat.com> 0.9.7a-18
- Updated libica to version 1.3.4.

* Thu Jul 17 2003 Nalin Dahyabhai <nalin@redhat.com> 0.9.7a-17
- rebuild

* Tue Jul 15 2003 Nalin Dahyabhai <nalin@redhat.com> 0.9.7a-10.9
- free the kssl_ctx structure when we free an SSL structure (#99066)

* Fri Jul 10 2003 Nalin Dahyabhai <nalin@redhat.com> 0.9.7a-16
- rebuild

* Thu Jul 10 2003 Nalin Dahyabhai <nalin@redhat.com> 0.9.7a-15
- lower thread test count on s390x

* Tue Jul  8 2003 Nalin Dahyabhai <nalin@redhat.com> 0.9.7a-14
- rebuild

* Thu Jun 26 2003 Nalin Dahyabhai <nalin@redhat.com> 0.9.7a-13
- disable assembly on arches where it seems to conflict with threading

* Thu Jun 26 2003 Phil Knirsch <pknirsch@redhat.com> 0.9.7a-12
- Updated libica to latest upstream version 1.3.0

* Wed Jun 11 2003 Nalin Dahyabhai <nalin@redhat.com> 0.9.7a-9.9
- rebuild

* Wed Jun 11 2003 Nalin Dahyabhai <nalin@redhat.com> 0.9.7a-11
- rebuild

* Tue Jun 10 2003 Nalin Dahyabhai <nalin@redhat.com> 0.9.7a-10
- ubsec: don't stomp on output data which might also be input data

* Tue Jun 10 2003 Nalin Dahyabhai <nalin@redhat.com> 0.9.7a-9
- temporarily disable optimizations on ppc64

* Mon Jun  9 2003 Nalin Dahyabhai <nalin@redhat.com>
- backport fix for engine-used-for-everything from 0.9.7b
- backport fix for prng not being seeded causing problems, also from 0.9.7b
- add a check at build-time to ensure that RSA is thread-safe
- keep perlpath from stomping on the libica configure scripts

* Fri Jun  6 2003 Nalin Dahyabhai <nalin@redhat.com>
- thread-safety fix for RSA blinding

* Wed Jun 04 2003 Elliot Lee <sopwith@redhat.com> 0.9.7a-8
- rebuilt

* Fri May 30 2003 Phil Knirsch <pknirsch@redhat.com> 0.9.7a-7
- Added libica-1.2 to openssl (featurerequest).

* Wed Apr 16 2003 Nalin Dahyabhai <nalin@redhat.com> 0.9.7a-6
- fix building with incorrect flags on ppc64

* Wed Mar 19 2003 Nalin Dahyabhai <nalin@redhat.com> 0.9.7a-5
- add patch to harden against Klima-Pokorny-Rosa extension of Bleichenbacher's
  attack (CAN-2003-0131)

* Mon Mar 17 2003 Nalin Dahyabhai <nalin@redhat.com>  0.9.7a-4
- add patch to enable RSA blinding by default, closing a timing attack
  (CAN-2003-0147)

* Wed Mar  5 2003 Nalin Dahyabhai <nalin@redhat.com> 0.9.7a-3
- disable use of BN assembly module on x86_64, but continue to allow inline
  assembly (#83403)

* Thu Feb 27 2003 Nalin Dahyabhai <nalin@redhat.com> 0.9.7a-2
- disable EC algorithms

* Wed Feb 19 2003 Nalin Dahyabhai <nalin@redhat.com> 0.9.7a-1
- update to 0.9.7a

* Wed Feb 19 2003 Nalin Dahyabhai <nalin@redhat.com> 0.9.7-8
- add fix to guard against attempts to allocate negative amounts of memory
- add patch for CAN-2003-0078, fixing a timing attack

* Thu Feb 13 2003 Elliot Lee <sopwith@redhat.com> 0.9.7-7
- Add openssl-ppc64.patch

* Mon Feb 10 2003 Nalin Dahyabhai <nalin@redhat.com> 0.9.7-6
- EVP_DecryptInit should call EVP_CipherInit() instead of EVP_CipherInit_ex(),
  to get the right behavior when passed uninitialized context structures
  (#83766)
- build with -mcpu=ev5 on alpha family (#83828)

* Wed Jan 22 2003 Tim Powers <timp@redhat.com>
- rebuilt

* Fri Jan 17 2003 Phil Knirsch <pknirsch@redhat.com> 0.9.7-4
- Added IBM hw crypto support patch.

* Wed Jan 15 2003 Nalin Dahyabhai <nalin@redhat.com>
- add missing builddep on sed

* Thu Jan  9 2003 Bill Nottingham <notting@redhat.com> 0.9.7-3
- debloat
- fix broken manpage symlinks

* Wed Jan  8 2003 Nalin Dahyabhai <nalin@redhat.com> 0.9.7-2
- fix double-free in 'openssl ca'

* Fri Jan  3 2003 Nalin Dahyabhai <nalin@redhat.com> 0.9.7-1
- update to 0.9.7 final

* Tue Dec 17 2002 Nalin Dahyabhai <nalin@redhat.com> 0.9.7-0
- update to 0.9.7 beta6 (DO NOT USE UNTIL UPDATED TO FINAL 0.9.7)

* Wed Dec 11 2002 Nalin Dahyabhai <nalin@redhat.com>
- update to 0.9.7 beta5 (DO NOT USE UNTIL UPDATED TO FINAL 0.9.7)

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
- own _datadir/ssl/misc

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
