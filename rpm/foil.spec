Name: libfoil

Version: 1.0.27
Release: 0
Summary: Yet another glib-style crypto API
Group: Development/Libraries
License: BSD
Vendor: slava
URL: https://github.com/monich/foil
Source: %{name}-%{version}.tar.bz2

%define glib_version 2.36
%define libglibutil_version 1.0.24
%define libglibutil_build_version 1.0.54

BuildRequires: file-devel
BuildRequires: pkgconfig
BuildRequires: pkgconfig(openssl)
BuildRequires: pkgconfig(libpng)
BuildRequires: pkgconfig(glib-2.0) >= %{glib_version}
BuildRequires: pkgconfig(libglibutil) >= %{libglibutil_build_version}
Requires: glib2 >= %{glib_version}
Requires: libglibutil >= %{libglibutil_version}
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description
Provides glib based cryptography API.

%package devel
Summary: Development library for %{name}
Group: Development/Libraries
Requires: %{name} = %{version}
Requires: pkgconfig(libglibutil) >= %{libglibutil_build_version}

%description devel
This package contains the development library for %{name}.

%package -n libfoilmsg-devel
Summary: Library for encrypting and decrypting messages
Group: Development/Libraries
Requires: pkgconfig(libfoil)

%description -n libfoilmsg-devel
This package contains the development library for libfoilmsg.

%package -n foil-tools
Summary: Encryption/decryption utilities
Group: Applications/File
Requires: libfoil >= %{version}

%description -n foil-tools
Command line encryption/decryption utilities.

%prep
%setup -q

%build
make -C libfoil %{_smp_mflags} LIBDIR=%{_libdir} KEEP_SYMBOLS=1 release pkgconfig
make -C libfoilmsg %{_smp_mflags} LIBDIR=%{_libdir} KEEP_SYMBOLS=1 release pkgconfig
make -C tools %{_smp_mflags} LIBDIR=%{_libdir} KEEP_SYMBOLS=1 release

%install
make -C libfoil DESTDIR=%{buildroot} LIBDIR=%{_libdir} install-dev
make -C libfoilmsg DESTDIR=%{buildroot} LIBDIR=%{_libdir} install-dev
make -C tools DESTDIR=%{buildroot} install

%check
make check

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%defattr(-,root,root,-)
%{_libdir}/%{name}.so.*

%files devel
%defattr(-,root,root,-)
%dir %{_includedir}/foil
%{_libdir}/pkgconfig/libfoil.pc
%{_libdir}/%{name}.so
%{_includedir}/foil/*.h

%files -n libfoilmsg-devel
%defattr(-,root,root,-)
%dir %{_includedir}/foilmsg
%{_libdir}/pkgconfig/libfoilmsg.pc
%{_libdir}/libfoilmsg.a
%{_includedir}/foilmsg/*.h

%files -n foil-tools
%defattr(-,root,root,-)
%{_bindir}/foilmsg
%{_bindir}/foilpng
