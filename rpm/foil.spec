Name: libfoil
Version: 1.0.19
Release: 0
Summary: Yet another glib-style crypto API
Group: Development/Libraries
License: BSD
Vendor: slava
URL: https://github.com/monich/foil
Source: %{name}-%{version}.tar.bz2

%define glib_version 2.36
%define libglibutil_version 1.0.24

BuildRequires: file-devel
BuildRequires: pkgconfig(openssl)
BuildRequires: pkgconfig(libpng)
BuildRequires: pkgconfig(glib-2.0) >= %{glib_version}
BuildRequires: pkgconfig(libglibutil) >= %{libglibutil_version}
Requires: glib2 >= %{glib_version}
Requires: libglibutil >= %{libglibutil_version}
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description
Provides glib based cryptography API.

%package devel
Summary: Development library for %{name}
Requires: %{name} = %{version}
Requires: pkgconfig

%description devel
This package contains the development library for %{name}.

%package -n foil-tools
Summary: Encryption/decryption utilities
Group: Applications/File
Requires: libfoil >= 1.0.13

%description -n foil-tools
Command line encryption/decryption utilities.

%prep
%setup -q

%build
make -C libfoil KEEP_SYMBOLS=1 release pkgconfig
make -C tools KEEP_SYMBOLS=1 release

%install
rm -rf %{buildroot}
make -C libfoil install-dev DESTDIR=%{buildroot}
make -C tools install DESTDIR=%{buildroot}

%check
make check

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%defattr(-,root,root,-)
%{_libdir}/%{name}.so.*

%files devel
%defattr(-,root,root,-)
%{_libdir}/pkgconfig/*.pc
%{_libdir}/%{name}.so
%{_includedir}/foil/*.h

%files -n foil-tools
%defattr(-,root,root,-)
%{_bindir}/foilmsg
%{_bindir}/foilpng
