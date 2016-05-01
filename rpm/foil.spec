Name: libfoil
Version: 1.0.0
Release: 0
Summary: Cryptography library based on glib
Group: Development/Libraries
License: BSD
Vendor: slava
URL: https://github.com/monich/foil
Source: %{name}-%{version}.tar.bz2
BuildRequires: pkgconfig(openssl)
BuildRequires: pkgconfig(glib-2.0) >= 2.36
BuildRequires: pkgconfig(libglibutil) >= 1.0.24
Requires: glib2 >= 2.36
Requires: libglibutil >= 1.0.24
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description
Provides glib based cryptography functions.

%package devel
Summary: Development library for %{name}
Requires: %{name} = %{version}
Requires: pkgconfig

%description devel
This package contains the development library for %{name}.

%package -n foilmsg
Summary: Encryption/decryption utility
Group: Applications/File
Requires: libfoil

%description -n foilmsg
Command line encryption/decryption utility.

%prep
%setup -q

%build
make -C libfoil KEEP_SYMBOLS=1 release pkgconfig
make -C foilmsg KEEP_SYMBOLS=1 release

%install
rm -rf %{buildroot}
make -C libfoil install-dev DESTDIR=%{buildroot}
make -C foilmsg install DESTDIR=%{buildroot}

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

%files -n foilmsg
%defattr(-,root,root,-)
%{_bindir}/foilmsg
