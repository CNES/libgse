Summary:        Generic Stream Encapsulation (GSE) library
Name:           libgse
Version:        1.x.x.bzr+50
Release:        tas.1.1.el6%{?ci_flag}
License:        LGPLv3
Group:          System Environment/Libraries
URL:            https://code.launchpad.net/libgse
Vendor:         Thales AS
Source0:        %{name}-%{version}.tar.gz
BuildRequires:  automake autoconf libtool pkgconfig libpcap-devel
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root

%description
GSE (Generic Stream Encapsulation) library.

%package devel
Requires:   gse = %{version}
Summary:    Include and pkgconfig files for the GSE library
Group:      Development/Libraries

%description devel
Include and pkgconfig files for the GSE library

%prep
%setup

%build
./autogen.sh
%configure
make

%install
make DESTDIR=%{buildroot} install

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%{_libdir}/libgse.so
%{_libdir}/libgse.so.0
%{_libdir}/libgse.so.0.0.0

%files devel
%defattr(-,root,root,-)
%{_includedir}/gse/constants.h
%{_includedir}/gse/deencap.h
%{_includedir}/gse/deencap_header_ext.h
%{_includedir}/gse/encap.h
%{_includedir}/gse/encap_header_ext.h
%{_includedir}/gse/header_fields.h
%{_includedir}/gse/refrag.h
%{_includedir}/gse/status.h
%{_includedir}/gse/virtual_fragment.h
%{_libdir}/pkgconfig/gse.pc
%{_libdir}/libgse.la
%doc %{_defaultdocdir}/gse

%changelog
* Wed Aug 21 2013 Audric Schiltknecht <audric.schiltknecht@external.thalesaleniaspace.com> 1.x.x.bzr+50
- Initial RPM release.
