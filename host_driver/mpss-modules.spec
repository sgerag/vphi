%define debug_package %{nil}
%{!?KERNEL_VERSION: %define KERNEL_VERSION %(uname -r)}
%{!?KERNEL_SRC: %define KERNEL_SRC "/lib/modules/%{KERNEL_VERSION}/build"}

Name:        mpss-modules
BuildRoot:   %{_topdir}/BUILDROOT
Version:     3.5.2
Release:     1
Source0:     mpss-modules-3.5.2.tar.bz2
Summary:     Intel® Xeon Phi™ product family
Group:       System Environment/Kernel
License:     GPLv2
URL:         http://www.intel.com
Vendor:      Intel Corporation
%if %{_vendor} == suse
BuildRequires: kernel-headers kernel-default-devel
%else
BuildRequires: kernel-headers kernel-devel
%endif
Autoreq: 0

%description
Provides driver and firmware for Intel® Xeon Phi™ coprocessor cards

%package -n mpss-modules-%{KERNEL_VERSION}
Group:       System Environment/Kernel
Summary:     Host driver for Intel® Xeon Phi™ coprocessor cards
%description -n mpss-modules-%{KERNEL_VERSION}
Provides host driver for Intel® Xeon Phi™ coprocessor cards

%package -n mpss-modules-dev-%{KERNEL_VERSION}
Group:       System Environment/Kernel
Summary:     Header and symbol version file for driver development
%description -n mpss-modules-dev-%{KERNEL_VERSION}
Provides header and symbol version file for driver development

%prep
%setup  -c -T -a 0

%build
[ -d modules ] && cd modules
%{__make} %{?_smp_mflags} KERNEL_VERSION=%{KERNEL_VERSION} KERNEL_SRC=%{KERNEL_SRC} CC="%{__cc}" LD="ld " MIC_CARD_ARCH=k1om 

%install
[ -d modules ] && cd modules
%{__make} KERNEL_VERSION=%{KERNEL_VERSION} KERNEL_SRC=%{KERNEL_SRC} kmodincludedir="/usr/src/kernels/%{KERNEL_VERSION}/include/modules" DESTDIR=%{buildroot} MIC_CARD_ARCH=k1om prefix="" install
# Cleanup unnecessary kernel-generated module dependency files.
find %{buildroot}/lib/modules -iname modules.\* -exec rm {} \;

%post -n mpss-modules-%{KERNEL_VERSION}
/sbin/depmod -a %{KERNEL_VERSION}

%postun -n mpss-modules-%{KERNEL_VERSION}
/sbin/depmod -a %{KERNEL_VERSION}

%files -n mpss-modules-%{KERNEL_VERSION}
%defattr (-,root,root)
/etc/modprobe.d/mic.conf
/etc/sysconfig/modules/mic.modules
/etc/udev/rules.d/50-udev-mic.rules
/lib/modules/%{KERNEL_VERSION}/extra/mic.ko

%files -n mpss-modules-dev-%{KERNEL_VERSION}
%defattr (-,root,root)
/lib/modules/%{KERNEL_VERSION}/scif.symvers
/usr/src/kernels/%{KERNEL_VERSION}/include/modules/scif.h

%changelog
