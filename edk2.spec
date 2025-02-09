%global stable_date 202011
%global release_tag edk2-stable%{stable_date}
%global openssl_version 1.1.1f
%global _python_bytecompile_extra 0

Name: edk2
Version: %{stable_date}
Release: 11
Summary: EFI Development Kit II
License: BSD-2-Clause-Patent
URL: https://github.com/tianocore/edk2
Source0: https://github.com/tianocore/edk2/archive/%{release_tag}.tar.gz
Source1: openssl-%{openssl_version}.tar.gz
Source2: brotli.tar.gz

# for CVE-2021-38575
Patch0001: 0001-NetworkPkg-IScsiDxe-wrap-IScsiCHAP-source-files-to-8.patch
Patch0002: 0002-NetworkPkg-IScsiDxe-simplify-ISCSI_CHAP_AUTH_DATA.In.patch
Patch0003: 0003-NetworkPkg-IScsiDxe-clean-up-ISCSI_CHAP_AUTH_DATA.Ou.patch
Patch0004: 0004-NetworkPkg-IScsiDxe-clean-up-library-class-dependenc.patch
Patch0005: 0005-NetworkPkg-IScsiDxe-fix-potential-integer-overflow-i.patch
Patch0006: 0006-NetworkPkg-IScsiDxe-assert-that-IScsiBinToHex-always.patch
Patch0007: 0007-NetworkPkg-IScsiDxe-reformat-IScsiHexToBin-leading-c.patch
Patch0008: 0008-NetworkPkg-IScsiDxe-fix-IScsiHexToBin-hex-parsing.patch
Patch0009: 0009-NetworkPkg-IScsiDxe-fix-IScsiHexToBin-buffer-overflo.patch
Patch0010: 0010-NetworkPkg-IScsiDxe-check-IScsiHexToBin-return-value.patch

# for CVE-2021-28216
Patch0011: 0011-MdeModulePkg-FPDT-Lock-boot-performance-table-addres.patch

# for CVE-2021-38576
Patch0012: 0012-SecurityPkg-TPM-Import-PeiDxeTpmPlatformHierarchyLib.patch
Patch0013: 0013-SecurityPkg-TPM-Fix-bugs-in-imported-PeiDxeTpmPlatfo.patch
Patch0014: 0014-SecrutiyPkg-Tcg-Import-Tcg2PlatformDxe-from-edk2-pla.patch
Patch0015: 0015-SecurityPkg-Tcg-Make-Tcg2PlatformDxe-buildable-and-f.patch
Patch0016: 0016-SecurityPkg-Introduce-new-PCD-PcdRandomizePlatformHi.patch
Patch0017: 0017-SecurityPkg-Tcg-Import-Tcg2PlatformPei-from-edk2-pla.patch
Patch0018: 0018-SecurityPkg-Tcg-Make-Tcg2PlatformPei-buildable-and-f.patch
Patch0019: 0019-SecurityPkg-Add-references-to-header-and-inf-files-t.patch

Patch0020: 0020-OvmfPkg-VirtioNetDxe-Extend-the-RxBufferSize-to-avoi.patch

Patch0021: 0021-UefiCpuPkg-Move-MigrateGdt-from-DiscoverMemory-to-Te.patch

Patch0022: 0022-MdeModulePkg-PiSmmCore-SmmEntryPoint-underflow-CVE-2.patch
Patch0023: 0023-PATCH-Avoid-dangling-ptrs-in-header-and-data-params-.patch
Patch0024: 0024-PATCH-pk7_doit.c-Check-return-of-BIO_set_md-calls.patch
Patch0025: 0025-Fix-a-UAF-resulting-from-a-bug-in-BIO_new_NDEF.patch
Patch0026: 0026-Check-CMS-failure-during-BIO-setup-with-stream-is-ha.patch
Patch0027: 0027-Correctly-compare-EdiPartyName-in-GENERAL_NAME_cmp.patch
Patch0028: 0028-CVE-2023-0286-Fix-GENERAL_NAME_cmp-for-x400Address-1.patch

BuildRequires: acpica-tools gcc gcc-c++ libuuid-devel python3 bc nasm python3-unversioned-command

%description
EDK II is a modern, feature-rich, cross-platform firmware development environment for the UEFI and PI specifications. 

%package devel
Summary: EFI Development Kit II Tools
%description devel
This package provides tools that are needed to build EFI executables and ROMs using the GNU tools.

%package -n python3-%{name}-devel
Summary: EFI Development Kit II Tools
Requires: python3
BuildArch: noarch
%description -n python3-%{name}-devel
This package provides tools that are needed to build EFI executables and ROMs using the GNU tools.

%package help
Summary: Documentation for EFI Development Kit II Tools
BuildArch: noarch
%description help
This package documents the tools that are needed to build EFI executables and ROMs using the GNU tools.

%ifarch aarch64
%package aarch64
Summary: AARCH64 Virtual Machine Firmware
BuildArch: noarch
%description aarch64
EFI Development Kit II AARCH64 UEFI Firmware
%endif

%ifarch x86_64
%package ovmf
Summary: Open Virtual Machine Firmware
BuildArch: noarch
%description ovmf
EFI Development Kit II Open Virtual Machine Firmware (x64)
%endif

%ifarch %{ix86}
%package ovmf-ia32
Summary: Open Virtual Machine Firmware
BuildArch: noarch
%description ovmf-ia32
EFI Development Kit II Open Virtual Machine Firmware (ia32)
%endif

%prep
%setup -n edk2-%{release_tag}
tar -xf %{SOURCE1} -C CryptoPkg/Library/OpensslLib/openssl --strip-components=1
tar -xf %{SOURCE2} -C MdeModulePkg/Library/BrotliCustomDecompressLib/brotli --strip-components=1
tar -xf %{SOURCE2} -C BaseTools/Source/C/BrotliCompress/brotli --strip-components=1
%autopatch -p1

%build
NCPUS=`/usr/bin/getconf _NPROCESSORS_ONLN`
BUILD_OPTION="-t GCC5 -n $NCPUS -b RELEASE"

make -C BaseTools %{?_smp_mflags} EXTRA_OPTFLAGS="%{optflags}" EXTRA_LDFLAGS="%{__global_ldflags}"
. ./edksetup.sh

COMMON_FLAGS="-D NETWORK_IP6_ENABLE"
%ifarch aarch64
    BUILD_OPTION="$BUILD_OPTION -a AARCH64 -p ArmVirtPkg/ArmVirtQemu.dsc --cmd-len=65536 $COMMON_FLAGS"
%endif

%ifarch x86_64
    BUILD_OPTION="$BUILD_OPTION -a X64 -p OvmfPkg/OvmfPkgX64.dsc $COMMON_FLAGS"
%endif

%ifarch %{ix86}
    BUILD_OPTION="$BUILD_OPTION -a IA32 -p OvmfPkg/OvmfPkgIa32.dsc"
%endif
BUILD_OPTION="$BUILD_OPTION -D SECURE_BOOT_ENABLE=TRUE"
BUILD_OPTION="$BUILD_OPTION -D TPM2_ENABLE=TRUE"
BUILD_OPTION="$BUILD_OPTION -D TPM2_CONFIG_ENABLE=TRUE"
BUILD_OPTION="$BUILD_OPTION -D TPM_ENABLE=TRUE"
BUILD_OPTION="$BUILD_OPTION -D TPM_CONFIG_ENABLE=TRUE"
build $BUILD_OPTION

%install
cp CryptoPkg/Library/OpensslLib/openssl/LICENSE LICENSE.openssl
mkdir -p %{buildroot}%{_bindir} \
         %{buildroot}%{_datadir}/%{name}/Conf \
         %{buildroot}%{_datadir}/%{name}/Scripts
install BaseTools/Source/C/bin/* %{buildroot}%{_bindir}
install BaseTools/BuildEnv %{buildroot}%{_datadir}/%{name}
install BaseTools/Conf/*.template %{buildroot}%{_datadir}/%{name}/Conf
install BaseTools/Scripts/GccBase.lds %{buildroot}%{_datadir}/%{name}/Scripts

cp -R BaseTools/Source/Python %{buildroot}%{_datadir}/%{name}/Python
find %{buildroot}%{_datadir}/%{name}/Python -name '__pycache__'|xargs rm -rf 

for i in build BPDG GenDepex GenFds GenPatchPcdTable PatchPcdValue Pkcs7Sign Rsa2048Sha256Sign TargetTool Trim UPT; do
echo '#!/usr/bin/env bash
export PYTHONPATH=%{_datadir}/%{name}/Python${PYTHONPATH:+:"$PYTHONPATH"}
exec python3 '%{_datadir}/%{name}/Python/$i/$i.py' "$@"' > %{buildroot}%{_bindir}/$i
  chmod +x %{buildroot}%{_bindir}/$i
done

echo '#!/usr/bin/env bash
export PYTHONPATH=%{_datadir}/%{name}/Python${PYTHONPATH:+:"$PYTHONPATH"}
exec python3 '%{_datadir}/%{name}/Python/Ecc/EccMain.py' "$@"' > %{buildroot}%{_bindir}/Ecc
chmod +x %{buildroot}%{_bindir}/Ecc

echo '#!/usr/bin/env bash
export PYTHONPATH=%{_datadir}/%{name}/Python${PYTHONPATH:+:"$PYTHONPATH"}
exec python3 '%{_datadir}/%{name}/Python/Capsule/GenerateCapsule.py' "$@"' > %{buildroot}%{_bindir}/GenerateCapsule
chmod +x %{buildroot}%{_bindir}/GenerateCapsule

echo '#!/usr/bin/env bash
export PYTHONPATH=%{_datadir}/%{name}/Python${PYTHONPATH:+:"$PYTHONPATH"}
exec python3 '%{_datadir}/%{name}/Python/Rsa2048Sha256Sign/Rsa2048Sha256GenerateKeys.py' "$@"' > %{buildroot}%{_bindir}/Rsa2048Sha256GenerateKeys
chmod +x %{buildroot}%{_bindir}/Rsa2048Sha256GenerateKeys

%ifarch aarch64
    mkdir -p %{buildroot}/usr/share/%{name}/aarch64
    cp Build/ArmVirtQemu-AARCH64/RELEASE_*/FV/*.fd %{buildroot}/usr/share/%{name}/aarch64
    dd of="%{buildroot}/usr/share/%{name}/aarch64/QEMU_EFI-pflash.raw" if="/dev/zero" bs=1M count=64
    dd of="%{buildroot}/usr/share/%{name}/aarch64/QEMU_EFI-pflash.raw" if="%{buildroot}/usr/share/%{name}/aarch64/QEMU_EFI.fd" conv=notrunc
    dd of="%{buildroot}/usr/share/%{name}/aarch64/vars-template-pflash.raw" if="/dev/zero" bs=1M count=64
%endif

%ifarch x86_64
    mkdir -p %{buildroot}/usr/share/%{name}/ovmf
    cp Build/OvmfX64/*/FV/OVMF*.fd %{buildroot}/usr/share/%{name}/ovmf
%endif

%ifarch %{ix86}
    mkdir -p %{buildroot}/usr/share/%{name}/ovmf-ia32
    cp Build/OvmfIa32/*/FV/OVMF_CODE.fd %{buildroot}/usr/share/%{name}/ovmf-ia32
%endif

%files devel
%license License.txt
%license LICENSE.openssl
%{_bindir}/BrotliCompress
%{_bindir}/DevicePath
%{_bindir}/EfiRom
%{_bindir}/GenCrc32
%{_bindir}/GenFfs
%{_bindir}/GenFv
%{_bindir}/GenFw
%{_bindir}/GenSec
%{_bindir}/LzmaCompress
%{_bindir}/Split
%{_bindir}/TianoCompress
%{_bindir}/VfrCompile
%{_bindir}/VolInfo
%{_datadir}/%{name}/BuildEnv
%{_datadir}/%{name}/Conf
%{_datadir}/%{name}/Scripts

%files -n python3-%{name}-devel
%{_bindir}/BPDG
%{_bindir}/Ecc
%{_bindir}/GenDepex
%{_bindir}/GenFds
%{_bindir}/GenPatchPcdTable
%{_bindir}/GenerateCapsule
%{_bindir}/Pkcs7Sign
%{_bindir}/PatchPcdValue
%{_bindir}/Rsa2048Sha256GenerateKeys
%{_bindir}/Rsa2048Sha256Sign
%{_bindir}/TargetTool
%{_bindir}/Trim
%{_bindir}/UPT
%{_bindir}/build
%dir %{_datadir}/%{name}
%{_datadir}/%{name}/Python

%files help
%doc BaseTools/UserManuals/*.rtf

%ifarch aarch64
%files aarch64
%license OvmfPkg/License.txt
%license LICENSE.openssl
%dir /usr/share/%{name}
%dir /usr/share/%{name}/aarch64
/usr/share/%{name}/aarch64/QEMU*.fd
/usr/share/%{name}/aarch64/*.raw
%endif

%ifarch x86_64
%files ovmf
%license OvmfPkg/License.txt
%license LICENSE.openssl
%dir %{_datadir}/%{name}
%{_datadir}/%{name}/ovmf
%endif

%ifarch %{ix86}
%license OvmfPkg/License.txt
%license LICENSE.openssl
%files ovfm-ia32
%dir /usr/share/%{name}
%endif

%changelog
* Sun Feb 26 2023 chenhuiying<chenhuiying4@huawei.com> - 202011-11
- fix CVE-2023-0286

* Sun Feb 26 2023 chenhuiying<chenhuiying4@huawei.com> - 202011-10
- fix CVE-2023-0215

* Sat Feb 25 2023 shaodenghui<shaodenghui@huawei.com> - 202011-9
- fix CVE-2023-0401

* Mon Feb 20 2023 shaodenghui<shaodenghui@huawei.com> - 202011-8
- fix CVE-2022-4450

* Tue Nov 29 2022 chenhuiying<chenhuiying4@huawei.com> - 202011-7
- fix CVE-2021-38578

* Thu Sep 29 2022 chenhuiying<chenhuiying4@huawei.com> - 202011-6
* fix CVE-2019-11098

* Tue Jun 14 2022 miaoyubo <miaoyubo@huawei.com> - 202011-5
- Enable TPM for pcr0-7

* Wed Apr 27 2022 yezengruan <yezengruan@huawei.com> - 202011-4
- update the format of changelog

* Thu Feb 17 2022 Jinhua Cao <caojinhua1@huawei.com> - 202011-3
- OvmfPkg: VirtioNetDxe: Extend the RxBufferSize to avoid data truncation

* Tue Feb 15 2022 Jinhua Cao <caojinhua1@huawei.com> - 202011-2
- fix CVE-2021-38576

* Mon Feb 7 2022 Jinhua Cao <caojinhua1@huawei.com> - 202011-1
- update edk2 to stable 202011

* Wed Jan 12 2022 Jinhua Cao <caojinhua1@huawei.com> - 202002-11
- BaseTools: fix ucs-2 lookup on python3.9
- BaseTools: Work around array.array.tostring() removal in python3.9

* Wed Dec 1 2021 Jinhua Cao <caojinhua1@huawei.com> - 202002-10
- fix CVE-2021-28216

* Wed Sep 22 2021 imxcc <xingchaochao@huawei.com> - 202002-9
- fix cve-2021-38575

* Tue Aug 31 2021 miaoyubo <miaoyubo@huawei.com> - 202002-8
- MdeModulePkg/LzmaCustomDecompressLib: catch 4GB+ uncompressed

* Fri Jul 30 2021 Zhenyu Ye <yezhenyu2@huawei.com> - 202002-7
- ArmPkg/CompilerIntrinsicsLib: provide atomics intrinsics

* Mon Jun 28 2021 Jiajie Li <lijiajie11@huawei.com> - 202002-6
- Fix CVE-2021-28210

* Tue Oct 27 2020 AlexChen <alex.chen@huawei.com> - 202002-5
- remove build requires of python2

* Mon Sep 28 2020 FangYing <fangying1@huawei.com> - 202002-4
- update the Source0 to http url

* Fri Jul 31 2020 jiangfangjie <jiangfangjie@huawei.com> - 202002-3
- ArmVirtPkg/ArmVirtQemu: enable TPM2 based measured boot
- ArmVirtPkg/ArmVirtQemu: enable the TPM2 configuration module

* Mon Jul 27 2020 zhangxinhao <zhangxinhao1@huawei.com> - 202002-2
- add build option "-D SECURE_BOOT_ENABLE=TRUE" to enable secure boot

* Thu May 7 2020 openEuler Buildteam <buildteam@openeuler.org> - 202002-1
- Update edk2 to stable202002 and OpenSSL to 1.1.1f

* Thu Mar 19 2020 openEuler Buildteam <buildteam@openeuler.org> - 201908-9
- fix an overflow bug in rsaz_512_sqr
- use the correct maximum indent

* Tue Mar 17 2020 openEuler Buildteam <buildteam@openeuler.org> - 201908-8
- enable multiple threads compiling
- Pass EXTRA_OPTFLAGS and EXTRA_OPTFLAGS options to make command
- enable IPv6 for X86_64

* Sun Mar 15 2020 openEuler Buildteam <buildteam@openeuler.org> - 201908-7
- fix missing OVMF.fd in package

* Sat Feb 22 2020 openEuler Buildteam <buildteam@openeuler.org> - 201908-6
- add build requires of python2

* Mon Dec 30 2019 Heyi Guo <buildteam@openeuler.org> - 201908-5
- Upgrade openssl to 1.1.1d

* Tue Nov 26 2019 openEuler Buildteam <buildteam@openeuler.org> - 201908-4
- add build requires of nasm

* Tue Nov 26 2019 openEuler Buildteam <buildteam@openeuler.org> - 201908-3
- Correct name of package ovmf

* Mon Sep 30 2019  zhanghailiang <zhang.zhanghailiang@huawei.com> - 201908-2
- Enable IPv6 suppport and Modify Release number to 2

* Wed Sep 18 2019 openEuler Buildteam <buildteam@openeuler.org> - 201908-1
- Package init
