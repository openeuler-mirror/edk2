%global stable_date 202002
%global release_tag edk2-stable%{stable_date}
%global openssl_version 1.1.1f
%global _python_bytecompile_extra 0

Name: edk2
Version: %{stable_date}
Release: 15
Summary: EFI Development Kit II
License: BSD-2-Clause-Patent
URL: https://github.com/tianocore/edk2
Source0: %{release_tag}.tar.gz
Source1: openssl-%{openssl_version}.tar.gz

Patch0001: 0001-CryptoPkg-OpensslLib-Modify-process_files.pl-for-Ope.patch
Patch0002: 0002-CryptoPkg-Upgrade-OpenSSL-to-1.1.1f.patch
Patch0003: 0001-SecurityPkg-DxeImageVerificationLib-extract-SecDataD.patch
Patch0004: 0002-SecurityPkg-DxeImageVerificationLib-assign-WinCertif.patch
Patch0005: 0003-SecurityPkg-DxeImageVerificationLib-catch-alignment-.patch
Patch0006: 0004-MdeModulePkg-Core-Dxe-assert-SectionInstance-invariant-in-FindChildNode.patch
Patch0007: 0005-MdeModulePkg-Core-Dxe-limit-FwVol-encapsulation-section-recursion.patch
Patch0008: 0006-MdeModulePkg-LzmaCustomDecompressLib-catch-4GB-uncom.patch
Patch0009: 0007-NetworkPkg-IScsiDxe-wrap-IScsiCHAP-source-files-to-8.patch
Patch0010: 0008-NetworkPkg-IScsiDxe-simplify-ISCSI_CHAP_AUTH_DATA.In.patch
Patch0011: 0009-NetworkPkg-IScsiDxe-clean-up-ISCSI_CHAP_AUTH_DATA.Ou.patch
Patch0012: 0010-NetworkPkg-IScsiDxe-clean-up-library-class-dependenc.patch
Patch0013: 0011-NetworkPkg-IScsiDxe-fix-potential-integer-overflow-i.patch
Patch0014: 0012-NetworkPkg-IScsiDxe-assert-that-IScsiBinToHex-always.patch
Patch0015: 0013-NetworkPkg-IScsiDxe-reformat-IScsiHexToBin-leading-c.patch
Patch0016: 0014-NetworkPkg-IScsiDxe-fix-IScsiHexToBin-hex-parsing.patch
Patch0017: 0015-NetworkPkg-IScsiDxe-fix-IScsiHexToBin-buffer-overflo.patch
Patch0018: 0016-NetworkPkg-IScsiDxe-check-IScsiHexToBin-return-value.patch
Patch0019: 0017-MdeModulePkg-FPDT-Lock-boot-performance-table-addres.patch
Patch0020: 0018-SecurityPkg-TPM-Import-PeiDxeTpmPlatformHierarchyLib.patch
Patch0021: 0019-SecurityPkg-TPM-Fix-bugs-in-imported-PeiDxeTpmPlatfo.patch
Patch0022: 0020-SecrutiyPkg-Tcg-Import-Tcg2PlatformDxe-from-edk2-pla.patch
Patch0023: 0021-SecurityPkg-Tcg-Make-Tcg2PlatformDxe-buildable-and-f.patch
Patch0024: 0022-SecurityPkg-Introduce-new-PCD-PcdRandomizePlatformHi.patch
Patch0025: 0023-SecurityPkg-Tcg-Import-Tcg2PlatformPei-from-edk2-pla.patch
Patch0026: 0024-SecurityPkg-Tcg-Make-Tcg2PlatformPei-buildable-and-f.patch
Patch0027: 0025-SecurityPkg-Add-references-to-header-and-inf-files-t.patch
Patch0028: 0026-CryptoPkg-BaseCryptLib-fix-NULL-dereference-CVE-2019.patch
Patch0029: 0027-UefiCpuPkg-Correct-some-typos.patch
Patch0030: 0028-UefiCpuPkg-SecMigrationPei-Add-initial-PEIM-CVE-2019.patch
Patch0031: 0029-MdeModulePkg-PeiCore-Enable-T-RAM-evacuation-in-PeiC.patch
Patch0032: 0030-SecurityPkg-Tcg2Pei-Use-Migrated-FV-Info-Hob-for-cal.patch
Patch0033: 0031-MdeModulePkg-Add-new-PCD-to-control-the-evacuate-tem.patch
Patch0034: 0032-MdeModulePkg-Core-Create-Migrated-FV-Info-Hob-for-ca.patch
Patch0035: 0033-UefiCpuPkg-CpuMpPei-Add-GDT-migration-support-CVE-20.patch
Patch0036: 0034-UefiCpuPkg-CpuMpPei-Enable-paging-and-set-NP-flag-to.patch
Patch0037: 0035-SecurityPkg-TcgPei-Use-Migrated-FV-Info-Hob-for-calc.patch
Patch0038: 0036-UefiCpuPkg-Move-MigrateGdt-from-DiscoverMemory-to-Te.patch
Patch0039: 0037-MdeModulePkg-PiSmmCore-SmmEntryPoint-underflow-CVE-2.patch
Patch0040: 0038-PATCH-Avoid-dangling-ptrs-in-header-and-data-params-.patch
Patch0041: 0039-PATCH-pk7_doit.c-Check-return-of-BIO_set_md-calls.patch
Patch0042: 0040-Fix-a-UAF-resulting-from-a-bug-in-BIO_new_NDEF.patch
Patch0043: 0041-Check-CMS-failure-during-BIO-setup-with-stream-is-ha.patch
Patch0044: 0042-Correctly-compare-EdiPartyName-in-GENERAL_NAME_cmp.patch
Patch0045: 0043-CVE-2023-0286-Fix-GENERAL_NAME_cmp-for-x400Address-1.patch

BuildRequires: acpica-tools gcc gcc-c++ libuuid-devel python3 bc nasm python2

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
%autopatch -p1

%build
NCPUS=`/usr/bin/getconf _NPROCESSORS_ONLN`
BUILD_OPTION="-t GCC49 -n $NCPUS -b RELEASE"

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
%{_bindir}/Brotli
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
* Sun Feb 26 2023 chenhuiying<chenhuiying4@huawei.com> - 202002-15
- fix CVE-2023-0286

* Sun Feb 26 2023 chenhuiying<chenhuiying4@huawei.com> - 202002-14
- fix CVE-2023-0215

* Sun Feb 26 2023 shaodenghui<shaodenghui@huawei.com> - 202002-13
- fix CVE-2023-0401

* Sun Feb 26 2023 shaodenghui<shaodenghui@huawei.com> - 202002-12
- fix CVE-2022-4450

* Tue Nov 29 2022 chenhuiying<chenhuiying4@huawei.com> - 202002-11
- fix CVE-2021-38578

* Thu Sep 29 2022 chenhuiying<chenhuiying4@huawei.com> - 202002-10
- fix CVE-2019-11098

* Thu Sep 29 2022 chenhuiying<chenhuiying4@huawei.com> - 202002-9
- fix CVE-2019-14584

* Fri Jan 28 2022 Jinhua Cao<caojinhua1@huawei.com> - 202002-8
- fix CVE-2021-38576

* Thu Dec 2 2021 Jinhua Cao<caojinhua1@huawei.com> - 202002-7
- fix CVE-2021-21286

* Wed Sep 22 2021 imxcc <xingchaochao@Huawei.com> - 202002-6
- fix cve-2021-38575

* Mon Aug 30 2021 miaoyubo <miaoyubo@huawei.com> - 202002-5
- MdeModulePkg/LzmaCustomDecompressLib: catch 4GB+ uncompressed

* Mon Jun 28 2021 Jiajie Li <lijiajie11@huawei.com> - 202002-4
- Fix CVE-2021-28210

* Mon May 10 2021 openEuler Buildteam <buildteam@openeuler.org> - 202002-3
- Fix CVE-2019-14562

* Wed Oct 14 2020 zhangxinhao <zhangxinhao1@huawei.com> - 202002-2
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
