//! Mach-O CPU type and subtype constants, and the architecture names
//! `lipo` uses for them.
//!
//! The name table matches `lipo -arch` / `-thin` names, including the
//! aliases Apple accepts.

/// `cpu_type_t`
pub type CpuType = u32;
/// `cpu_subtype_t`
pub type CpuSubType = u32;

/// Mask of the capability bits in a `cpusubtype`
pub const CPU_SUBTYPE_MASK: CpuSubType = 0xff00_0000;
/// Mask of the architecture bits in a `cputype`
pub const CPU_ARCH_MASK: CpuType = 0xff00_0000;
/// 64-bit ABI
pub const CPU_ARCH_ABI64: CpuType = 0x0100_0000;
/// ABI for 64-bit hardware with 32-bit types
pub const CPU_ARCH_ABI64_32: CpuType = 0x0200_0000;

pub const CPU_TYPE_ANY: CpuType = !0;
pub const CPU_TYPE_VAX: CpuType = 1;
pub const CPU_TYPE_MC680X0: CpuType = 6;
pub const CPU_TYPE_X86: CpuType = 7;
pub const CPU_TYPE_I386: CpuType = CPU_TYPE_X86;
pub const CPU_TYPE_X86_64: CpuType = CPU_TYPE_X86 | CPU_ARCH_ABI64;
pub const CPU_TYPE_MIPS: CpuType = 8;
pub const CPU_TYPE_MC98000: CpuType = 10;
pub const CPU_TYPE_HPPA: CpuType = 11;
pub const CPU_TYPE_ARM: CpuType = 12;
pub const CPU_TYPE_ARM64: CpuType = CPU_TYPE_ARM | CPU_ARCH_ABI64;
pub const CPU_TYPE_ARM64_32: CpuType = CPU_TYPE_ARM | CPU_ARCH_ABI64_32;
pub const CPU_TYPE_MC88000: CpuType = 13;
pub const CPU_TYPE_SPARC: CpuType = 14;
pub const CPU_TYPE_I860: CpuType = 15;
pub const CPU_TYPE_ALPHA: CpuType = 16;
pub const CPU_TYPE_POWERPC: CpuType = 18;
pub const CPU_TYPE_POWERPC64: CpuType = CPU_TYPE_POWERPC | CPU_ARCH_ABI64;

pub const CPU_SUBTYPE_MULTIPLE: CpuSubType = !0;
pub const CPU_SUBTYPE_LITTLE_ENDIAN: CpuSubType = 0;
pub const CPU_SUBTYPE_BIG_ENDIAN: CpuSubType = 1;

pub const CPU_SUBTYPE_MC680X0_ALL: CpuSubType = 1;
pub const CPU_SUBTYPE_MC68040: CpuSubType = 2;
pub const CPU_SUBTYPE_MC68030_ONLY: CpuSubType = 3;

/// `CPU_SUBTYPE_INTEL(f, m)`
const fn cpu_subtype_intel(family: u32, model: u32) -> CpuSubType {
    family + (model << 4)
}
pub const CPU_SUBTYPE_I386_ALL: CpuSubType = cpu_subtype_intel(3, 0);
pub const CPU_SUBTYPE_486: CpuSubType = cpu_subtype_intel(4, 0);
pub const CPU_SUBTYPE_486SX: CpuSubType = cpu_subtype_intel(4, 8);
pub const CPU_SUBTYPE_586: CpuSubType = cpu_subtype_intel(5, 0);
pub const CPU_SUBTYPE_PENT: CpuSubType = cpu_subtype_intel(5, 0);
pub const CPU_SUBTYPE_PENTPRO: CpuSubType = cpu_subtype_intel(6, 1);
pub const CPU_SUBTYPE_PENTII_M3: CpuSubType = cpu_subtype_intel(6, 3);
pub const CPU_SUBTYPE_PENTII_M5: CpuSubType = cpu_subtype_intel(6, 5);
pub const CPU_SUBTYPE_PENTIUM_4: CpuSubType = cpu_subtype_intel(10, 0);
pub const CPU_SUBTYPE_X86_64_ALL: CpuSubType = 3;
pub const CPU_SUBTYPE_X86_64_H: CpuSubType = 8;

pub const CPU_SUBTYPE_HPPA_ALL: CpuSubType = 0;
pub const CPU_SUBTYPE_HPPA_7100LC: CpuSubType = 1;
pub const CPU_SUBTYPE_MC88000_ALL: CpuSubType = 0;
pub const CPU_SUBTYPE_SPARC_ALL: CpuSubType = 0;
pub const CPU_SUBTYPE_I860_ALL: CpuSubType = 0;

pub const CPU_SUBTYPE_POWERPC_ALL: CpuSubType = 0;
pub const CPU_SUBTYPE_POWERPC_601: CpuSubType = 1;
pub const CPU_SUBTYPE_POWERPC_603: CpuSubType = 3;
pub const CPU_SUBTYPE_POWERPC_603E: CpuSubType = 4;
pub const CPU_SUBTYPE_POWERPC_603EV: CpuSubType = 5;
pub const CPU_SUBTYPE_POWERPC_604: CpuSubType = 6;
pub const CPU_SUBTYPE_POWERPC_604E: CpuSubType = 7;
pub const CPU_SUBTYPE_POWERPC_750: CpuSubType = 9;
pub const CPU_SUBTYPE_POWERPC_7400: CpuSubType = 10;
pub const CPU_SUBTYPE_POWERPC_7450: CpuSubType = 11;
pub const CPU_SUBTYPE_POWERPC_970: CpuSubType = 100;

pub const CPU_SUBTYPE_ARM_ALL: CpuSubType = 0;
pub const CPU_SUBTYPE_ARM_V4T: CpuSubType = 5;
pub const CPU_SUBTYPE_ARM_V6: CpuSubType = 6;
pub const CPU_SUBTYPE_ARM_V5TEJ: CpuSubType = 7;
pub const CPU_SUBTYPE_ARM_XSCALE: CpuSubType = 8;
pub const CPU_SUBTYPE_ARM_V7: CpuSubType = 9;
pub const CPU_SUBTYPE_ARM_V7F: CpuSubType = 10;
pub const CPU_SUBTYPE_ARM_V7S: CpuSubType = 11;
pub const CPU_SUBTYPE_ARM_V7K: CpuSubType = 12;
pub const CPU_SUBTYPE_ARM_V8: CpuSubType = 13;
pub const CPU_SUBTYPE_ARM_V6M: CpuSubType = 14;
pub const CPU_SUBTYPE_ARM_V7M: CpuSubType = 15;
pub const CPU_SUBTYPE_ARM_V7EM: CpuSubType = 16;

pub const CPU_SUBTYPE_ARM64_ALL: CpuSubType = 0;
pub const CPU_SUBTYPE_ARM64_V8: CpuSubType = 1;
pub const CPU_SUBTYPE_ARM64_E: CpuSubType = 2;
pub const CPU_SUBTYPE_ARM64_32_ALL: CpuSubType = 0;
pub const CPU_SUBTYPE_ARM64_32_V8: CpuSubType = 1;

/// Architecture names as `lipo` knows them, in lookup order
static ARCH_NAMES: &[(&str, CpuType, CpuSubType)] = &[
    // generic types
    ("any", CPU_TYPE_ANY, CPU_SUBTYPE_MULTIPLE),
    ("little", CPU_TYPE_ANY, CPU_SUBTYPE_LITTLE_ENDIAN),
    ("big", CPU_TYPE_ANY, CPU_SUBTYPE_BIG_ENDIAN),
    // macho names
    ("ppc64", CPU_TYPE_POWERPC64, CPU_SUBTYPE_POWERPC_ALL),
    ("x86_64", CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL),
    ("x86_64h", CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_H),
    ("arm64", CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL),
    ("arm64_32", CPU_TYPE_ARM64_32, CPU_SUBTYPE_ARM64_32_ALL),
    ("ppc970-64", CPU_TYPE_POWERPC64, CPU_SUBTYPE_POWERPC_970),
    ("ppc", CPU_TYPE_POWERPC, CPU_SUBTYPE_POWERPC_ALL),
    ("i386", CPU_TYPE_I386, CPU_SUBTYPE_I386_ALL),
    ("m68k", CPU_TYPE_MC680X0, CPU_SUBTYPE_MC680X0_ALL),
    ("hppa", CPU_TYPE_HPPA, CPU_SUBTYPE_HPPA_ALL),
    ("sparc", CPU_TYPE_SPARC, CPU_SUBTYPE_SPARC_ALL),
    ("m88k", CPU_TYPE_MC88000, CPU_SUBTYPE_MC88000_ALL),
    ("i860", CPU_TYPE_I860, CPU_SUBTYPE_I860_ALL),
    ("arm", CPU_TYPE_ARM, CPU_SUBTYPE_ARM_ALL),
    ("ppc601", CPU_TYPE_POWERPC, CPU_SUBTYPE_POWERPC_601),
    ("ppc603", CPU_TYPE_POWERPC, CPU_SUBTYPE_POWERPC_603),
    ("ppc603e", CPU_TYPE_POWERPC, CPU_SUBTYPE_POWERPC_603E),
    ("ppc603ev", CPU_TYPE_POWERPC, CPU_SUBTYPE_POWERPC_603EV),
    ("ppc604", CPU_TYPE_POWERPC, CPU_SUBTYPE_POWERPC_604),
    ("ppc604e", CPU_TYPE_POWERPC, CPU_SUBTYPE_POWERPC_604E),
    ("ppc750", CPU_TYPE_POWERPC, CPU_SUBTYPE_POWERPC_750),
    ("ppc7400", CPU_TYPE_POWERPC, CPU_SUBTYPE_POWERPC_7400),
    ("ppc7450", CPU_TYPE_POWERPC, CPU_SUBTYPE_POWERPC_7450),
    ("ppc970", CPU_TYPE_POWERPC, CPU_SUBTYPE_POWERPC_970),
    ("i486", CPU_TYPE_I386, CPU_SUBTYPE_486),
    ("i486SX", CPU_TYPE_I386, CPU_SUBTYPE_486SX),
    ("i586", CPU_TYPE_I386, CPU_SUBTYPE_586),
    ("i686", CPU_TYPE_I386, CPU_SUBTYPE_PENTPRO),
    ("pentIIm3", CPU_TYPE_I386, CPU_SUBTYPE_PENTII_M3),
    ("pentIIm5", CPU_TYPE_I386, CPU_SUBTYPE_PENTII_M5),
    ("pentium4", CPU_TYPE_I386, CPU_SUBTYPE_PENTIUM_4),
    ("m68030", CPU_TYPE_MC680X0, CPU_SUBTYPE_MC68030_ONLY),
    ("m68040", CPU_TYPE_MC680X0, CPU_SUBTYPE_MC68040),
    ("hppa7100LC", CPU_TYPE_HPPA, CPU_SUBTYPE_HPPA_7100LC),
    ("armv4t", CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V4T),
    ("armv5", CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V5TEJ),
    ("xscale", CPU_TYPE_ARM, CPU_SUBTYPE_ARM_XSCALE),
    ("armv6", CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V6),
    ("armv6m", CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V6M),
    ("armv7", CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7),
    ("armv7f", CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7F),
    ("armv7s", CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7S),
    ("armv7k", CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7K),
    ("armv7m", CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7M),
    ("armv7em", CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7EM),
    ("arm64v8", CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_V8),
    ("arm64e", CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_E),
    ("arm64_32_v8", CPU_TYPE_ARM64_32, CPU_SUBTYPE_ARM64_32_V8),
];

/// Strip the capability bits (the high byte) from a `cpusubtype`.
///
/// Mach-O headers may carry feature flags in the high byte of `cpusubtype`,
/// e.g. `CPU_SUBTYPE_PTRAUTH_ABI` (`0x80000000`) on arm64e binaries, which
/// gives `cpusubtype == 0x80000002` instead of the bare `CPU_SUBTYPE_ARM64_E`.
/// Like `lipo`, we ignore those bits when identifying an architecture.
#[inline]
pub const fn strip_cpu_subtype_caps(cpu_subtype: CpuSubType) -> CpuSubType {
    cpu_subtype & !CPU_SUBTYPE_MASK
}

/// Look up the `cputype` and `cpusubtype` for an architecture name such as
/// `x86_64` or `arm64e`.
pub fn arch_from_name(name: &str) -> Option<(CpuType, CpuSubType)> {
    if let Some(&(_, cpu_type, cpu_subtype)) = ARCH_NAMES.iter().find(|(n, _, _)| *n == name) {
        return Some((cpu_type, cpu_subtype));
    }
    // aliases
    match name {
        // these are used by apple
        "pentium" => Some((CPU_TYPE_I386, CPU_SUBTYPE_PENT)),
        "pentpro" => Some((CPU_TYPE_I386, CPU_SUBTYPE_PENTPRO)),
        // these are used commonly for consistency
        "x86" => Some((CPU_TYPE_I386, CPU_SUBTYPE_I386_ALL)),
        _ => None,
    }
}

/// Look up the architecture name for a `cputype` / `cpusubtype` pair.
///
/// Capability bits in `cpu_subtype` are ignored.
pub fn arch_name(cpu_type: CpuType, cpu_subtype: CpuSubType) -> Option<&'static str> {
    let cpu_subtype = strip_cpu_subtype_caps(cpu_subtype);
    ARCH_NAMES
        .iter()
        .find(|&&(_, t, s)| t == cpu_type && s == cpu_subtype)
        .map(|&(name, _, _)| name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        for &(name, cpu_type, cpu_subtype) in ARCH_NAMES {
            assert_eq!(arch_from_name(name), Some((cpu_type, cpu_subtype)));
        }
        assert_eq!(
            arch_name(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL),
            Some("arm64")
        );
        assert_eq!(arch_name(CPU_TYPE_ARM64, 0x8000_0002), Some("arm64e"));
        assert_eq!(
            arch_name(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL),
            Some("x86_64")
        );
        assert_eq!(arch_name(CPU_TYPE_X86_64, 0x8000_0003), Some("x86_64"));
        assert_eq!(arch_name(CPU_TYPE_I386, CPU_SUBTYPE_PENT), Some("i586"));
        assert_eq!(arch_name(0x1234, 0), None);
        assert_eq!(
            arch_from_name("x86"),
            Some((CPU_TYPE_I386, CPU_SUBTYPE_I386_ALL))
        );
        assert_eq!(
            arch_from_name("pentium"),
            Some((CPU_TYPE_I386, CPU_SUBTYPE_PENT))
        );
        assert_eq!(arch_from_name("riscv"), None);
    }
}
