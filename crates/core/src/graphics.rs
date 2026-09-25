//! Judging whether the host's Vulkan stack is good enough for DXVK/VKD3D, from `vulkaninfo --summary` text.
//!
//! Pure: the runner that executes the tool lives elsewhere. The output is untrusted text, so the number of
//! devices, the line length and every kept string are bounded and stripped of control characters.
use crate::text::clean;

const MAX_DEVICES: usize = 16;
const MAX_LINE: usize = 512;
const MAX_FIELD: usize = 128;

/// One physical device from the `Devices:` section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VulkanDevice {
    pub name: String,
    pub device_type: String,
    /// `(major, minor)` of `apiVersion`; the patch level is ignored.
    pub api: (u32, u32),
    pub driver: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VulkanVerdict {
    Usable,
    Unusable(String),
    /// The tool ran but printed nothing we understand.
    Unknown,
}

fn parse_api(v: &str) -> Option<(u32, u32)> {
    let mut it = v.split('.');
    let major = it.next()?.trim().parse().ok()?;
    let minor = it.next()?.trim().parse().ok()?;
    Some((major, minor))
}

fn is_gpu_header(line: &str) -> bool {
    line.strip_prefix("GPU")
        .and_then(|r| r.strip_suffix(':'))
        .is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
}

/// Parses the device blocks of `vulkaninfo --summary`. At most 16 devices; a device without a parsable
/// `apiVersion` is dropped.
pub fn parse_vulkaninfo_summary(text: &str) -> Vec<VulkanDevice> {
    #[derive(Default)]
    struct Cur {
        name: String,
        device_type: String,
        api: Option<(u32, u32)>,
        driver: String,
    }
    fn flush(cur: Option<Cur>, out: &mut Vec<VulkanDevice>) {
        if let Some(Cur {
            name,
            device_type,
            api: Some(api),
            driver,
        }) = cur
        {
            out.push(VulkanDevice {
                name,
                device_type,
                api,
                driver,
            });
        }
    }
    let mut out = Vec::new();
    let mut cur: Option<Cur> = None;
    let mut seen = 0;
    for line in text.lines() {
        if line.len() > MAX_LINE {
            continue;
        }
        let line = line.trim_end();
        if is_gpu_header(line) {
            flush(cur.take(), &mut out);
            seen += 1;
            if seen > MAX_DEVICES {
                break;
            }
            cur = Some(Cur::default());
            continue;
        }
        let (Some(c), Some((k, v))) = (cur.as_mut(), line.split_once('=')) else {
            continue;
        };
        let v = v.trim();
        match k.trim() {
            "apiVersion" => c.api = parse_api(v),
            "deviceType" => c.device_type = clean(v, MAX_FIELD),
            "deviceName" => c.name = clean(v, MAX_FIELD),
            "driverName" => c.driver = clean(v, MAX_FIELD),
            _ => {}
        }
    }
    flush(cur, &mut out);
    out
}

/// `Usable` if any device supports at least `min` (or `min` is `None`); `Unknown` for an empty list.
pub fn judge(devices: &[VulkanDevice], min: Option<(u32, u32)>) -> VulkanVerdict {
    let Some(best) = devices.iter().map(|d| d.api).max() else {
        return VulkanVerdict::Unknown;
    };
    match min {
        Some(m) if best < m => VulkanVerdict::Unusable(format!(
            "no Vulkan device supports API {}.{} (best is {}.{})",
            m.0, m.1, best.0, best.1
        )),
        _ => VulkanVerdict::Usable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REAL: &str = r#"Devices:
========
GPU0:
	apiVersion         = 1.4.335
	driverVersion      = 26.0.8
	vendorID           = 0x1002
	deviceID           = 0x1681
	deviceType         = PHYSICAL_DEVICE_TYPE_INTEGRATED_GPU
	deviceName         = AMD Radeon 660M (RADV REMBRANDT)
	driverID           = DRIVER_ID_MESA_RADV
	driverName         = radv
	driverInfo         = Mesa 26.0.8-1ubuntu0.3
	conformanceVersion = 1.4.0.0
	deviceUUID         = 00000000-7400-0000-0000-000000000000
	driverUUID         = 414d442d-4d45-5341-2d44-525600000000
GPU1:
	apiVersion         = 1.4.329
	driverVersion      = 595.91.7.0
	vendorID           = 0x10de
	deviceID           = 0x25ac
	deviceType         = PHYSICAL_DEVICE_TYPE_DISCRETE_GPU
	deviceName         = NVIDIA GeForce RTX 3050 6GB Laptop GPU
	driverID           = DRIVER_ID_NVIDIA_PROPRIETARY
	driverName         = NVIDIA
	driverInfo         = 595.91.07
	conformanceVersion = 1.4.3.3
	deviceUUID         = e016bf46-7f5e-982f-d69b-62be74524c57
	driverUUID         = 84d66e5a-5337-5512-92cd-fc48fce44ebd
GPU2:
	apiVersion         = 1.4.335
	driverVersion      = 26.0.8
	vendorID           = 0x10005
	deviceID           = 0x0000
	deviceType         = PHYSICAL_DEVICE_TYPE_CPU
	deviceName         = llvmpipe (LLVM 21.1.8, 256 bits)
	driverID           = DRIVER_ID_MESA_LLVMPIPE
	driverName         = llvmpipe
	driverInfo         = Mesa 26.0.8-1ubuntu0.3 (LLVM 21.1.8)
	conformanceVersion = 1.3.1.1
	deviceUUID         = 6d657361-3236-2e30-2e38-2d3175627500
	driverUUID         = 6c6c766d-7069-7065-5555-494400000000
"#;
    const LLVMPIPE: &str = "GPU0:\n\tapiVersion         = 1.3.274\n\tdriverVersion      = 0.0.1\n\tdeviceType         = PHYSICAL_DEVICE_TYPE_CPU\n\tdeviceName         = llvmpipe (LLVM 15.0.7, 256 bits)\n\tdriverName         = llvmpipe\n";
    const OLD: &str = "GPU0:\n\tapiVersion         = 1.1.0\n\tdriverVersion      = 1.0.0\n\tdeviceType         = PHYSICAL_DEVICE_TYPE_DISCRETE_GPU\n\tdeviceName         = Old GPU\n\tdriverName         = old\n";

    #[test]
    fn parses_a_real_summary() {
        let d = parse_vulkaninfo_summary(REAL);
        assert!(!d.is_empty());
        assert!(d.iter().all(|d| d.api.0 >= 1 && !d.name.is_empty()));
    }
    #[test]
    fn llvmpipe_is_usable_and_typed_cpu() {
        let d = parse_vulkaninfo_summary(LLVMPIPE);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].api, (1, 3));
        assert!(d[0].device_type.ends_with("CPU"));
        assert_eq!(judge(&d, Some((1, 3))), VulkanVerdict::Usable);
    }
    #[test]
    fn too_old_is_unusable_and_the_reason_names_both_versions() {
        let d = parse_vulkaninfo_summary(OLD);
        match judge(&d, Some((1, 3))) {
            VulkanVerdict::Unusable(r) => assert!(r.contains("1.3") && r.contains("1.1"), "{r}"),
            v => panic!("{v:?}"),
        }
    }
    #[test]
    fn one_good_device_among_bad_is_usable() {
        let mut d = parse_vulkaninfo_summary(OLD);
        d.extend(parse_vulkaninfo_summary(LLVMPIPE));
        assert_eq!(judge(&d, Some((1, 3))), VulkanVerdict::Usable);
    }
    #[test]
    fn garbage_and_empty_are_unknown_not_unusable() {
        for t in ["", "not vulkaninfo", "GPU0:\n\tapiVersion = banana\n", "\0\u{1b}[31m"] {
            assert_eq!(
                judge(&parse_vulkaninfo_summary(t), Some((1, 3))),
                VulkanVerdict::Unknown,
                "{t:?}"
            );
        }
    }
    #[test]
    fn no_minimum_means_any_device_is_usable() {
        assert_eq!(judge(&parse_vulkaninfo_summary(OLD), None), VulkanVerdict::Usable);
    }
    #[test]
    fn bounded_devices_and_fields() {
        let big = (0..100)
            .map(|i| format!("GPU{i}:\n\tapiVersion = 1.3.0\n\tdeviceName = {}\n", "x".repeat(10_000)))
            .collect::<String>();
        let d = parse_vulkaninfo_summary(&big);
        assert_eq!(d.len(), 16);
        assert!(d.iter().all(|d| d.name.len() <= 128));
        let long_but_under_line_cap = format!("GPU0:\n\tapiVersion = 1.3.0\n\tdeviceName = {}\n", "y".repeat(400));
        assert_eq!(parse_vulkaninfo_summary(&long_but_under_line_cap)[0].name.len(), 128);
    }
    #[test]
    fn never_panics_on_mutations() {
        let b = REAL.as_bytes();
        for i in (0..b.len()).step_by(7) {
            let mut m = b.to_vec();
            m[i] ^= 0xff;
            let _ = parse_vulkaninfo_summary(&String::from_utf8_lossy(&m));
            let _ = parse_vulkaninfo_summary(&String::from_utf8_lossy(&b[..i]));
        }
    }
}
