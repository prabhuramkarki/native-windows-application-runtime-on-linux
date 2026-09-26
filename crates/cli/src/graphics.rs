//! `runtime graphics info`: what the host's Vulkan stack offers, from `vulkaninfo --summary`. The probe (bounded,
//! once per invocation) is `rt_api::host::graphics`; this module formats it.
use crate::CmdError;
use crate::safe::safe;
use rt_core::{HostVulkan, VulkanVerdict, host_verdict};

pub fn info() -> Result<u8, CmdError> {
    let needs: Vec<(&str, (u32, u32))> = rt_deps::Manifest::bundled()
        .packages
        .iter()
        .filter_map(|p| Some((p.id.as_str(), p.min_vulkan?)))
        .collect();
    crate::emit(&format_info(rt_api::host::graphics::host(), &needs))?;
    Ok(0)
}

/// The report for `h`; `needs` is each bundled package's minimum Vulkan version. The host counts as usable when
/// it meets the smallest of them (a package with a higher minimum is listed as not met).
fn format_info(h: &HostVulkan, needs: &[(&str, (u32, u32))]) -> String {
    let mut out = String::new();
    match host_verdict(h, needs.iter().map(|n| n.1).min()) {
        VulkanVerdict::Usable => {
            out.push_str("Vulkan: usable\n");
            for (i, d) in h.devices.iter().enumerate() {
                let kind = d
                    .device_type
                    .strip_prefix("PHYSICAL_DEVICE_TYPE_")
                    .unwrap_or(&d.device_type);
                let soft = if kind == "CPU" {
                    "software rendering (CPU)".to_string()
                } else {
                    safe(&kind.to_lowercase())
                };
                let driver = if d.driver.is_empty() {
                    String::new()
                } else {
                    format!("   driver {}", safe(&d.driver))
                };
                out.push_str(&format!(
                    "  GPU{i}  {}   Vulkan {}.{}   {soft}{driver}\n",
                    safe(&d.name),
                    d.api.0,
                    d.api.1
                ));
            }
        }
        VulkanVerdict::Unusable(why) => out.push_str(&format!("Vulkan: unusable  ({})\n", safe(&why))),
        VulkanVerdict::Unknown if !h.tool_found => out.push_str(
            "Vulkan: unknown  (could not read the Vulkan device list: vulkaninfo is missing, failed or timed out; the Vulkan loader is present)\n",
        ),
        VulkanVerdict::Unknown => {
            out.push_str("Vulkan: unknown  (could not read the Vulkan device list: vulkaninfo listed no devices)\n");
        }
    }
    if !needs.is_empty() {
        out.push_str("Vulkan needed by bundled packages:\n");
        for (id, (major, minor)) in needs {
            let state = match host_verdict(h, Some((*major, *minor))) {
                VulkanVerdict::Usable => "met",
                VulkanVerdict::Unusable(_) => "not met",
                VulkanVerdict::Unknown => "unknown",
            };
            out.push_str(&format!("  {} {major}.{minor}+: {state}\n", safe(id)));
        }
        out.push_str("DXVK 3.x upstream recommends Vulkan 1.4; older AMD GCN cards work without it.\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn info_lists_each_packages_minimum_and_whether_it_is_met() {
        let dev = |api| rt_core::VulkanDevice {
            name: "gpu".into(),
            device_type: "PHYSICAL_DEVICE_TYPE_DISCRETE_GPU".into(),
            api,
            driver: "drv".into(),
        };
        let h = HostVulkan {
            tool_found: true,
            loader_found: true,
            devices: vec![dev((1, 2))],
        };
        let out = format_info(&h, &[("dxvk", (1, 3)), ("old", (1, 1))]);
        // Usable by the smallest minimum, with the driver shown; the higher one is reported as not met.
        assert!(out.starts_with("Vulkan: usable\n"), "{out}");
        assert!(
            out.contains("driver drv") && out.contains("  dxvk 1.3+: not met\n"),
            "{out}"
        );
        assert!(
            out.contains("  old 1.1+: met\n") && out.contains("recommends Vulkan 1.4"),
            "{out}"
        );
        assert!(!format_info(&h, &[]).contains("needed by"));
    }

    #[test]
    fn unknown_says_why_the_list_could_not_be_read() {
        let mut h = HostVulkan {
            tool_found: false,
            loader_found: true,
            devices: vec![],
        };
        assert!(format_info(&h, &[]).contains("missing, failed or timed out"));
        h.tool_found = true;
        assert!(format_info(&h, &[]).contains("listed no devices"));
    }
}
