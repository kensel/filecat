use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

#[derive(Deserialize, Debug)]
struct VGuestConf {
    name: String,
    #[serde(default)]
    desc: String,
    #[serde(default)]
    vcpu_num: u32,
    #[serde(default)]
    vram_size: u64,
    #[serde(default)]
    is_general_vm: bool,
    #[serde(default)]
    version: String,
}

#[derive(Deserialize, Debug, Clone)]
struct VDiskEntry {
    #[serde(default)]
    is_dummy: bool,
    #[serde(default)]
    is_meta_disk: bool,
    #[serde(default)]
    vdisk_mode: u32,
}

#[derive(Serialize, Debug, Clone)]
pub struct VmmGuestDiskMeta {
    pub vm_uuid: String,
    pub vm_name: String,
    pub vm_desc: String,
    pub is_general_vm: bool,
    pub is_meta_disk: bool,
    pub is_dummy: bool,
    pub vcpu_num: u32,
    pub vram_mb: u64,
    pub dsm_version: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct SynologyBlockDevice {
    pub uuid: String,
    pub lid: u32,
    pub name: String,
    pub kind: &'static str,       // "san_blun" | "san_blun_thick" | "vmm_vdisk" | "vmm_image"
    pub root_volume: String,      // "/volume1"
    pub backing_dir: String,      // "/volume1/@iSCSI/LUN/VDISK_BLUN/<uuid>"
    pub provisioned_bytes: u64,   // From iscsi_lun.conf `bytes=`
    pub allocated_bytes: u64,     // Sum of st_blocks * 512 across *_0000* + ROD (never st_size of 512GiB ROD!)
    pub extent_files: usize,
    pub vm_uuid: Option<String>,
    pub vm_name: Option<String>,
    pub vdisk_uuid: Option<String>,
    pub is_meta_disk: Option<bool>,
}

#[derive(Serialize, Debug)]
pub struct VolumeTopology {
    pub mount_point: String,
    pub device: String,
    pub fs_type: String,
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub free_bytes: u64,
    pub shares: Vec<String>,
    pub block_devices: Vec<SynologyBlockDevice>,
}

/// Discovers /volume* mounts, shares, and Synology SAN/VMM block backing stores
pub fn discover_all_volumes() -> Vec<VolumeTopology> {
    let mut volumes = Vec::new();
    let mounts = fs::read_to_string("/proc/mounts").unwrap_or_default();

    for line in mounts.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 || !parts[1].starts_with("/volume") {
            continue;
        }
        let device = parts[0].to_string();
        let mount = parts[1].to_string();
        let fs_type = parts[2].to_string();

        let mut total_bytes = 0;
        let mut free_bytes = 0;
        if let Ok(c_path) = std::ffi::CString::new(mount.as_str()) {
            unsafe {
                let mut stat: libc::statvfs = std::mem::zeroed();
                if libc::statvfs(c_path.as_ptr(), &mut stat) == 0 {
                    total_bytes = (stat.f_blocks as u64) * (stat.f_frsize as u64);
                    free_bytes = (stat.f_bavail as u64) * (stat.f_frsize as u64);
                }
            }
        }

        let mut shares = Vec::new();
        if let Ok(entries) = fs::read_dir(&mount) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                let p = entry.path();
                if !name.starts_with('@') && !name.starts_with('#') && p.is_dir() {
                    shares.push(p.to_string_lossy().into_owned());
                }
            }
        }

        let block_devices = discover_synology_luns_and_vdisks(&mount);

        volumes.push(VolumeTopology {
            mount_point: mount,
            device,
            fs_type,
            total_bytes,
            used_bytes: total_bytes.saturating_sub(free_bytes),
            free_bytes,
            shares,
            block_devices,
        });
    }
    volumes
}

/// Parses /volume*/@iSCSI/LUN/iscsi_lun.conf and measures real Btrfs physical allocation
pub fn discover_synology_luns_and_vdisks(volume_mount: &str) -> Vec<SynologyBlockDevice> {
    let conf_path = format!("{}/@iSCSI/LUN/iscsi_lun.conf", volume_mount);
    let content = match fs::read_to_string(&conf_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let vdisk_to_vm = load_vmm_guest_mapping(volume_mount);
    let mut devices = Vec::new();
    let mut current: HashMap<String, String> = HashMap::new();

    for line in content.lines().chain(std::iter::once("[END]")) {
        let line = line.trim();
        if line.starts_with('[') && line.ends_with(']') {
            if let Some(uuid) = current.get("uuid") {
                if let Some(dev) = build_block_device(volume_mount, uuid, &current, &vdisk_to_vm) {
                    devices.push(dev);
                }
            }
            current.clear();
        } else if let Some((k, v)) = line.split_once('=') {
            current.insert(k.trim().to_string(), v.trim().to_string());
        }
    }

    devices
}

fn build_block_device(
    volume_mount: &str,
    uuid: &str,
    props: &HashMap<String, String>,
    vdisk_to_vm: &HashMap<String, VmmGuestDiskMeta>,
) -> Option<SynologyBlockDevice> {
    let name = props.get("name")?.clone();
    let lid = props.get("lid").and_then(|v| v.parse().ok()).unwrap_or(0);
    let provisioned_bytes = props.get("bytes").and_then(|v| v.parse().ok()).unwrap_or(0);
    let devtype = props.get("devtype").map(|s| s.as_str()).unwrap_or("");

    let (subdir, kind) = if devtype == "7" {
        if name.starts_with("vdisk.") {
            ("VDISK_BLUN", "vmm_vdisk")
        } else if name.starts_with("image.") {
            ("VDISK_BLUN", "vmm_image")
        } else {
            ("VDISK_BLUN", "vmm_other")
        }
    } else if devtype == "11"
        || Path::new(&format!("{}/@iSCSI/LUN/BLUN_THICK/{}", volume_mount, uuid)).exists()
    {
        ("BLUN_THICK", "san_blun_thick")
    } else {
        ("BLUN", "san_blun")
    };

    let backing_dir = format!("{}/@iSCSI/LUN/{}/{}", volume_mount, subdir, uuid);

    // Sum physical allocated blocks (st_blocks * 512) across extent files (*_0000* and ROD).
    // NEVER use st_size of ROD (which is a 512 GiB sparse metadata map!).
    let mut allocated_bytes: u64 = 0;
    let mut extent_files: usize = 0;

    if let Ok(entries) = fs::read_dir(&backing_dir) {
        for entry in entries.flatten() {
            if let Ok(meta) = fs::symlink_metadata(entry.path()) {
                if meta.is_file() {
                    allocated_bytes += meta.blocks() * 512;
                    let fname = entry.file_name().to_string_lossy().into_owned();
                    if fname != "ROD" {
                        extent_files += 1;
                    }
                }
            }
        }
    }

    let mut vdisk_uuid = None;
    let mut vm_uuid = None;
    let mut vm_name = None;
    let mut is_meta_disk = None;

    if kind == "vmm_vdisk" {
        let parts: Vec<&str> = name.split('.').collect();
        if parts.len() >= 3 {
            let parsed_vm_uuid = parts[1].to_string();
            let parsed_vdisk_uuid = parts[2].to_string();
            if let Some(meta) = vdisk_to_vm.get(&parsed_vdisk_uuid) {
                vm_uuid = Some(meta.vm_uuid.clone());
                vm_name = Some(meta.vm_name.clone());
                is_meta_disk = Some(meta.is_meta_disk);
            } else {
                vm_uuid = Some(parsed_vm_uuid);
                vm_name = Some("[ORPHANED_VDISK]".to_string());
            }
            vdisk_uuid = Some(parsed_vdisk_uuid);
        }
    } else if kind == "vmm_image" {
        let parts: Vec<&str> = name.split('.').collect();
        if parts.len() >= 2 {
            let short_id = if parts[1].len() >= 8 { &parts[1][..8] } else { parts[1] };
            vm_name = Some(format!("[VMM_IMAGE: {}]", short_id));
            vdisk_uuid = parts.get(2).map(|s| s.to_string());
        }
    }

    Some(SynologyBlockDevice {
        uuid: uuid.to_string(),
        lid,
        name,
        kind,
        root_volume: volume_mount.to_string(),
        backing_dir,
        provisioned_bytes,
        allocated_bytes,
        extent_files,
        vm_uuid,
        vm_name,
        vdisk_uuid,
        is_meta_disk,
    })
}

/// Maps vdisk_uuid -> VmmGuestDiskMeta by reading /volume*/@Repository/<vm_uuid>/{vguest.conf, vdisk.conf}
pub fn load_vmm_guest_mapping(volume_mount: &str) -> HashMap<String, VmmGuestDiskMeta> {
    let mut map = HashMap::new();
    let repo_dir = format!("{}/@Repository", volume_mount);

    if let Ok(entries) = fs::read_dir(&repo_dir) {
        for entry in entries.flatten() {
            let guest_dir = entry.path();
            if !guest_dir.is_dir() {
                continue;
            }
            let vm_uuid = entry.file_name().to_string_lossy().into_owned();
            let guest_conf_path = guest_dir.join("vguest.conf");
            let disk_conf_path = guest_dir.join("vdisk.conf");

            let guest_json = match fs::read_to_string(&guest_conf_path) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let disk_json = match fs::read_to_string(&disk_conf_path) {
                Ok(s) => s,
                Err(_) => continue,
            };

            let guest: VGuestConf = match serde_json::from_str(&guest_json) {
                Ok(g) => g,
                Err(_) => continue,
            };
            let disks: HashMap<String, VDiskEntry> = match serde_json::from_str(&disk_json) {
                Ok(d) => d,
                Err(_) => continue,
            };

            for (vdisk_uuid, d_meta) in disks {
                map.insert(
                    vdisk_uuid,
                    VmmGuestDiskMeta {
                        vm_uuid: vm_uuid.clone(),
                        vm_name: guest.name.clone(),
                        vm_desc: guest.desc.clone(),
                        is_general_vm: guest.is_general_vm,
                        is_meta_disk: d_meta.is_meta_disk,
                        is_dummy: d_meta.is_dummy,
                        vcpu_num: guest.vcpu_num,
                        vram_mb: guest.vram_size,
                        dsm_version: guest.version.clone(),
                    },
                );
            }
        }
    }

    map
}
