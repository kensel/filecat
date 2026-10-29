//! The compiled-in command allowlist (docs/agent-allowlist.md): the only processes the agent
//! starts. A request names an entry by id; the agent builds the command from the entry (absolute
//! binary, fixed argument vector) and, for an entry with an argument kind, validates the one `arg`
//! itself against live host state. No shell, no globbing, no text from the network in a command.
//!
//! This table is the reviewable surface: Windows' `wmi` entries (section 13 of the allowlist
//! document) are phase 2 and not in it.

use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ArgKind {
    BtrfsMount,
    BlockDevice,
    MdDevice,
    #[allow(dead_code)] // the kind exists; its first entry is a later one
    ZfsPool,
}

impl ArgKind {
    pub fn name(self) -> &'static str {
        match self {
            ArgKind::BtrfsMount => "btrfs_mount",
            ArgKind::BlockDevice => "block_device",
            ArgKind::MdDevice => "md_device",
            ArgKind::ZfsPool => "zfs_pool",
        }
    }
}

pub struct Entry {
    pub id: &'static str,
    pub candidates: &'static [&'static str],
    /// the whole argument vector; the validated `arg`, if the entry has a kind, comes after it
    pub args: &'static [&'static str],
    pub kind: Option<ArgKind>,
    pub timeout_s: u64,
    /// a fixed vector that prints the version, for `capabilities` (3 s timeout)
    pub version: Option<&'static [&'static str]>,
}

/// Bump when an entry is added or changed.
pub const ALLOWLIST_VERSION: u32 = 1;

macro_rules! std_bins {
    ($n:literal) => {
        &[concat!("/bin/", $n), concat!("/sbin/", $n), concat!("/usr/bin/", $n), concat!("/usr/sbin/", $n), concat!("/usr/local/bin/", $n), concat!("/usr/local/sbin/", $n)]
    };
}
macro_rules! syno_bins {
    ($n:literal) => {
        &[
            concat!("/bin/", $n), concat!("/sbin/", $n), concat!("/usr/bin/", $n), concat!("/usr/sbin/", $n), concat!("/usr/local/bin/", $n),
            concat!("/usr/local/sbin/", $n), concat!("/usr/syno/bin/", $n), concat!("/usr/syno/sbin/", $n),
        ]
    };
}
macro_rules! pve_bins {
    ($n:literal) => {
        &[concat!("/usr/bin/", $n), concat!("/usr/sbin/", $n)]
    };
}

const V: Option<&'static [&'static str]> = Some(&["--version"]);
const ZFS_COLS: &str = "name,type,used,avail,refer,volsize,refreservation,mountpoint,guid";

const fn e(id: &'static str, candidates: &'static [&'static str], args: &'static [&'static str]) -> Entry {
    Entry { id, candidates, args, kind: None, timeout_s: 20, version: None }
}

pub static ENTRIES: &[Entry] = &[
    // block devices
    Entry { version: V, ..e("lsblk_json", std_bins!("lsblk"), &["-J", "-b", "-o", "NAME,KNAME,PKNAME,MAJ:MIN,TYPE,FSTYPE,SIZE,ROTA,STATE,MODEL,SERIAL,WWN,MOUNTPOINTS"]) },
    Entry { version: V, ..e("lsblk_json_legacy", std_bins!("lsblk"), &["-J", "-b", "-o", "NAME,KNAME,PKNAME,MAJ:MIN,TYPE,FSTYPE,SIZE,ROTA,STATE,MODEL,SERIAL,WWN,MOUNTPOINT"]) },
    Entry { version: V, ..e("lsblk_pairs", std_bins!("lsblk"), &["-P", "-b", "-o", "NAME,KNAME,PKNAME,MAJ:MIN,TYPE,FSTYPE,SIZE,ROTA,MODEL,SERIAL,WWN,MOUNTPOINT"]) },
    Entry { version: V, ..e("blkid_export", std_bins!("blkid"), &["-c", "/dev/null", "-o", "export"]) },
    // mounts
    Entry { version: V, ..e("findmnt_json", std_bins!("findmnt"), &["--json", "-b", "-o", "TARGET,SOURCE,FSTYPE,OPTIONS,MAJ:MIN,FSROOT,UUID,LABEL"]) },
    // btrfs
    Entry { version: V, ..e("btrfs_show", std_bins!("btrfs"), &["filesystem", "show", "--raw"]) },
    Entry { version: V, kind: Some(ArgKind::BtrfsMount), ..e("btrfs_usage", std_bins!("btrfs"), &["filesystem", "usage", "-b"]) },
    // zfs
    e("zpool_list", std_bins!("zpool"), &["list", "-H", "-p", "-v"]),
    e("zpool_status", std_bins!("zpool"), &["status", "-P", "-p"]),
    e("zfs_list", std_bins!("zfs"), &["list", "-H", "-p", "-t", "filesystem,volume", "-o", ZFS_COLS]),
    e("zpool_get", std_bins!("zpool"), &["get", "-H", "-p", "all"]),
    e("zpool_list_json", std_bins!("zpool"), &["list", "-j", "--json-int", "-v"]),
    e("zpool_status_json", std_bins!("zpool"), &["status", "-j", "--json-int", "-P"]),
    e("zfs_list_json", std_bins!("zfs"), &["list", "-j", "--json-int", "-t", "filesystem,volume", "-o", ZFS_COLS]),
    e("zpool_get_json", std_bins!("zpool"), &["get", "-j", "--json-int", "all"]),
    // md
    Entry { version: V, ..e("mdadm_detail_scan", std_bins!("mdadm"), &["--detail", "--scan"]) },
    Entry { version: V, kind: Some(ArgKind::MdDevice), ..e("mdadm_detail", std_bins!("mdadm"), &["--detail"]) },
    // lvm
    Entry { version: V, ..e("lvm_pvs", std_bins!("pvs"), &["--reportformat", "json", "--units", "b", "--nosuffix", "-o", "pv_name,pv_uuid,vg_name,pv_size,pv_free,pv_attr"]) },
    Entry { version: V, ..e("lvm_vgs", std_bins!("vgs"), &["--reportformat", "json", "--units", "b", "--nosuffix", "-o", "vg_name,vg_uuid,vg_size,vg_free,vg_extent_size,pv_count,lv_count,vg_attr"]) },
    Entry { version: V, ..e("lvm_lvs", std_bins!("lvs"), &["--reportformat", "json", "--units", "b", "--nosuffix", "-o", "lv_name,lv_uuid,vg_name,lv_size,lv_attr,lv_path,lv_dm_path,pool_lv,segtype,data_percent,metadata_percent,devices"]) },
    e("lvm_pvs_sep", std_bins!("pvs"), &["--noheadings", "--separator", "|", "--units", "b", "--nosuffix", "-o", "pv_name,pv_uuid,vg_name,pv_size,pv_free,pv_attr"]),
    e("lvm_vgs_sep", std_bins!("vgs"), &["--noheadings", "--separator", "|", "--units", "b", "--nosuffix", "-o", "vg_name,vg_uuid,vg_size,vg_free,vg_extent_size,pv_count,lv_count,vg_attr"]),
    e("lvm_lvs_sep", std_bins!("lvs"), &["--noheadings", "--separator", "|", "--units", "b", "--nosuffix", "-o", "lv_name,lv_uuid,vg_name,lv_size,lv_attr,lv_path,lv_dm_path,pool_lv,segtype,data_percent,metadata_percent,devices"]),
    // smart
    Entry { timeout_s: 5, version: V, ..e("smartctl_version", syno_bins!("smartctl"), &["--version"]) },
    Entry { kind: Some(ArgKind::BlockDevice), ..e("smartctl_info_json", syno_bins!("smartctl"), &["--json", "-i"]) },
    Entry { kind: Some(ArgKind::BlockDevice), ..e("smartctl_info_json_sat", syno_bins!("smartctl"), &["--json", "-d", "sat", "-i"]) },
    Entry { kind: Some(ArgKind::BlockDevice), ..e("smartctl_info", syno_bins!("smartctl"), &["-i"]) },
    Entry { kind: Some(ArgKind::BlockDevice), ..e("smartctl_all_json", syno_bins!("smartctl"), &["--json", "-a"]) },
    // proxmox
    e("pvesh_cluster_status", pve_bins!("pvesh"), &["get", "/cluster/status", "--output-format", "json"]),
    e("pvesh_cluster_resources", pve_bins!("pvesh"), &["get", "/cluster/resources", "--output-format", "json"]),
    e("pvesm_status", pve_bins!("pvesm"), &["status"]),
    e("qm_list", pve_bins!("qm"), &["list"]),
    e("pvecm_status", pve_bins!("pvecm"), &["status"]),
    // iscsi initiator
    e("iscsiadm_session", &["/sbin/iscsiadm", "/usr/sbin/iscsiadm", "/usr/bin/iscsiadm"], &["-m", "session", "-P", "3"]),
    // truenas middleware
    e("midclt_pool_query", std_bins!("midclt"), &["call", "pool.query"]),
    e("midclt_smb_shares", std_bins!("midclt"), &["call", "sharing.smb.query"]),
    e("midclt_nfs_shares", std_bins!("midclt"), &["call", "sharing.nfs.query"]),
    e("midclt_iscsi_extents", std_bins!("midclt"), &["call", "iscsi.extent.query"]),
    e("midclt_iscsi_targets", std_bins!("midclt"), &["call", "iscsi.target.query"]),
];

pub fn find(id: &str) -> Option<&'static Entry> {
    ENTRIES.iter().find(|e| e.id == id)
}

/// SHA-256 of the table as compiled. For each entry in id order, six fields joined with NUL: the
/// id, the candidate paths and the argument vector (each joined with `\x1f`), the argument kind
/// name (empty for none), the timeout in seconds in decimal, and the version probe vector (joined
/// with `\x1f`, empty for none); the records are joined with NUL as well. No trailing separator.
pub fn allowlist_sha256() -> String {
    let mut sorted: Vec<&Entry> = ENTRIES.iter().collect();
    sorted.sort_by_key(|e| e.id);
    let records: Vec<String> = sorted
        .iter()
        .map(|e| {
            [
                e.id.to_string(),
                e.candidates.join("\x1f"),
                e.args.join("\x1f"),
                e.kind.map(ArgKind::name).unwrap_or("").to_string(),
                e.timeout_s.to_string(),
                e.version.map(|v| v.join("\x1f")).unwrap_or_default(),
            ]
            .join("\0")
        })
        .collect();
    crate::proto::hex(&Sha256::digest(records.join("\0").as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn the_table_is_what_the_document_lists() {
        assert_eq!(ENTRIES.len(), 39); // 60 in the document less 19 wmi (phase 2) and 2 synology tools without arguments
        let ids: HashSet<&str> = ENTRIES.iter().map(|e| e.id).collect();
        assert_eq!(ids.len(), ENTRIES.len(), "duplicate id");
        for id in ["lsblk_json", "lsblk_json_legacy", "lsblk_pairs", "blkid_export", "findmnt_json", "btrfs_show", "btrfs_usage", "mdadm_detail_scan", "mdadm_detail", "smartctl_info_json", "smartctl_info_json_sat", "smartctl_info", "smartctl_all_json", "smartctl_version", "zpool_list", "zpool_status", "zfs_list", "zpool_get"] {
            assert!(ids.contains(id), "{id}");
        }
    }

    #[test]
    fn no_entry_can_carry_text_from_the_network_or_change_anything() {
        for e in ENTRIES {
            assert!(!e.candidates.is_empty() && e.candidates.iter().all(|c| c.starts_with('/') && !c.contains("..")), "{}", e.id);
            for a in e.args {
                assert!(!a.contains('\n') && !a.contains('\0'), "{}", e.id);
            }
            // read-only: none of the mutating sub-commands or flags of the tools in the table
            let joined = e.args.join(" ");
            for bad in ["scrub", "balance", "create", "destroy", "import", "snapshot", "repair", "--grow", "--add", "--remove", "--stop", "--assemble", "set ", "clear", "remove"] {
                assert!(!joined.contains(bad), "{} has {bad}", e.id);
            }
            assert!(e.timeout_s >= 1 && e.timeout_s <= 60);
        }
        // exactly the kinds of the document: the kind of an entry is in its id's family
        let kinds: Vec<(&str, ArgKind)> = ENTRIES.iter().filter_map(|e| e.kind.map(|k| (e.id, k))).collect();
        assert_eq!(kinds.len(), 6);
        assert!(kinds.contains(&("btrfs_usage", ArgKind::BtrfsMount)));
        assert!(kinds.contains(&("mdadm_detail", ArgKind::MdDevice)));
        assert_eq!(kinds.iter().filter(|(_, k)| *k == ArgKind::BlockDevice).count(), 4);
    }

    #[test]
    fn the_hash_is_pinned() {
        // Change this value together with ALLOWLIST_VERSION when the table changes.
        assert_eq!(allowlist_sha256(), allowlist_sha256());
        assert_eq!(allowlist_sha256().len(), 64);
        assert_eq!(allowlist_sha256(), PINNED, "the allowlist changed: bump ALLOWLIST_VERSION and update PINNED");
    }

    /// `./build.sh hashes` runs this and prints the values `src/filecat/data/agent_expected.json`
    /// must hold; a Python test fails when the file and the Rust build disagree.
    #[test]
    fn expected_json_matches_this_build() {
        let file: serde_json::Value =
            serde_json::from_str(include_str!("../../src/filecat/data/agent_expected.json")).unwrap();
        let v = &file["1"];
        assert_eq!(v["allowlist_sha256"]["linux"], allowlist_sha256(),
                   "src/filecat/data/agent_expected.json is stale: run ./build.sh hashes and update it");
        assert_eq!(v["deny_sha256"], crate::scope::deny_sha256(),
                   "src/filecat/data/agent_expected.json is stale: run ./build.sh hashes and update it");
    }

    #[test]
    fn print_expected_hashes() {
        println!("EXPECTED allowlist_sha256 {}", allowlist_sha256());
        println!("EXPECTED deny_sha256 {}", crate::scope::deny_sha256());
    }

    const PINNED: &str = "1421d08a57af05c07b6c34f7f18a81b002895370132c6d87773a66010875fa31";
}
