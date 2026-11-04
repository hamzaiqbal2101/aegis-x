//! WFP engine installer — installs translated filters into the live
//! Windows Filtering Platform engine.
//!
//! # STATUS — READ FIRST
//!
//! This file IS compile-checked: `cargo check -p aegis-windows
//! --target x86_64-pc-windows-gnu --all-targets` runs on Linux and
//! type-checks this code against the real `windows` crate bindings
//! (that check caught and fixed 30 errors in the first draft,
//! including a missing `Win32_Security` feature and wrong struct
//! shapes). What it does NOT prove is runtime behavior: linking and
//! actual WFP enforcement still need a Windows 10/11 host — run
//! `tools/windows/verify-m4.ps1` there before any enforcement claim.
//! Runtime-uncertain spots are marked `RUNTIME-CHECK`.
//!
//! # Design
//!
//! * One WFP provider ("AEGIS X") and one sublayer, both with fixed
//!   AEGIS-assigned GUIDs, so reinstall finds them again.
//! * Install = two transactions (this matters — see below): first a
//!   committed delete of the old sublayer (removing all previous
//!   AEGIS filters — replace, never merge), then a fresh transaction
//!   that re-adds the sublayer and the new filters and commits.
//!   Abort on any error rolls that transaction back.
//! * OBSERVED on a real Windows host (Nov 3, 2026): deleting and
//!   re-adding the same sublayer key inside ONE transaction fails
//!   with FWP_E_ALREADY_EXISTS (0x80320009) on the add, because the
//!   delete is only staged until commit. The two-transaction split
//!   is the fix; do not merge them back.
//! * Uninstall = delete the sublayer (its filters go with it), then the
//!   provider. That is the complete cleanup; see tools/windows/.
//! * Sublayer weight is max (0xFFFF): AEGIS filters are evaluated
//!   before other sublayers, including Windows Firewall's own. That
//!   means installing AEGIS makes it the effective firewall — Windows
//!   Firewall rules stop being decisive. This is stated openly, not
//!   hidden: a dedicated firewall product must win arbitration, or it
//!   protects nothing.
//! * Filter keys are deterministic (SHA-256 of rule id + layer), so a
//!   reinstall addresses the same filters.
//! * Direction: WFP distinguishes local vs remote addresses, not
//!   source vs destination. For connect layers (outbound) local = the
//!   rule's source, remote = its destination; for recv-accept layers
//!   (inbound) it is the reverse.
//! * Expansion: one filter per (source address × destination address ×
//!   source port choice × destination port choice) combination. A rule
//!   with address lists or port lists becomes several filters with the
//!   same weight and action, which is always correct (filters from one
//!   rule share a verdict, so order among them cannot change the
//!   outcome). Port ranges use FWP_RANGE0, not per-port expansion.
//! * Fail-closed limits in M4 (each returns an error, never a silently
//!   weakened rule):
//!   - interface-scoped rules (Windows interface naming differs from
//!     Linux names; mapping is M4 follow-up),
//!   - rules matching only `invalid` state (they can never fire),
//!   - app paths that fail app-id resolution (a rule must never be
//!     installed without its app scope).
//! * States otherwise: ALE authorizes at connection establishment and
//!   the connection's later packets follow that verdict, so rule states
//!   are establishment-time semantics on Windows (documented, not
//!   silently reinterpreted).
//! * WFP functions return Win32 error codes (u32), not HRESULTs:
//!   0 = success, anything else = failure.

/// Fixed AEGIS-assigned GUIDs (u128), generated with `uuidgen` on
/// Nov 3, 2026. The ORIGINAL hand-patterned keys (see OLD_* below)
/// failed FwpmSubLayerAdd0 with FWP_E_ALREADY_EXISTS on a real host
/// even after a committed delete — something already holds that key,
/// and the delete could not remove it. The old keys are kept ONLY
/// for the read-only `diag` command, which reports what holds them.
/// Never install with the old keys again.
pub const PROVIDER_KEY_U128: u128 = 0x3F55_9715_1DBD_4EC4_A5D5_22F699826534;
pub const SUBLAYER_KEY_U128: u128 = 0xFFFB_EC5C_282B_4EDD_B80F_B264C1381886;
/// Keys used before Nov 3, 2026 — retained for diagnosis only.
pub const OLD_PROVIDER_KEY_U128: u128 = 0xA1E6_5F3C_9B2A_4D7E_8F10_6C3A9B2D4E5F;
pub const OLD_SUBLAYER_KEY_U128: u128 = 0xB2F7_6E4D_8C3B_5E6F_9A21_7D4B8C3E5F60;

/// Human-readable GUID string from a u128 (standard 8-4-4-4-12 layout).
pub fn fmt_guid(v: u128) -> String {
    let b = v.to_be_bytes();
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11],
        b[12], b[13], b[14], b[15]
    )
}

/// What an install produced.
#[derive(Debug, Clone)]
pub struct InstallReport {
    pub filters_installed: usize,
    pub provider_key: String,
    pub sublayer_key: String,
}

#[cfg(windows)]
mod imp {
    use super::{
        fmt_guid, InstallReport, OLD_PROVIDER_KEY_U128,
        OLD_SUBLAYER_KEY_U128, PROVIDER_KEY_U128, SUBLAYER_KEY_U128,
    };
    use crate::translate::{translate, WfpAction, WfpFilter, WfpLayer};
    use aegis_core::policy::{Cidr, ConnState, PortSpec, Protocol};
    use aegis_core::Policy;
    use std::collections::HashMap;
    use std::ffi::OsStr;
    use std::net::IpAddr;
    use std::os::windows::ffi::OsStrExt;
    use sha2::{Digest, Sha256};
    use windows::core::{GUID, PCWSTR, PWSTR};
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;
    use windows::Win32::Security::PSECURITY_DESCRIPTOR;
    use windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

    /// Win32 error code check: 0 = success.
    fn check(code: u32, what: &str) -> Result<(), String> {
        if code == 0 {
            Ok(())
        } else {
            Err(format!("{what} failed: Win32 error {code} (0x{code:08x})"))
        }
    }

    /// FWP_E_ALREADY_EXISTS — tolerate it when ensuring the provider.
    fn is_already_exists(code: u32) -> bool {
        code == 0x80320009
    }

    fn null_sd() -> PSECURITY_DESCRIPTOR {
        PSECURITY_DESCRIPTOR(std::ptr::null_mut())
    }

    /// Null-terminated UTF-16 string that outlives one FFI call.
    struct WString(Vec<u16>);
    impl WString {
        fn new(s: &str) -> WString {
            let mut v: Vec<u16> = OsStr::new(s).encode_wide().collect();
            v.push(0);
            WString(v)
        }
        fn as_pwstr(&mut self) -> PWSTR {
            PWSTR(self.0.as_mut_ptr())
        }
        fn as_pcwstr(&self) -> PCWSTR {
            PCWSTR(self.0.as_ptr())
        }
    }

    pub struct Engine {
        handle: HANDLE,
    }

    impl Engine {
        pub fn open() -> Result<Engine, String> {
            let mut handle = HANDLE::default();
            unsafe {
                check(
                    FwpmEngineOpen0(
                        PCWSTR::null(),
                        RPC_C_AUTHN_WINNT,
                        None,
                        None,
                        &mut handle,
                    ),
                    "FwpmEngineOpen0 (run as Administrator?)",
                )?;
            }
            Ok(Engine { handle })
        }
    }

    impl Drop for Engine {
        fn drop(&mut self) {
            unsafe {
                let _ = FwpmEngineClose0(self.handle);
            }
        }
    }

    struct Transaction<'a> {
        engine: &'a Engine,
        committed: bool,
    }

    impl<'a> Transaction<'a> {
        fn begin(engine: &'a Engine) -> Result<Transaction<'a>, String> {
            unsafe {
                check(
                    FwpmTransactionBegin0(engine.handle, 0),
                    "FwpmTransactionBegin0",
                )?;
            }
            Ok(Transaction {
                engine,
                committed: false,
            })
        }

        fn commit(mut self) -> Result<(), String> {
            unsafe {
                check(
                    FwpmTransactionCommit0(self.engine.handle),
                    "FwpmTransactionCommit0",
                )?;
            }
            self.committed = true;
            Ok(())
        }
    }

    impl<'a> Drop for Transaction<'a> {
        fn drop(&mut self) {
            if !self.committed {
                unsafe {
                    let _ = FwpmTransactionAbort0(self.engine.handle);
                }
            }
        }
    }

    fn layer_guid(layer: WfpLayer) -> GUID {
        match layer {
            WfpLayer::AleAuthConnectV4 => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            WfpLayer::AleAuthConnectV6 => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            WfpLayer::AleAuthRecvAcceptV4 => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
            WfpLayer::AleAuthRecvAcceptV6 => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        }
    }

    fn is_connect(layer: WfpLayer) -> bool {
        matches!(
            layer,
            WfpLayer::AleAuthConnectV4 | WfpLayer::AleAuthConnectV6
        )
    }

    fn is_v6(layer: WfpLayer) -> bool {
        matches!(
            layer,
            WfpLayer::AleAuthConnectV6 | WfpLayer::AleAuthRecvAcceptV6
        )
    }

    fn filter_key(rule_id: &str, layer: WfpLayer) -> GUID {
        let mut h = Sha256::new();
        h.update(b"aegis-x-filter-v1");
        h.update(rule_id.as_bytes());
        h.update([layer as u8]);
        let digest = h.finalize();
        GUID::from_u128(u128::from_be_bytes(
            digest[0..16].try_into().expect("sha256 is 32 bytes"),
        ))
    }

    fn ensure_provider(engine: &Engine) -> Result<(), String> {
        let mut name = WString::new("AEGIS X");
        let mut desc = WString::new("AEGIS X Next-Generation Firewall");
        let provider = FWPM_PROVIDER0 {
            providerKey: GUID::from_u128(PROVIDER_KEY_U128),
            displayData: FWPM_DISPLAY_DATA0 {
                name: name.as_pwstr(),
                description: desc.as_pwstr(),
            },
            flags: 0,
            serviceName: PWSTR::null(),
            ..Default::default()
        };
        unsafe {
            let code = FwpmProviderAdd0(engine.handle, &provider, null_sd());
            if code == 0 || is_already_exists(code) {
                Ok(())
            } else {
                Err(format!(
                    "FwpmProviderAdd0 failed: Win32 error {code} (0x{code:08x})"
                ))
            }
        }
    }

    fn ensure_sublayer(engine: &Engine) -> Result<(), String> {
        let mut name = WString::new("AEGIS X");
        let mut desc = WString::new("AEGIS X policy sublayer");
        let mut provider_key = GUID::from_u128(PROVIDER_KEY_U128);
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: GUID::from_u128(SUBLAYER_KEY_U128),
            displayData: FWPM_DISPLAY_DATA0 {
                name: name.as_pwstr(),
                description: desc.as_pwstr(),
            },
            flags: 0,
            providerKey: &mut provider_key,
            weight: 0xFFFF,
            ..Default::default()
        };
        unsafe {
            let code = FwpmSubLayerAdd0(engine.handle, &sublayer, null_sd());
            if is_already_exists(code) {
                Err("FwpmSubLayerAdd0 failed: sublayer already exists even \
                     after the committed delete — a previous AEGIS install \
                     may be stuck (Win32 error 0x80320009)".to_string())
            } else {
                check(code, "FwpmSubLayerAdd0")
            }
        }
    }

    /// Delete the AEGIS sublayer, returning the raw Win32 code
    /// (0 = deleted; anything else = not deleted, e.g. not found).
    /// Callers decide whether the code matters; install phase 1 logs
    /// a non-zero code so a stuck sublayer is visible instead of
    /// surfacing later as a confusing ALREADY_EXISTS on add.
    fn delete_sublayer_ignore(engine: &Engine) -> u32 {
        unsafe {
            FwpmSubLayerDeleteByKey0(
                engine.handle,
                &GUID::from_u128(SUBLAYER_KEY_U128),
            )
        }
    }

    /// Enumerate every filter and return the runtime IDs of those
    /// living in the given sublayer. The enum template cannot filter
    /// by sublayer, so match on FWPM_FILTER0.subLayerKey. Read-only;
    /// deletion happens after the enum handle is destroyed, because
    /// deleting during enumeration disturbs the enumeration.
    fn filters_in_sublayer(engine: &Engine, key: u128) -> Result<Vec<u64>, String> {
        let mut enum_handle = HANDLE::default();
        let code = unsafe {
            FwpmFilterCreateEnumHandle0(engine.handle, None, &mut enum_handle)
        };
        if code != 0 {
            return Err(format!(
                "FwpmFilterCreateEnumHandle0 failed: Win32 error {code} (0x{code:08x})"
            ));
        }
        let mut ids = Vec::new();
        let result = (|| -> Result<(), String> {
            loop {
                let mut entries: *mut *mut FWPM_FILTER0 =
                    std::ptr::null_mut();
                let mut returned: u32 = 0;
                let code = unsafe {
                    FwpmFilterEnum0(
                        engine.handle,
                        enum_handle,
                        256,
                        &mut entries,
                        &mut returned,
                    )
                };
                if code != 0 {
                    return Err(format!(
                        "FwpmFilterEnum0 failed: Win32 error {code} (0x{code:08x})"
                    ));
                }
                if returned == 0 || entries.is_null() {
                    break;
                }
                for i in 0..returned as usize {
                    let f = unsafe { &**entries.add(i) };
                    if f.subLayerKey == GUID::from_u128(key) {
                        ids.push(f.filterId);
                    }
                }
                unsafe {
                    let mut p = entries as *mut std::ffi::c_void;
                    FwpmFreeMemory0(&mut p);
                }
                if returned < 256 {
                    break;
                }
            }
            Ok(())
        })();
        unsafe {
            FwpmFilterDestroyEnumHandle0(engine.handle, enum_handle);
        }
        result?;
        Ok(ids)
    }

    /// Delete every filter in the given sublayer (each delete commits
    /// immediately, no transaction). Stops at the first failure so the
    /// caller sees a real error. This MUST run before any sublayer
    /// delete: a sublayer that still contains filters cannot be
    /// deleted — BFE returns FWP_E_IN_USE (0x8032000A). That is the
    /// Nov 3, 2026 lesson: the M4 run's cleanup deleted the sublayer
    /// directly, got IN_USE, ignored it, printed "removed", and left
    /// the whole test policy live — which then blocked the service's
    /// first install with ALREADY_EXISTS.
    fn delete_sublayer_filters(engine: &Engine, key: u128) -> Result<usize, String> {
        let ids = filters_in_sublayer(engine, key)?;
        let mut deleted = 0;
        for id in &ids {
            let code = unsafe { FwpmFilterDeleteById0(engine.handle, *id) };
            if code != 0 {
                return Err(format!(
                    "FwpmFilterDeleteById0({id}) failed: Win32 error {code} (0x{code:08x})"
                ));
            }
            deleted += 1;
        }
        Ok(deleted)
    }

    fn proto_number(proto: Protocol) -> u8 {
        match proto {
            Protocol::Tcp => 6,
            Protocol::Udp => 17,
            Protocol::Icmp => 1,
            Protocol::Icmpv6 => 58,
            Protocol::Any => 0, // never used: Any emits no condition
        }
    }

    fn v4_mask(prefix: u8) -> u32 {
        if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        }
    }

    /// One port match choice for a single WFP filter.
    #[derive(Debug, Clone, Copy)]
    enum PortChoice {
        Any,
        Single(u16),
        Range(u16, u16),
    }

    /// One concrete combination of match values for a single WFP filter.
    struct Expanded {
        local_addr: Option<Cidr>,
        remote_addr: Option<Cidr>,
        local_port: PortChoice,
        remote_port: PortChoice,
    }

    fn port_options(spec: &Option<PortSpec>) -> Vec<PortChoice> {
        match spec {
            None => vec![PortChoice::Any],
            Some(PortSpec::Single(p)) => vec![PortChoice::Single(*p)],
            Some(PortSpec::List(ps)) => {
                ps.iter().map(|p| PortChoice::Single(*p)).collect()
            }
            Some(PortSpec::Range { range: (low, high) }) => {
                vec![PortChoice::Range(*low, *high)]
            }
        }
    }

    /// Expand one translated filter into concrete filters. Returns an
    /// empty vec when the filter's family has no addresses on this layer
    /// (the filter must be skipped, never broadened to "any").
    fn expand(filter: &WfpFilter) -> Vec<Expanded> {
        let v6 = is_v6(filter.layer);
        let fam = |c: &Cidr| match (v6, c.network) {
            (true, IpAddr::V6(_)) => true,
            (false, IpAddr::V4(_)) => true,
            _ => false,
        };
        if !filter.src_addrs.is_empty() && !filter.src_addrs.iter().any(fam) {
            return vec![];
        }
        if !filter.dst_addrs.is_empty() && !filter.dst_addrs.iter().any(fam) {
            return vec![];
        }
        let srcs: Vec<Option<Cidr>> = {
            let kept: Vec<Cidr> = filter
                .src_addrs
                .iter()
                .filter(|c| fam(c))
                .cloned()
                .collect();
            if kept.is_empty() {
                vec![None]
            } else {
                kept.into_iter().map(Some).collect()
            }
        };
        let dsts: Vec<Option<Cidr>> = {
            let kept: Vec<Cidr> = filter
                .dst_addrs
                .iter()
                .filter(|c| fam(c))
                .cloned()
                .collect();
            if kept.is_empty() {
                vec![None]
            } else {
                kept.into_iter().map(Some).collect()
            }
        };
        let sport_opts = port_options(&filter.src_port);
        let dport_opts = port_options(&filter.dst_port);
        let connect = is_connect(filter.layer);
        let mut out = Vec::new();
        for s in &srcs {
            for d in &dsts {
                for sp in &sport_opts {
                    for dp in &dport_opts {
                        // Local/remote mapping depends on direction.
                        let (local_addr, remote_addr) = if connect {
                            (s.clone(), d.clone())
                        } else {
                            (d.clone(), s.clone())
                        };
                        let (local_port, remote_port) = if connect {
                            (*sp, *dp)
                        } else {
                            (*dp, *sp)
                        };
                        out.push(Expanded {
                            local_addr,
                            remote_addr,
                            local_port,
                            remote_port,
                        });
                    }
                }
            }
        }
        out
    }

    fn app_id_blob(
        _engine: &Engine,
        path: &str,
        cache: &mut HashMap<String, *mut FWP_BYTE_BLOB>,
    ) -> Result<*mut FWP_BYTE_BLOB, String> {
        if let Some(blob) = cache.get(path) {
            return Ok(*blob);
        }
        let wpath = WString::new(path);
        let mut blob: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
        unsafe {
            check(
                FwpmGetAppIdFromFileName0(wpath.as_pcwstr(), &mut blob),
                &format!("FwpmGetAppIdFromFileName0 for {path}"),
            )?;
        }
        cache.insert(path.to_string(), blob);
        Ok(blob)
    }

    /// Scratch storage for values that WFP condition values point at.
    /// Everything here must outlive the FwpmFilterAdd0 call that uses it.
    /// (FWP condition values hold pointers for masks, weights and ranges,
    /// so these cannot be temporaries.)
    #[derive(Default)]
    struct Scratch {
        v4: Vec<Box<FWP_V4_ADDR_AND_MASK>>,
        v6: Vec<Box<FWP_V6_ADDR_AND_MASK>>,
        weights: Vec<Box<u64>>,
        ranges: Vec<Box<FWP_RANGE0>>,
    }

    fn addr_condition(
        is_local: bool,
        cidr: &Cidr,
        scratch: &mut Scratch,
    ) -> FWPM_FILTER_CONDITION0 {
        let field = if is_local {
            FWPM_CONDITION_IP_LOCAL_ADDRESS
        } else {
            FWPM_CONDITION_IP_REMOTE_ADDRESS
        };
        match cidr.network {
            IpAddr::V4(ip) => {
                scratch.v4.push(Box::new(FWP_V4_ADDR_AND_MASK {
                    addr: u32::from(ip),
                    mask: v4_mask(cidr.prefix),
                }));
                let mask = scratch.v4.last_mut().expect("just pushed").as_mut()
                    as *mut FWP_V4_ADDR_AND_MASK;
                FWPM_FILTER_CONDITION0 {
                    fieldKey: field,
                    matchType: FWP_MATCH_EQUAL,
                    conditionValue: FWP_CONDITION_VALUE0 {
                        r#type: FWP_V4_ADDR_MASK,
                        Anonymous: FWP_CONDITION_VALUE0_0 { v4AddrMask: mask },
                    },
                }
            }
            IpAddr::V6(ip) => {
                scratch.v6.push(Box::new(FWP_V6_ADDR_AND_MASK {
                    addr: ip.octets(),
                    prefixLength: cidr.prefix,
                }));
                let mask = scratch.v6.last_mut().expect("just pushed").as_mut()
                    as *mut FWP_V6_ADDR_AND_MASK;
                FWPM_FILTER_CONDITION0 {
                    fieldKey: field,
                    matchType: FWP_MATCH_EQUAL,
                    conditionValue: FWP_CONDITION_VALUE0 {
                        r#type: FWP_V6_ADDR_MASK,
                        Anonymous: FWP_CONDITION_VALUE0_0 { v6AddrMask: mask },
                    },
                }
            }
        }
    }

    fn port_condition(
        is_local: bool,
        choice: PortChoice,
        scratch: &mut Scratch,
    ) -> Option<FWPM_FILTER_CONDITION0> {
        let field = if is_local {
            FWPM_CONDITION_IP_LOCAL_PORT
        } else {
            FWPM_CONDITION_IP_REMOTE_PORT
        };
        match choice {
            PortChoice::Any => None,
            PortChoice::Single(port) => Some(FWPM_FILTER_CONDITION0 {
                fieldKey: field,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT16,
                    Anonymous: FWP_CONDITION_VALUE0_0 { uint16: port },
                },
            }),
            PortChoice::Range(low, high) => {
                scratch.ranges.push(Box::new(FWP_RANGE0 {
                    valueLow: FWP_VALUE0 {
                        r#type: FWP_UINT16,
                        Anonymous: FWP_VALUE0_0 { uint16: low },
                    },
                    valueHigh: FWP_VALUE0 {
                        r#type: FWP_UINT16,
                        Anonymous: FWP_VALUE0_0 { uint16: high },
                    },
                }));
                let range = scratch.ranges.last_mut().expect("just pushed").as_mut()
                    as *mut FWP_RANGE0;
                Some(FWPM_FILTER_CONDITION0 {
                    fieldKey: field,
                    matchType: FWP_MATCH_RANGE,
                    conditionValue: FWP_CONDITION_VALUE0 {
                        r#type: FWP_RANGE_TYPE,
                        Anonymous: FWP_CONDITION_VALUE0_0 { rangeValue: range },
                    },
                })
            }
        }
    }

    fn add_one_filter(
        engine: &Engine,
        filter: &WfpFilter,
        ex: &Expanded,
        app_blobs: &mut HashMap<String, *mut FWP_BYTE_BLOB>,
    ) -> Result<(), String> {
        let mut scratch = Scratch::default();
        let mut conditions: Vec<FWPM_FILTER_CONDITION0> = Vec::new();
        if filter.protocol != Protocol::Any {
            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_PROTOCOL,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT8,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        uint8: proto_number(filter.protocol),
                    },
                },
            });
        }
        if let Some(cidr) = &ex.local_addr {
            conditions.push(addr_condition(true, cidr, &mut scratch));
        }
        if let Some(cidr) = &ex.remote_addr {
            conditions.push(addr_condition(false, cidr, &mut scratch));
        }
        if let Some(c) = port_condition(true, ex.local_port, &mut scratch) {
            conditions.push(c);
        }
        if let Some(c) = port_condition(false, ex.remote_port, &mut scratch) {
            conditions.push(c);
        }
        if let Some(app) = &filter.app {
            let blob = app_id_blob(engine, app, app_blobs)?;
            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_ALE_APP_ID,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_BYTE_BLOB_TYPE,
                    Anonymous: FWP_CONDITION_VALUE0_0 { byteBlob: blob },
                },
            });
        }

        // Weight is a pointed-to u64 in FWP_VALUE0: box it so the
        // pointer stays valid through the Add call.
        scratch.weights.push(Box::new(filter.weight));
        let weight_ptr = scratch.weights.last_mut().expect("just pushed").as_mut()
            as *mut u64;

        let mut name = WString::new(&format!("AEGIS X: {}", filter.id));
        let mut desc = WString::new(&format!("AEGIS X rule {}", filter.id));
        let mut provider_key = GUID::from_u128(PROVIDER_KEY_U128);
        let action_type = match filter.action {
            WfpAction::Permit => FWP_ACTION_PERMIT,
            WfpAction::Block => FWP_ACTION_BLOCK,
        };
        let wfp_filter = FWPM_FILTER0 {
            filterKey: filter_key(&filter.id, filter.layer),
            displayData: FWPM_DISPLAY_DATA0 {
                name: name.as_pwstr(),
                description: desc.as_pwstr(),
            },
            providerKey: &mut provider_key,
            layerKey: layer_guid(filter.layer),
            subLayerKey: GUID::from_u128(SUBLAYER_KEY_U128),
            weight: FWP_VALUE0 {
                r#type: FWP_UINT64,
                Anonymous: FWP_VALUE0_0 { uint64: weight_ptr },
            },
            numFilterConditions: conditions.len() as u32,
            filterCondition: conditions.as_mut_ptr(),
            action: FWPM_ACTION0 {
                r#type: action_type,
                Anonymous: FWPM_ACTION0_0 {
                    filterType: GUID::zeroed(),
                },
            },
            ..Default::default()
        };
        unsafe {
            let mut id: u64 = 0;
            check(
                FwpmFilterAdd0(
                    engine.handle,
                    &wfp_filter,
                    null_sd(),
                    Some(&mut id as *mut u64),
                ),
                &format!("FwpmFilterAdd0 for rule {}", filter.id),
            )?;
        }
        Ok(())
    }

    fn gate_policy(policy: &Policy) -> Result<(), String> {
        for rule in &policy.rules {
            if rule.in_interface.is_some() || rule.out_interface.is_some() {
                return Err(format!(
                    "rule {} uses interface scoping, unsupported on Windows in M4",
                    rule.id
                ));
            }
            if rule.states.len() == 1 && rule.states[0] == ConnState::Invalid {
                return Err(format!(
                    "rule {} matches only invalid state and can never fire",
                    rule.id
                ));
            }
        }
        Ok(())
    }

    pub fn install_policy(policy: &Policy) -> Result<InstallReport, String> {
        gate_policy(policy)?;
        let filters = translate(policy);
        // Phase 1: committed delete of any previous sublayer (and its
        // filters). This MUST be its own transaction that commits
        // before phase 2: deleting and re-adding the same sublayer key
        // inside one transaction fails with FWP_E_ALREADY_EXISTS on
        // real Windows (observed Nov 3, 2026) because the delete is
        // only staged until commit. Filters go FIRST: a sublayer with
        // filters cannot be deleted (FWP_E_IN_USE), so skipping this
        // step leaves the old policy live and breaks the phase-2 add.
        {
            let engine = Engine::open()?;
            let n = delete_sublayer_filters(&engine, SUBLAYER_KEY_U128)?;
            if n > 0 {
                eprintln!("phase-1: removed {n} filter(s) from the previous policy");
            }
            let txn = Transaction::begin(&engine)?;
            let code = delete_sublayer_ignore(&engine);
            if code != 0 && code != 0x80320007 {
                // NOT_FOUND (no previous sublayer) is fine; anything
                // else is real and must fail loudly here instead of
                // surfacing later as a confusing ALREADY_EXISTS.
                return Err(format!(
                    "phase-1 sublayer delete failed: Win32 error {code} (0x{code:08x})"
                ));
            }
            txn.commit()?;
        }
        // Phase 2: fresh transaction — provider + sublayer + filters.
        let engine = Engine::open()?;
        let txn = Transaction::begin(&engine)?;
        ensure_provider(&engine)?;
        ensure_sublayer(&engine)?;
        let mut app_blobs: HashMap<String, *mut FWP_BYTE_BLOB> = HashMap::new();
        let result = (|| -> Result<usize, String> {
            let mut count = 0;
            for filter in &filters {
                for ex in expand(filter) {
                    add_one_filter(&engine, filter, &ex, &mut app_blobs)?;
                    count += 1;
                }
            }
            Ok(count)
        })();
        let count = match result {
            Ok(count) => {
                txn.commit()?;
                count
            }
            Err(e) => {
                drop(txn); // aborts
                for (_, blob) in app_blobs.drain() {
                    unsafe {
                        let mut p = blob as *mut std::ffi::c_void;
                        FwpmFreeMemory0(&mut p);
                    }
                }
                return Err(e);
            }
        };
        for (_, blob) in app_blobs.drain() {
            unsafe {
                let mut p = blob as *mut std::ffi::c_void;
                FwpmFreeMemory0(&mut p);
            }
        }
        Ok(InstallReport {
            filters_installed: count,
            provider_key: fmt_guid(PROVIDER_KEY_U128),
            sublayer_key: fmt_guid(SUBLAYER_KEY_U128),
        })
    }

    pub fn uninstall() -> Result<(), String> {
        // Cascade, in order: filters, then sublayer, then provider.
        // The old version deleted the sublayer directly and IGNORED
        // both delete codes, so every cleanup printed "removed" while
        // leaving the policy live whenever filters existed (observed
        // Nov 3, 2026: the M4 run's cleanup left all 8 test filters
        // behind). Never again: NOT_FOUND (nothing installed) is the
        // only tolerated code; any other failure is an error, and a
        // partially completed uninstall reports it instead of lying.
        // Sublayer and provider go in separate committed transactions:
        // same staged-delete visibility reason as install phase 1/2.
        let engine = Engine::open()?;
        delete_sublayer_filters(&engine, SUBLAYER_KEY_U128)?;
        {
            let engine = Engine::open()?;
            let txn = Transaction::begin(&engine)?;
            let code = delete_sublayer_ignore(&engine);
            if code != 0 && code != 0x80320007 {
                return Err(format!(
                    "FwpmSubLayerDeleteByKey0 failed: Win32 error {code} (0x{code:08x})"
                ));
            }
            txn.commit()?;
        }
        {
            let engine = Engine::open()?;
            let txn = Transaction::begin(&engine)?;
            let pcode = unsafe {
                FwpmProviderDeleteByKey0(
                    engine.handle,
                    &GUID::from_u128(PROVIDER_KEY_U128),
                )
            };
            if pcode != 0 && pcode != 0x80320005 {
                return Err(format!(
                    "FwpmProviderDeleteByKey0 failed: Win32 error {pcode} (0x{pcode:08x})"
                ));
            }
            txn.commit()?;
        }
        Ok(())
    }

    fn pwstr_to_string(p: PWSTR) -> String {
        if p.is_null() {
            return String::new();
        }
        unsafe {
            let mut len = 0usize;
            while *p.0.add(len) != 0 {
                len += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(p.0, len))
        }
    }

    /// Read-only diagnosis: report what (if anything) already holds
    /// the old and new provider/sublayer keys. Never modifies WFP.
    /// A sublayer that EXISTS with a foreign name (a system or
    /// third-party product's sublayer) explains an ALREADY_EXISTS on
    /// add that no delete can fix — the fix is new keys, not force.
    pub fn diag() -> Result<String, String> {
        let engine = Engine::open()?;
        let mut out = String::new();
        for (label, key) in [
            ("old sublayer", OLD_SUBLAYER_KEY_U128),
            ("new sublayer", SUBLAYER_KEY_U128),
        ] {
            let mut ptr: *mut FWPM_SUBLAYER0 = std::ptr::null_mut();
            let code = unsafe {
                FwpmSubLayerGetByKey0(
                    engine.handle,
                    &GUID::from_u128(key),
                    &mut ptr,
                )
            };
            if code == 0 && !ptr.is_null() {
                let s = unsafe { &*ptr };
                out.push_str(&format!(
                    "{label} {}: EXISTS name={:?} description={:?} weight={} flags={}\n",
                    fmt_guid(key),
                    pwstr_to_string(s.displayData.name),
                    pwstr_to_string(s.displayData.description),
                    s.weight,
                    s.flags
                ));
                unsafe {
                    let mut p = ptr as *mut std::ffi::c_void;
                    FwpmFreeMemory0(&mut p);
                }
            } else {
                out.push_str(&format!(
                    "{label} {}: absent (Win32 error {code} / 0x{code:08x})\n",
                    fmt_guid(key)
                ));
            }
        }
        for (label, key) in [
            ("old provider", OLD_PROVIDER_KEY_U128),
            ("new provider", PROVIDER_KEY_U128),
        ] {
            let mut ptr: *mut FWPM_PROVIDER0 = std::ptr::null_mut();
            let code = unsafe {
                FwpmProviderGetByKey0(
                    engine.handle,
                    &GUID::from_u128(key),
                    &mut ptr,
                )
            };
            if code == 0 && !ptr.is_null() {
                let pr = unsafe { &*ptr };
                out.push_str(&format!(
                    "{label} {}: EXISTS name={:?}\n",
                    fmt_guid(key),
                    pwstr_to_string(pr.displayData.name)
                ));
                unsafe {
                    let mut p = ptr as *mut std::ffi::c_void;
                    FwpmFreeMemory0(&mut p);
                }
            } else {
                out.push_str(&format!(
                    "{label} {}: absent (Win32 error {code} / 0x{code:08x})\n",
                    fmt_guid(key)
                ));
            }
        }
        Ok(out)
    }

    /// Delete the OLD (pre-Nov-3) provider/sublayer orphans, reporting
    /// the exact Win32 code of every step. The normal `uninstall`
    /// silently ignores delete codes, which hid the fact that these
    /// deletes were failing while still printing "removed".
    /// Root cause found Nov 3, 2026: the deletes fail with
    /// FWP_E_IN_USE (0x8032000A) — "the object is referenced by other
    /// objects, so it cannot be deleted." The old sublayer still
    /// contains live filters from the earlier successful install, so
    /// the cascade order matters: delete the filters FIRST, then the
    /// sublayer, then the provider. Two separate committed
    /// transactions for sublayer/provider: deleting both in one
    /// transaction risks the same staged-delete visibility problem
    /// seen with delete+add.
    pub fn remove_old() -> Result<String, String> {
        let mut out = String::new();
        // Step 0: enumerate every filter and collect the ones living
        // in the old sublayer. The enum template cannot filter by
        // sublayer, so match on FWPM_FILTER0.subLayerKey. Collect
        // first, delete after the enum handle is destroyed: deleting
        // during enumeration disturbs the enumeration.
        let old_filter_ids: Vec<u64> = {
            let engine = Engine::open()?;
            let mut enum_handle = HANDLE::default();
            let code = unsafe {
                FwpmFilterCreateEnumHandle0(
                    engine.handle,
                    None,
                    &mut enum_handle,
                )
            };
            if code != 0 {
                return Err(format!(
                    "FwpmFilterCreateEnumHandle0 failed: Win32 error {code} (0x{code:08x})"
                ));
            }
            let mut ids = Vec::new();
            loop {
                let mut entries: *mut *mut FWPM_FILTER0 =
                    std::ptr::null_mut();
                let mut returned: u32 = 0;
                let code = unsafe {
                    FwpmFilterEnum0(
                        engine.handle,
                        enum_handle,
                        256,
                        &mut entries,
                        &mut returned,
                    )
                };
                if code != 0 {
                    unsafe {
                        FwpmFilterDestroyEnumHandle0(
                            engine.handle,
                            enum_handle,
                        );
                    }
                    return Err(format!(
                        "FwpmFilterEnum0 failed: Win32 error {code} (0x{code:08x})"
                    ));
                }
                if returned == 0 || entries.is_null() {
                    break;
                }
                for i in 0..returned as usize {
                    let f = unsafe { &**entries.add(i) };
                    if f.subLayerKey
                        == GUID::from_u128(OLD_SUBLAYER_KEY_U128)
                    {
                        ids.push(f.filterId);
                    }
                }
                unsafe {
                    let mut p = entries as *mut std::ffi::c_void;
                    FwpmFreeMemory0(&mut p);
                }
                if returned < 256 {
                    break;
                }
            }
            unsafe {
                FwpmFilterDestroyEnumHandle0(engine.handle, enum_handle);
            }
            ids
        };
        out.push_str(&format!(
            "old sublayer filters found: {}\n",
            old_filter_ids.len()
        ));
        // Step 0b: delete those filters (no transaction: each delete
        // commits immediately, and a failed one must not block the
        // rest from being attempted).
        {
            let engine = Engine::open()?;
            for id in &old_filter_ids {
                let code =
                    unsafe { FwpmFilterDeleteById0(engine.handle, *id) };
                out.push_str(&format!(
                    "delete filter {id}: Win32 error {code} (0x{code:08x})\n"
                ));
            }
        }
        {
            let engine = Engine::open()?;
            let txn = Transaction::begin(&engine)?;
            let code = unsafe {
                FwpmSubLayerDeleteByKey0(
                    engine.handle,
                    &GUID::from_u128(OLD_SUBLAYER_KEY_U128),
                )
            };
            out.push_str(&format!(
                "delete old sublayer: Win32 error {code} (0x{code:08x})\n"
            ));
            txn.commit()?;
        }
        {
            let engine = Engine::open()?;
            let txn = Transaction::begin(&engine)?;
            let code = unsafe {
                FwpmProviderDeleteByKey0(
                    engine.handle,
                    &GUID::from_u128(OLD_PROVIDER_KEY_U128),
                )
            };
            out.push_str(&format!(
                "delete old provider: Win32 error {code} (0x{code:08x})\n"
            ));
            txn.commit()?;
        }
        // Verify what remains of the old keys.
        let engine = Engine::open()?;
        let mut ptr: *mut FWPM_SUBLAYER0 = std::ptr::null_mut();
        let code = unsafe {
            FwpmSubLayerGetByKey0(
                engine.handle,
                &GUID::from_u128(OLD_SUBLAYER_KEY_U128),
                &mut ptr,
            )
        };
        if code == 0 && !ptr.is_null() {
            out.push_str("old sublayer: STILL EXISTS after delete\n");
            unsafe {
                let mut p = ptr as *mut std::ffi::c_void;
                FwpmFreeMemory0(&mut p);
            }
        } else {
            out.push_str(&format!(
                "old sublayer: gone (GetByKey Win32 error {code} / 0x{code:08x})\n"
            ));
        }
        let mut pptr: *mut FWPM_PROVIDER0 = std::ptr::null_mut();
        let code = unsafe {
            FwpmProviderGetByKey0(
                engine.handle,
                &GUID::from_u128(OLD_PROVIDER_KEY_U128),
                &mut pptr,
            )
        };
        if code == 0 && !pptr.is_null() {
            out.push_str("old provider: STILL EXISTS after delete\n");
            unsafe {
                let mut p = pptr as *mut std::ffi::c_void;
                FwpmFreeMemory0(&mut p);
            }
        } else {
            out.push_str(&format!(
                "old provider: gone (GetByKey Win32 error {code} / 0x{code:08x})\n"
            ));
        }
        Ok(out)
    }

    pub fn status() -> Result<String, String> {
        let _engine = Engine::open()?;
        Ok(format!(
            "WFP engine reachable (Administrator access confirmed).\nAEGIS provider key: {}\nAEGIS sublayer key: {}\nNote: filter enumeration is M4 follow-up; use uninstall to remove all AEGIS filters.",
            fmt_guid(PROVIDER_KEY_U128),
            fmt_guid(SUBLAYER_KEY_U128)
        ))
    }
}

#[cfg(not(windows))]
mod imp {
    use super::InstallReport;
    use aegis_core::Policy;

    pub fn install_policy(_policy: &Policy) -> Result<InstallReport, String> {
        Err("aegis-win requires Windows 10/11 (WFP is a Windows-only API)".to_string())
    }

    pub fn uninstall() -> Result<(), String> {
        Err("aegis-win requires Windows 10/11 (WFP is a Windows-only API)".to_string())
    }

    pub fn diag() -> Result<String, String> {
        Err("aegis-win requires Windows 10/11 (WFP is a Windows-only API)".to_string())
    }

    pub fn remove_old() -> Result<String, String> {
        Err("aegis-win requires Windows 10/11 (WFP is a Windows-only API)".to_string())
    }

    pub fn status() -> Result<String, String> {
        Err("aegis-win requires Windows 10/11 (WFP is a Windows-only API)".to_string())
    }
}

pub use imp::{diag, install_policy, remove_old, status, uninstall};
