//! aegis-service — Windows service for AEGIS X (loop structure).
//!
//! # HONEST STATUS — READ FIRST
//!
//! This file is **NOT FUNCTIONAL and NOT compile-checked on Linux**:
//! it is `cfg(windows)`-gated (Linux builds a stub `main` that exits
//! with an error). On Windows it now contains the full loop
//! *structure* — SCM entry points, initial policy install, file-watch
//! reinstall, uninstall on stop — cross-target compile-checked
//! (`cargo check --target x86_64-pc-windows-gnu --all-targets`,
//! zero errors/warnings) but it has never been natively linked or
//! run under the SCM. The functional check is
//! `tools/windows/verify-service.ps1` (sc.exe create + start,
//! RUNNING + service.log checks, LAN probes, process-alive check,
//! policy-change reload, stop/delete + always-cleanup). Spots most
//! likely to need a touch-up on the first Windows build are marked
//! `WINDOWS-BUILD-CHECK`, as in `engine.rs`.
//!
//! # Behavior (once it compiles and runs under the SCM)
//!
//! * Policy source: the file at `%AEGIS_POLICY_FILE%`, or
//!   `%ProgramData%\AEGIS X\policy.json` by default. The service does
//!   NOT fetch policy from the network and does NOT embed a policy.
//! * Start: install the policy via the WFP engine (transactional
//!   replace, as in `engine.rs`). If the initial install fails, the
//!   service logs the failure and stops with an error exit code
//!   (fail fast and visible — the SCM restart policy, if configured,
//!   restarts it). It never reports RUNNING while unprotected.
//! * Run: every poll tick (default 5s, `AEGIS_POLICY_POLL_SECS`) the
//!   service hashes the policy file. On change it reloads and
//!   reinstalls. A failed reinstall is logged and the PREVIOUS policy
//!   stays installed (fail safe — a bad new file must never strip
//!   protection, because the engine install is transactional and
//!   aborts on error).
//! * A missing or unparsable policy file is likewise logged with the
//!   old policy kept in place — never an uninstall on bad input.
//! * Stop (SCM stop control): uninstall all AEGIS filters, then
//!   report STOPPED. NOTE: this is uninstall-on-stop, per design —
//!   the alternative (leaving filters installed after the service
//!   stops, i.e. fail-closed) is a one-line change in `service_main`
//!   (skip the uninstall call) and is worth revisiting before any
//!   production deployment, since a stopped service currently leaves
//!   the machine unfiltered.
//! * Logging: plain-text appends to
//!   `%ProgramData%\AEGIS X\service.log` (no Event Log integration
//!   yet — follow-up work). If the log file cannot be opened, entries
//!   go to stderr (invisible under the SCM, but harmless).
//! * NOT included: SCM registration itself (use `sc.exe create` or
//!   the MSI — see `docs/WINDOWS_PACKAGING.md`), the API client (the
//!   service reads a local file only), and restart-policy
//!   configuration (set it in the SCM registration, not here).

#[cfg(windows)]
mod imp {
    use aegis_core::Policy;
    use aegis_windows::engine::{self, InstallReport};
    use sha2::{Digest, Sha256};
    use std::ffi::c_void;
    use std::fs;
    use std::io::Write;
    use std::os::windows::ffi::OsStrExt;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{HANDLE, NO_ERROR, WAIT_OBJECT_0};
    use windows::Win32::System::Services::*;

    static mut STOP_EVENT: HANDLE = HANDLE(std::ptr::null_mut());
    static mut STATUS_HANDLE: SERVICE_STATUS_HANDLE =
        SERVICE_STATUS_HANDLE(std::ptr::null_mut());

    fn report(state: SERVICE_STATUS_CURRENT_STATE, wait_hint: u32) {
        report_ex(state, wait_hint, NO_ERROR.0);
    }

    fn report_ex(state: SERVICE_STATUS_CURRENT_STATE, wait_hint: u32, win32_exit: u32) {
        unsafe {
            let mut status = SERVICE_STATUS {
                dwServiceType: SERVICE_WIN32_OWN_PROCESS,
                dwCurrentState: state,
                dwControlsAccepted: if state == SERVICE_RUNNING {
                    SERVICE_ACCEPT_STOP
                } else {
                    0
                },
                dwWin32ExitCode: win32_exit,
                dwServiceSpecificExitCode: 0,
                dwCheckPoint: 0,
                dwWaitHint: wait_hint,
            };
            // WINDOWS-BUILD-CHECK: SERVICE_STATUS field shapes.
            let _ = SetServiceStatus(STATUS_HANDLE, &mut status);
        }
    }

    unsafe extern "system" fn handler(
        control: u32,
        _event_type: u32,
        _event_data: *mut c_void,
        _context: *mut c_void,
    ) -> u32 {
        if control == SERVICE_CONTROL_STOP {
            report(SERVICE_STOP_PENDING, 3000);
            // Copy out of the static first: taking a reference to a
            // mutable static is refused by the static_mut_refs lint.
            let event = STOP_EVENT;
            if !event.is_invalid() {
                let _ = windows::Win32::System::Threading::SetEvent(event);
            }
        }
        NO_ERROR.0
    }

    fn log_path() -> Option<PathBuf> {
        std::env::var_os("ProgramData").map(|d| {
            let mut p = PathBuf::from(d);
            p.push("AEGIS X");
            p.push("service.log");
            p
        })
    }

    fn log_line(msg: &str) {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let line = format!("[{secs}] {msg}\n");
        match log_path() {
            Some(path) => {
                if let Some(parent) = path.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                match fs::OpenOptions::new().create(true).append(true).open(&path) {
                    Ok(mut f) => {
                        let _ = f.write_all(line.as_bytes());
                    }
                    Err(_) => eprintln!("aegis-service: {line}"),
                }
            }
            None => eprintln!("aegis-service: {line}"),
        }
    }

    fn policy_path() -> PathBuf {
        if let Ok(p) = std::env::var("AEGIS_POLICY_FILE") {
            if !p.is_empty() {
                return PathBuf::from(p);
            }
        }
        match std::env::var_os("ProgramData") {
            Some(d) => {
                let mut p = PathBuf::from(d);
                p.push("AEGIS X");
                p.push("policy.json");
                p
            }
            None => PathBuf::from("policy.json"),
        }
    }

    fn poll_interval_ms() -> u32 {
        std::env::var("AEGIS_POLICY_POLL_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v > 0)
            .map(|v| v.saturating_mul(1000).min(u32::MAX as u64) as u32)
            .unwrap_or(5000)
    }

    fn file_hash(path: &PathBuf) -> Option<String> {
        let bytes = fs::read(path).ok()?;
        let mut h = Sha256::new();
        h.update(&bytes);
        Some(format!("{:x}", h.finalize()))
    }

    fn load_and_install(path: &PathBuf) -> Result<InstallReport, String> {
        let text = fs::read_to_string(path)
            .map_err(|e| format!("cannot read policy {}: {e}", path.display()))?;
        let policy = Policy::from_json(&text)?;
        engine::install_policy(&policy)
    }

    unsafe extern "system" fn service_main(_argc: u32, _argv: *mut PWSTR) {
        let mut name: Vec<u16> = std::ffi::OsStr::new("AEGIS X")
            .encode_wide()
            .chain([0])
            .collect();
        // WINDOWS-BUILD-CHECK: handler callback type + context pointer.
        STATUS_HANDLE = match RegisterServiceCtrlHandlerExW(
            PCWSTR(name.as_mut_ptr()),
            Some(handler),
            None,
        ) {
            Ok(handle) => handle,
            Err(_) => return,
        };
        // Copy out of the static first (see the handler for why).
        let status_handle = STATUS_HANDLE;
        if status_handle.is_invalid() {
            return;
        }
        report(SERVICE_START_PENDING, 3000);
        match windows::Win32::System::Threading::CreateEventW(
            None,
            true,
            false,
            PCWSTR::null(),
        ) {
            Ok(event) => STOP_EVENT = event,
            Err(_) => {
                report(SERVICE_STOPPED, 0);
                return;
            }
        }
        // Copy out of the static first (see the handler for why).
        let stop_event = STOP_EVENT;
        if stop_event.is_invalid() {
            report(SERVICE_STOPPED, 0);
            return;
        }

        let path = policy_path();
        log_line(&format!(
            "aegis-service starting; policy file: {}",
            path.display()
        ));
        // Initial install: fail fast and visible on error — never
        // report RUNNING while unprotected.
        match load_and_install(&path) {
            Ok(report) => {
                log_line(&format!(
                    "initial policy installed: {} WFP filters",
                    report.filters_installed
                ));
            }
            Err(e) => {
                log_line(&format!("FATAL: initial policy install failed: {e}"));
                report_ex(SERVICE_STOPPED, 0, 1);
                return;
            }
        }
        let mut last_hash = file_hash(&path);
        report(SERVICE_RUNNING, 0);

        // Watch loop: WaitForSingleObject with a timeout so SCM stop
        // stays responsive while we poll the policy file.
        let interval = poll_interval_ms();
        loop {
            // WINDOWS-BUILD-CHECK: WAIT_OBJECT_0 comparison shape.
            let wait = windows::Win32::System::Threading::WaitForSingleObject(STOP_EVENT, interval);
            if wait == WAIT_OBJECT_0 {
                break; // SCM stop requested.
            }
            // On timeout (or any other wait result that is not the
            // stop signal), re-check the policy file.
            match file_hash(&path) {
                Some(hash) if Some(hash.clone()) != last_hash => {
                    log_line("policy file changed; reinstalling");
                    match load_and_install(&path) {
                        Ok(report) => {
                            log_line(&format!(
                                "policy reinstalled: {} WFP filters",
                                report.filters_installed
                            ));
                            last_hash = Some(hash);
                        }
                        Err(e) => {
                            // Fail safe: previous policy stays
                            // installed (engine install is
                            // transactional); keep the old hash so
                            // the next tick retries.
                            log_line(&format!(
                                "policy reinstall failed, keeping previous policy: {e}"
                            ));
                        }
                    }
                }
                Some(_) => {} // Unchanged.
                None => {
                    log_line("policy file unreadable; keeping previous policy");
                }
            }
        }

        // SCM stop: uninstall all AEGIS filters, then report STOPPED.
        // (See the header note: skipping this uninstall is the
        // fail-closed alternative for production review.)
        report(SERVICE_STOP_PENDING, 3000);
        match engine::uninstall() {
            Ok(()) => log_line("AEGIS filters removed on service stop"),
            Err(e) => log_line(&format!("warning: uninstall on stop failed: {e}")),
        }
        report(SERVICE_STOPPED, 0);
    }

    pub fn run() -> i32 {
        let mut name: Vec<u16> = std::ffi::OsStr::new("AEGIS X")
            .encode_wide()
            .chain([0])
            .collect();
        let table = [
            SERVICE_TABLE_ENTRYW {
                lpServiceName: PWSTR(name.as_mut_ptr()),
                lpServiceProc: Some(service_main),
            },
            SERVICE_TABLE_ENTRYW::default(),
        ];
        // WINDOWS-BUILD-CHECK: table entry construction.
        let ok = unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) };
        if ok.is_ok() {
            0
        } else {
            eprintln!("aegis-service: StartServiceCtrlDispatcherW failed (run under the SCM, not from a console)");
            1
        }
    }
}

fn main() {
    #[cfg(windows)]
    {
        std::process::exit(imp::run());
    }
    #[cfg(not(windows))]
    {
        eprintln!("aegis-service requires Windows 10/11 (service loop structure written, NOT FUNCTIONAL until the first Windows build — see the source banner)");
        std::process::exit(1);
    }
}
