use crate::{key::SecretKey, model::Finding};

#[derive(Default)]
pub struct HostResult {
    pub findings: Vec<Finding>,
    pub issues: Vec<&'static str>,
}

#[cfg(not(windows))]
pub fn audit(_key: &SecretKey) -> HostResult {
    HostResult { findings: Vec::new(), issues: vec!["host-unsupported"] }
}

#[cfg(windows)]
pub fn system_executable(name: &str) -> anyhow::Result<std::path::PathBuf> {
    use anyhow::{bail, Context};
    let root = std::env::var_os("SystemRoot").context("SystemRoot is unavailable")?;
    let root = std::path::PathBuf::from(root);
    if !root.is_absolute() { bail!("SystemRoot must be absolute"); }
    let executable = root.join("System32").join(name);
    let metadata = std::fs::symlink_metadata(&executable).context("Windows system executable unavailable")?;
    if !metadata.is_file() || crate::scan::unsafe_entry(&metadata) { bail!("invalid system executable"); }
    Ok(executable)
}

#[cfg(windows)]
pub fn audit(key: &SecretKey) -> HostResult {
    use crate::detectors::Surface;
    use serde::Deserialize;
    use std::{io::Read, process::{Command, Stdio}, time::{Duration, Instant}};

    #[derive(Deserialize)]
    struct State {
        firewall_disabled: Option<bool>,
        defender_disabled: Option<bool>,
        rdp_enabled: Option<bool>,
        nla_disabled: Option<bool>,
        incomplete: bool,
    }
    // Fixed, read-only script. No user paths, commands, secrets, or identities are interpolated.
    const SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$r = @{firewall_disabled=$null; defender_disabled=$null; rdp_enabled=$null; nla_disabled=$null; incomplete=$false}
try { $p = @(Get-NetFirewallProfile); if($p.Count -ne 3) { throw 'missing profiles' }; $r.firewall_disabled = @($p | Where-Object { -not $_.Enabled }).Count -gt 0 } catch { $r.incomplete=$true }
try { $d = Get-MpComputerStatus; $r.defender_disabled = (-not $d.AntivirusEnabled) -or (-not $d.RealTimeProtectionEnabled) } catch { $r.incomplete=$true }
try { $t = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'; $r.rdp_enabled = $t.fDenyTSConnections -eq 0; if($null -eq $t.fDenyTSConnections) { throw 'missing RDP value' }; if($r.rdp_enabled) { $n = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'; if($null -eq $n.UserAuthentication) { throw 'missing NLA value' }; $r.nla_disabled = $n.UserAuthentication -eq 0 } } catch { $r.incomplete=$true }
$r | ConvertTo-Json -Compress
"#;
    let failure = || HostResult { findings: Vec::new(), issues: vec!["host-incomplete"] };
    let executable = match system_executable("WindowsPowerShell/v1.0/powershell.exe") {
        Ok(path) => path,
        Err(_) => return failure(),
    };
    let mut child = match Command::new(executable)
        .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", SCRIPT])
        .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn() {
        Ok(child) => child,
        Err(_) => return failure(),
    };
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => { if !status.success() { return failure(); } break; }
            Ok(None) if start.elapsed() < Duration::from_secs(15) => std::thread::sleep(Duration::from_millis(50)),
            _ => { let _ = child.kill(); let _ = child.wait(); return failure(); }
        }
    }
    let Some(stdout) = child.stdout.take() else { return failure(); };
    let mut bytes = Vec::new();
    if stdout.take(8193).read_to_end(&mut bytes).is_err() || bytes.len() > 8192 { return failure(); }
    let state: State = match serde_json::from_slice(&bytes) { Ok(state) => state, Err(_) => return failure() };
    let host_id = key.fingerprint("host", &[b"windows-posture"]);
    let surface = Surface { key, file_id: &host_id, path: None };
    let mut result = HostResult::default();
    for (enabled, rule, evidence) in [
        (state.firewall_disabled, "host.firewall", "at least one firewall profile disabled; profile names not collected"),
        (state.defender_disabled, "host.defender", "Defender antivirus or real-time protection reports disabled"),
        (state.rdp_enabled, "host.rdp", "registry permits Remote Desktop connections"),
        (state.nla_disabled, "host.rdp-nla", "RDP enabled without requiring Network Level Authentication"),
    ] {
        if enabled == Some(true) {
            result.findings.push(surface.finding(rule, rule.as_bytes(), None, &[evidence], false));
        }
    }
    if state.incomplete { result.issues.push("host-incomplete"); }
    result
}
