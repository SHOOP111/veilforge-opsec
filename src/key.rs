use anyhow::{bail, Context, Result};
use rand::{rngs::OsRng, RngCore};
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    path::Path,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; 32]);

impl SecretKey {
    pub fn ephemeral() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let metadata = std::fs::symlink_metadata(path).context("cannot inspect key file")?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            bail!("key must be a regular, non-symlink file");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                bail!("key file permissions must deny group and other access (chmod 600)");
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                bail!("key file must not be a Windows reparse point");
            }
        }
        let mut options = OpenOptions::new();
        options.read(true);
        nofollow(&mut options);
        let mut file = options.open(path).context("cannot open key file")?;
        if file.metadata()?.len() != 32 {
            bail!("key file must contain exactly 32 raw bytes");
        }
        let mut key = Self([0; 32]);
        file.read_exact(&mut key.0).context("cannot read key")?;
        let mut extra = [0; 1];
        if file.read(&mut extra)? != 0 {
            bail!("key file changed while being read");
        }
        Ok(key)
    }

    pub fn create(path: &Path) -> Result<()> {
        let key = Self::ephemeral();
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(path)
            .context("cannot create key; destination must not exist")?;
        // On Windows, protect the EMPTY file before writing any key material.
        #[cfg(windows)]
        if let Err(error) = protect_windows_key(path) {
            drop(file);
            let _ = std::fs::remove_file(path);
            return Err(error);
        }
        if file
            .write_all(&key.0)
            .and_then(|_| file.sync_all())
            .is_err()
        {
            drop(file);
            let _ = std::fs::remove_file(path);
            bail!("key write failed; partial file removed when possible");
        }
        Ok(())
    }

    pub fn fingerprint(&self, domain: &str, parts: &[&[u8]]) -> String {
        let mut hash = blake3::Hasher::new_keyed(&self.0);
        hash.update(b"veilforge/v1\0");
        hash.update(&(domain.len() as u64).to_le_bytes());
        hash.update(domain.as_bytes());
        for part in parts {
            hash.update(&(part.len() as u64).to_le_bytes());
            hash.update(part);
        }
        hash.finalize().to_hex().to_string()
    }

    pub fn id(&self) -> String {
        self.fingerprint("key-id", &[])
    }
}

pub(crate) fn nofollow(options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
}

#[cfg(windows)]
fn protect_windows_key(path: &Path) -> Result<()> {
    use std::process::Command;
    let identity = Command::new(crate::windows::system_executable("whoami.exe")?)
        .args(["/user", "/fo", "csv", "/nh"])
        .output()
        .context("cannot obtain current Windows SID")?;
    if !identity.status.success() {
        bail!("Windows identity lookup failed");
    }
    let text = String::from_utf8_lossy(&identity.stdout);
    let sid = text
        .split('"')
        .find(|s| {
            s.starts_with("S-1-")
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || b == b'S' || b == b'-')
        })
        .context("Windows identity did not return a valid SID")?;
    let result = Command::new(crate::windows::system_executable("icacls.exe")?)
        .arg(path)
        .args(["/inheritance:r", "/grant:r"])
        .arg(format!("*{sid}:(F)"))
        .output()
        .context("cannot restrict key ACL")?;
    if !result.status.success() {
        bail!("cannot restrict Windows key ACL; no key material was written");
    }
    Ok(())
}
