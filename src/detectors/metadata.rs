use super::Surface;
use crate::model::Finding;
use anyhow::{Context, Result};
use regex::Regex;
use std::io::{Cursor, Read};
use zeroize::Zeroizing;

pub struct MetadataDetector {
    identity_xml: Regex,
    pdf_identity: Regex,
    pdf_active: Regex,
    external: Regex,
}

#[derive(Default)]
pub struct MetadataResult {
    pub findings: Vec<Finding>,
    pub recognized: bool,
    pub incomplete: bool,
}

impl MetadataDetector {
    pub fn new() -> Result<Self> {
        Ok(Self {
            identity_xml: Regex::new(
                r"(?is)<(?:[a-z][a-z0-9]*:)?(?:creator|lastModifiedBy|author|producer|creatortool)\b[^>]*>\s*[^<\s]",
            )?,
            pdf_identity: Regex::new(r"(?i)/(?:Author|Creator|Producer)\s*[<(]")?,
            pdf_active: Regex::new(r"/(?:JavaScript|JS|Launch|OpenAction|AA)\b")?,
            external: Regex::new(r#"(?i)TargetMode\s*=\s*["']External["']"#)?,
        })
    }

    pub fn scan(&self, bytes: &[u8], extension: &str, surface: &Surface<'_>) -> MetadataResult {
        if bytes.starts_with(b"\xff\xd8") {
            return jpeg(bytes, surface);
        }
        if bytes.starts_with(b"%PDF-") {
            let text = Zeroizing::new(String::from_utf8_lossy(bytes).into_owned());
            let mut result = MetadataResult {
                recognized: true,
                ..Default::default()
            };
            if self.pdf_identity.is_match(&text) || self.identity_xml.is_match(&text) {
                result.findings.push(surface.finding(
                    "metadata.identity",
                    b"pdf-identity",
                    None,
                    &["PDF identity field; value omitted"],
                    false,
                ));
            }
            if self.pdf_active.is_match(&text) {
                result.findings.push(surface.finding(
                    "metadata.active-content",
                    b"pdf-active",
                    None,
                    &["PDF action name; action not executed"],
                    false,
                ));
            }
            // This is deliberately not a full PDF engine. Compressed/encrypted objects can hide fields.
            result.incomplete = true;
            return result;
        }
        if matches!(
            extension,
            "docx" | "docm" | "xlsx" | "xlsm" | "pptx" | "pptm"
        ) {
            return self
                .ooxml(bytes, surface)
                .unwrap_or_else(|_| MetadataResult {
                    recognized: true,
                    incomplete: true,
                    ..Default::default()
                });
        }
        if matches!(
            extension,
            "jpg"
                | "jpeg"
                | "pdf"
                | "png"
                | "tif"
                | "tiff"
                | "webp"
                | "heic"
                | "heif"
                | "doc"
                | "xls"
                | "ppt"
                | "odt"
                | "ods"
                | "odp"
        ) {
            return MetadataResult {
                recognized: true,
                incomplete: true,
                ..Default::default()
            };
        }
        MetadataResult::default()
    }

    fn ooxml(&self, bytes: &[u8], surface: &Surface<'_>) -> Result<MetadataResult> {
        let mut archive =
            zip::ZipArchive::new(Cursor::new(bytes)).context("invalid Office archive")?;
        let mut result = MetadataResult {
            recognized: true,
            ..Default::default()
        };
        if archive.len() > 4096 {
            result.incomplete = true;
            return Ok(result);
        }
        let mut macro_found = false;
        for name in archive.file_names() {
            match name {
                Ok(name) => macro_found |= name.to_ascii_lowercase().ends_with("vbaproject.bin"),
                Err(_) => result.incomplete = true,
            }
        }
        if macro_found {
            result.findings.push(surface.finding(
                "metadata.active-content",
                b"office-macro",
                None,
                &["VBA project member; never extracted or executed"],
                false,
            ));
        }
        const MEMBERS: &[&str] = &[
            "docProps/core.xml",
            "docProps/app.xml",
            "_rels/.rels",
            "word/_rels/document.xml.rels",
            "word/_rels/settings.xml.rels",
            "xl/_rels/workbook.xml.rels",
            "ppt/_rels/presentation.xml.rels",
        ];
        let mut identity = false;
        let mut external = false;
        let mut budget = 1024 * 1024u64;
        for name in MEMBERS {
            let mut member = match archive.by_name(name) {
                Ok(file) => file,
                Err(zip::result::ZipError::FileNotFound) => continue,
                Err(_) => {
                    result.incomplete = true;
                    continue;
                }
            };
            let size = member.size();
            if size > 256 * 1024 || size > budget {
                result.incomplete = true;
                continue;
            }
            budget = budget.saturating_sub(size);
            let mut data = Zeroizing::new(Vec::new());
            if Read::by_ref(&mut member)
                .take(size + 1)
                .read_to_end(&mut data)
                .is_err()
                || data.len() as u64 != size
            {
                result.incomplete = true;
                continue;
            }
            let Ok(text) = std::str::from_utf8(&data) else {
                result.incomplete = true;
                continue;
            };
            identity |= self.identity_xml.is_match(text);
            external |= self.external.is_match(text);
        }
        if identity {
            result.findings.push(surface.finding(
                "metadata.identity",
                b"office-identity",
                None,
                &["Office author/editor metadata; values omitted"],
                false,
            ));
        }
        if external {
            result.findings.push(surface.finding(
                "metadata.active-content",
                b"office-external",
                None,
                &["external package relationship; may be an ordinary hyperlink"],
                false,
            ));
        }
        // Relationships outside the bounded member allowlist are not inspected.
        result.incomplete = archive.file_names().any(|name| match name {
            Ok(name) => name.ends_with(".rels") && !MEMBERS.contains(&name.as_ref()),
            Err(_) => true,
        }) || result.incomplete;
        Ok(result)
    }
}

fn jpeg(bytes: &[u8], surface: &Surface<'_>) -> MetadataResult {
    let mut result = MetadataResult {
        recognized: true,
        ..Default::default()
    };
    let mut cursor = 2usize;
    let mut gps = false;
    let mut identity = false;
    let mut reached_image_data = false;
    while cursor < bytes.len() {
        if bytes[cursor] != 0xff {
            result.incomplete = true;
            break;
        }
        while cursor < bytes.len() && bytes[cursor] == 0xff {
            cursor += 1;
        }
        let Some(&marker) = bytes.get(cursor) else {
            result.incomplete = true;
            break;
        };
        cursor += 1;
        if marker == 0xda || marker == 0xd9 {
            reached_image_data = true;
            break;
        } // Stop at scan data or end-of-image.
        if marker == 0x01 || (0xd0..=0xd7).contains(&marker) {
            continue;
        }
        let Some(length_bytes) = bytes.get(cursor..cursor.saturating_add(2)) else {
            result.incomplete = true;
            break;
        };
        let length = u16::from_be_bytes([length_bytes[0], length_bytes[1]]) as usize;
        if length < 2 {
            result.incomplete = true;
            break;
        }
        let Some(payload) = bytes.get(cursor + 2..cursor.saturating_add(length)) else {
            result.incomplete = true;
            break;
        };
        if marker == 0xe1 && payload.starts_with(b"Exif\0\0") {
            match tiff_tags(&payload[6..]) {
                Some((has_gps, has_identity)) => {
                    gps |= has_gps;
                    identity |= has_identity;
                }
                None => result.incomplete = true,
            }
        } else if marker == 0xe1 {
            // XMP can carry identity and location; not parsed by this EXIF-only reader.
            result.incomplete = true;
        }
        cursor += length;
    }
    result.incomplete |= !reached_image_data;
    if gps {
        result.findings.push(surface.finding(
            "metadata.gps",
            b"exif-gps",
            None,
            &["GPS IFD pointer present; coordinates not collected"],
            false,
        ));
    }
    if identity {
        result.findings.push(surface.finding(
            "metadata.identity",
            b"exif-identity",
            None,
            &["EXIF artist/copyright/device tags; values omitted"],
            false,
        ));
    }
    result
}

fn tiff_tags(bytes: &[u8]) -> Option<(bool, bool)> {
    let little = match bytes.get(..2)? {
        b"II" => true,
        b"MM" => false,
        _ => return None,
    };
    let u16_at = |offset: usize| -> Option<u16> {
        let b = bytes.get(offset..offset.checked_add(2)?)?;
        Some(if little {
            u16::from_le_bytes([b[0], b[1]])
        } else {
            u16::from_be_bytes([b[0], b[1]])
        })
    };
    let u32_at = |offset: usize| -> Option<u32> {
        let b = bytes.get(offset..offset.checked_add(4)?)?;
        Some(if little {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        } else {
            u32::from_be_bytes([b[0], b[1], b[2], b[3]])
        })
    };
    if u16_at(2)? != 42 {
        return None;
    }
    let mut offset = u32_at(4)? as usize;
    let mut visited = Vec::new();
    let mut gps = false;
    let mut identity = false;
    for _ in 0..4 {
        if offset == 0 {
            return Some((gps, identity));
        }
        if visited.contains(&offset) {
            return None;
        }
        visited.push(offset);
        let count = u16_at(offset)? as usize;
        if count > 512 {
            return None;
        }
        let end = offset.checked_add(2)?.checked_add(count.checked_mul(12)?)?;
        bytes.get(..end.checked_add(4)?)?;
        for index in 0..count {
            let tag = u16_at(offset + 2 + index * 12)?;
            gps |= tag == 0x8825;
            identity |= matches!(tag, 0x010f | 0x0110 | 0x0131 | 0x013b | 0x8298);
        }
        offset = u32_at(end)? as usize;
    }
    if offset == 0 {
        Some((gps, identity))
    } else {
        None
    }
}
