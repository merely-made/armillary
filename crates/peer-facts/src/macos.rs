// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! macOS audit-token and code-signature observations.

use std::ffi::c_void;

type CFTypeRef = *const c_void;
type OSStatus = i32;

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    static kCFTypeDictionaryKeyCallBacks: c_void;
    static kCFTypeDictionaryValueCallBacks: c_void;
    fn CFDataCreate(allocator: CFTypeRef, bytes: *const u8, length: isize) -> CFTypeRef;
    fn CFStringCreateWithBytes(
        allocator: CFTypeRef,
        bytes: *const u8,
        length: isize,
        encoding: u32,
        external: u8,
    ) -> CFTypeRef;
    fn CFDictionaryCreate(
        allocator: CFTypeRef,
        keys: *const CFTypeRef,
        values: *const CFTypeRef,
        count: isize,
        key_callbacks: *const c_void,
        value_callbacks: *const c_void,
    ) -> CFTypeRef;
    fn CFRelease(object: CFTypeRef);
    fn CFDictionaryGetValue(dictionary: CFTypeRef, key: CFTypeRef) -> CFTypeRef;
    fn CFArrayGetCount(array: CFTypeRef) -> isize;
    fn CFArrayGetValueAtIndex(array: CFTypeRef, index: isize) -> CFTypeRef;
    fn CFDataGetLength(data: CFTypeRef) -> isize;
    fn CFDataGetBytePtr(data: CFTypeRef) -> *const u8;
}

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecGuestAttributeAudit: CFTypeRef;
    fn SecCodeCopyGuestWithAttributes(
        host: CFTypeRef,
        attributes: CFTypeRef,
        flags: u32,
        guest: *mut CFTypeRef,
    ) -> OSStatus;
    fn SecRequirementCreateWithString(
        text: CFTypeRef,
        flags: u32,
        requirement: *mut CFTypeRef,
    ) -> OSStatus;
    fn SecCodeCheckValidity(code: CFTypeRef, flags: u32, requirement: CFTypeRef) -> OSStatus;
    fn SecCodeCopySigningInformation(
        code: CFTypeRef,
        flags: u32,
        information: *mut CFTypeRef,
    ) -> OSStatus;
    static kSecCodeInfoCertificates: CFTypeRef;
    fn SecCertificateCopyData(certificate: CFTypeRef) -> CFTypeRef;
}

#[link(name = "System")]
unsafe extern "C" {
    fn CC_SHA1(data: *const c_void, length: u32, digest: *mut u8) -> *mut u8;
}

const UTF8: u32 = 0x0800_0100;

struct Owned(CFTypeRef);

impl Drop for Owned {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: a +1 reference this wrapper owns.
            unsafe { CFRelease(self.0) };
        }
    }
}

/// `LOCAL_PEERTOKEN` (6 under `SOL_LOCAL`): the peer's audit token.
pub fn audit_token(fd: std::os::fd::RawFd) -> Option<[u8; 32]> {
    let mut token = [0u8; 32];
    let mut len = token.len() as libc::socklen_t;
    // SAFETY: `token` is valid for `len` bytes.
    let rc = unsafe { libc::getsockopt(fd, 0, 6, token.as_mut_ptr().cast(), &mut len) };
    (rc == 0 && len as usize == token.len()).then_some(token)
}

pub fn satisfies(token: &[u8; 32], team: &str, identifier: &str) -> bool {
    verified_code(token, team, identifier, None).is_some()
}

pub fn signer(token: &[u8; 32], identity: &super::SignedIdentity) -> Option<String> {
    let code = verified_code(
        token,
        &identity.team,
        &identity.identifier,
        identity.certificate_sha1.as_deref(),
    )?;
    // SAFETY: Security returns a retained dictionary. Its certificate array
    // and first (leaf) certificate remain borrowed until the dictionary drops.
    unsafe {
        let mut information = std::ptr::null();
        if SecCodeCopySigningInformation(code.0, 1 << 1, &mut information) != 0
            || information.is_null()
        {
            return None;
        }
        let information = Owned(information);
        let certificates = CFDictionaryGetValue(information.0, kSecCodeInfoCertificates);
        if certificates.is_null() || CFArrayGetCount(certificates) < 1 {
            return None;
        }
        let certificate = CFArrayGetValueAtIndex(certificates, 0);
        let bytes = Owned(SecCertificateCopyData(certificate));
        if bytes.0.is_null() {
            return None;
        }
        let length = u32::try_from(CFDataGetLength(bytes.0)).ok()?;
        let mut digest = [0u8; 20];
        if CC_SHA1(
            CFDataGetBytePtr(bytes.0).cast(),
            length,
            digest.as_mut_ptr(),
        )
        .is_null()
        {
            return None;
        }
        Some(digest.iter().map(|byte| format!("{byte:02X}")).collect())
    }
}

fn requirement(team: &str, identifier: &str, certificate: Option<&str>) -> Option<String> {
    let valid = |s: &str| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || ".-_".contains(c))
    };
    if !valid(team) || !valid(identifier) {
        return None;
    }
    let mut text = format!(
        "anchor apple generic and identifier \"{identifier}\" and certificate leaf[subject.OU] = \"{team}\""
    );
    if let Some(certificate) = certificate {
        if certificate.len() != 40 || !certificate.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        text.push_str(&format!(
            " and certificate leaf = H\"{}\"",
            certificate.to_ascii_uppercase()
        ));
    }
    Some(text)
}

fn verified_code(
    token: &[u8; 32],
    team: &str,
    identifier: &str,
    certificate: Option<&str>,
) -> Option<Owned> {
    let text = requirement(team, identifier, certificate)?;
    // SAFETY: every CF object is created here, owned by `Owned` and
    // released on every path; the requirement text is validated ASCII.
    unsafe {
        let data = Owned(CFDataCreate(
            std::ptr::null(),
            token.as_ptr(),
            token.len() as isize,
        ));
        let key = kSecGuestAttributeAudit;
        let attributes = Owned(CFDictionaryCreate(
            std::ptr::null(),
            &key,
            &data.0,
            1,
            &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks,
        ));
        let mut code: CFTypeRef = std::ptr::null();
        if SecCodeCopyGuestWithAttributes(std::ptr::null(), attributes.0, 0, &mut code) != 0 {
            return None;
        }
        let code = Owned(code);
        let string = Owned(CFStringCreateWithBytes(
            std::ptr::null(),
            text.as_ptr(),
            text.len() as isize,
            UTF8,
            0,
        ));
        let mut requirement: CFTypeRef = std::ptr::null();
        if SecRequirementCreateWithString(string.0, 0, &mut requirement) != 0 {
            return None;
        }
        let requirement = Owned(requirement);
        (SecCodeCheckValidity(code.0, 0, requirement.0) == 0).then_some(code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_leaf_pin_is_exact_and_cannot_inject_a_requirement() {
        let text = requirement("TEAM", "com.merely.djinn", Some(&"ab".repeat(20))).unwrap();
        assert!(text.ends_with(&format!("certificate leaf = H\"{}\"", "AB".repeat(20))));
        for invalid in [
            "",
            "abc",
            "x000000000000000000000000000000000000000",
            "\" or anchor apple",
        ] {
            assert!(requirement("TEAM", "com.merely.djinn", Some(invalid)).is_none());
        }
        assert!(requirement("T\"", "com.merely.djinn", None).is_none());
    }
}
