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
    let valid = |s: &str| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || ".-_".contains(c))
    };
    if !valid(team) || !valid(identifier) {
        return false;
    }
    let text = format!(
        "anchor apple generic and identifier \"{identifier}\" and certificate leaf[subject.OU] = \"{team}\""
    );
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
            return false;
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
            return false;
        }
        let requirement = Owned(requirement);
        SecCodeCheckValidity(code.0, 0, requirement.0) == 0
    }
}
