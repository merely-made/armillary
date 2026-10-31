// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Launching an application with a handle (capability door plan, I1).
//!
//! Linux has no code signature to read from a peer, so Djinn starts the
//! application itself and hands it a one-time [`LaunchHandle`] on descriptor
//! [`LAUNCH_FD`], named by [`LAUNCH_FD_ENV`]. The child's door client reads
//! it once and carries it on every route hello; the door admits the label
//! when the handle is live for that application. It is a secret within the
//! same-user boundary, like the endpoint itself: it shows a connection came
//! from the launched process or one it shared the handle with, not more.

use crate::door::app_admission::LaunchHandle;

/// The environment variable naming the descriptor the handle arrives on.
pub const LAUNCH_FD_ENV: &str = "DJINN_LAUNCH_FD";
/// The descriptor Djinn places the handle on in a process it launches.
pub const LAUNCH_FD: i32 = 3;

/// The handle this process was launched with, read once from the descriptor
/// [`LAUNCH_FD_ENV`] names. `None` for a process Djinn did not launch.
#[cfg(unix)]
pub fn inherited() -> Option<LaunchHandle> {
    static HANDLE: std::sync::OnceLock<Option<LaunchHandle>> = std::sync::OnceLock::new();
    *HANDLE.get_or_init(|| {
        use std::io::Read;
        use std::os::fd::FromRawFd;
        let fd: i32 = std::env::var(LAUNCH_FD_ENV).ok()?.parse().ok()?;
        if fd < 0 {
            return None;
        }
        // SAFETY: the launcher placed a pipe's read end at `fd` for this
        // process to read once; taking ownership closes it after the read.
        let mut pipe = unsafe { std::fs::File::from_raw_fd(fd) };
        let mut bytes = [0u8; 32];
        pipe.read_exact(&mut bytes).ok()?;
        Some(LaunchHandle::from_bytes(bytes))
    })
}

/// The handle this process was launched with; never on this platform.
#[cfg(not(unix))]
pub fn inherited() -> Option<LaunchHandle> {
    None
}

/// A process Djinn launched, with the handle its connections carry.
#[cfg(all(feature = "door-serve", unix))]
pub struct Launched {
    pub child: std::process::Child,
    pub handle: LaunchHandle,
}

/// Start `program` with `args` as `app`, registering a fresh handle in
/// `grants` before it runs. The handle stays live until [`end`] is called;
/// a caller ends it when the child exits.
#[cfg(all(feature = "door-serve", unix))]
pub fn launch(
    grants: &crate::door::app_admission::AppRouteGrants,
    app: &crate::door::app_admission::AppId,
    program: &str,
    args: &[String],
) -> std::io::Result<Launched> {
    let mut command = std::process::Command::new(program);
    command.args(args);
    launch_command(grants, app, command)
}

/// [`launch`] for a command the caller has configured (its stdio, say).
#[cfg(all(feature = "door-serve", unix))]
pub fn launch_command(
    grants: &crate::door::app_admission::AppRouteGrants,
    app: &crate::door::app_admission::AppId,
    mut command: std::process::Command,
) -> std::io::Result<Launched> {
    use std::io::Write;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::process::CommandExt;

    let mut bytes = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut bytes);
    let handle = LaunchHandle::from_bytes(bytes);

    let mut fds = [0i32; 2];
    // SAFETY: `fds` is valid for two descriptors.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: both descriptors were just created and are owned here.
    let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    // The handle fits a pipe buffer, so writing before the child runs cannot block.
    std::fs::File::from(write).write_all(handle.as_bytes())?;

    grants.update(|routes| routes.begin_launch(handle, app.clone()));
    let read_fd = read.as_raw_fd();
    command.env(LAUNCH_FD_ENV, LAUNCH_FD.to_string());
    // SAFETY: only async-signal-safe calls (dup2) run between fork and exec.
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(read_fd, LAUNCH_FD) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    match command.spawn() {
        Ok(child) => {
            drop(read);
            Ok(Launched { child, handle })
        }
        Err(error) => {
            grants.update(|routes| routes.end_launch(&handle));
            Err(error)
        }
    }
}

/// Stop accepting `handle`: its process exited.
#[cfg(feature = "door-serve")]
pub fn end(grants: &crate::door::app_admission::AppRouteGrants, handle: &LaunchHandle) {
    grants.update(|routes| routes.end_launch(handle));
}

#[cfg(all(test, feature = "door-serve", unix))]
mod tests {
    use super::*;
    use crate::door::app_admission::{AllowedAppRoutes, AppId, AppRouteGrants};

    #[test]
    fn a_launched_process_reads_its_handle_once_from_the_named_descriptor() {
        let grants = AppRouteGrants::new(AllowedAppRoutes::none());
        let app = AppId::new("launched-app");
        let script = format!("test \"${LAUNCH_FD_ENV}\" = {LAUNCH_FD} && od -An -tx1 <&{LAUNCH_FD} | tr -d ' \\n'");
        let mut command = std::process::Command::new("/bin/sh");
        command.args(["-c", &script]).stdout(std::process::Stdio::piped());
        let launched = launch_command(&grants, &app, command).unwrap();
        let handle = launched.handle;
        let output = launched.child.wait_with_output().unwrap();
        assert!(output.status.success());
        assert_eq!(String::from_utf8(output.stdout).unwrap(), handle.to_hex());
        assert!(grants.current().identify_launch(&handle) == Some(&app));
        end(&grants, &handle);
        assert!(grants.current().identify_launch(&handle).is_none());
    }

    #[test]
    fn a_failed_launch_leaves_no_live_handle() {
        let grants = AppRouteGrants::new(AllowedAppRoutes::none());
        assert!(launch(&grants, &AppId::new("missing"), "/nonexistent/djinn-test", &[]).is_err());
        assert!(grants.current().launch_count() == 0);
    }
}
