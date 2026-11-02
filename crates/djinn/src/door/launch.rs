// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0


//! Launching an application with a handle (capability door plan, I1).
//!
//! Linux has no code signature to read from a peer, so Djinn starts the
//! application itself and hands it a one-time [`LaunchHandle`] on descriptor
//! [`LAUNCH_FD`], which the child claims through `ostiary::launch`. The door
//! admits the label while the handle is live for that application.
//!
//! Windows needs no secret (capability door plan, D11). Djinn holds the
//! launched process's handle, so its id names no other process until Djinn
//! lets go, and the door admits the label when the pipe recorded that
//! process, by id and creation time. Its children are not the application,
//! as on Linux.

use ostiary::app_admission::LaunchHandle;
#[cfg(unix)]
use ostiary::launch::{LAUNCH_FD, LAUNCH_FD_ENV};

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
    app: &ostiary::app_admission::AppId,
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
    app: &ostiary::app_admission::AppId,
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

/// A process Djinn launched on Windows. `child` holds the process's handle,
/// which keeps its id from naming another process; drop it only after
/// [`end_process`].
#[cfg(all(feature = "door-serve", windows))]
pub struct Launched {
    pub child: std::process::Child,
    pub process: peer_facts::ProcessKey,
}

/// Start `program` with `args` as `app`, accepting the process's own
/// connections as `app` until [`end_process`] is called; a caller ends it
/// when the child exits. The process is registered just after it starts, so
/// it should connect after it has started: a connection racing its creation
/// is refused, not mistaken.
#[cfg(all(feature = "door-serve", windows))]
pub fn launch(
    grants: &crate::door::app_admission::AppRouteGrants,
    app: &ostiary::app_admission::AppId,
    program: &str,
    args: &[String],
) -> std::io::Result<Launched> {
    let mut command = std::process::Command::new(program);
    command.args(args);
    launch_command(grants, app, command)
}

/// [`launch`] for a command the caller has configured (its stdio, say).
#[cfg(all(feature = "door-serve", windows))]
pub fn launch_command(
    grants: &crate::door::app_admission::AppRouteGrants,
    app: &ostiary::app_admission::AppId,
    mut command: std::process::Command,
) -> std::io::Result<Launched> {
    use std::os::windows::io::AsRawHandle;

    let mut child = command.spawn()?;
    let process = match peer_facts::process_key(child.as_raw_handle() as _, child.id()) {
        Ok(process) => process,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    };
    grants.update(|routes| routes.begin_process(process, app.clone()));
    Ok(Launched { child, process })
}

/// Stop accepting connections from `process`: it exited.
#[cfg(feature = "door-serve")]
pub fn end_process(grants: &crate::door::app_admission::AppRouteGrants, process: &peer_facts::ProcessKey) {
    grants.update(|routes| routes.end_process(process));
}

#[cfg(all(test, feature = "door-serve", unix))]
mod tests {
    use super::*;
    use crate::door::app_admission::{AllowedAppRoutes, AppRouteGrants};
    use ostiary::app_admission::AppId;

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
    fn a_launched_child_that_claims_first_leaves_its_own_children_nothing() {
        let grants = AppRouteGrants::new(AllowedAppRoutes::none());
        // What claim does in a launched process: read the handle, then a
        // grandchild finds neither the variable nor an open descriptor 3.
        let script = format!(
            "od -An -tx1 <&{LAUNCH_FD} >/dev/null; exec {LAUNCH_FD}<&-; unset {LAUNCH_FD_ENV}; \
             sh -c 'test -z \"${LAUNCH_FD_ENV}\" && ! od -An -tx1 <&{LAUNCH_FD} 2>/dev/null && echo clean'"
        );
        let mut command = std::process::Command::new("/bin/sh");
        command.args(["-c", &script]).stdout(std::process::Stdio::piped());
        let launched = launch_command(&grants, &AppId::new("claiming-app"), command).unwrap();
        let output = launched.child.wait_with_output().unwrap();
        assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), "clean");
    }

    #[test]
    fn a_failed_launch_leaves_no_live_handle() {
        let grants = AppRouteGrants::new(AllowedAppRoutes::none());
        assert!(launch(&grants, &AppId::new("missing"), "/nonexistent/djinn-test", &[]).is_err());
        assert!(grants.current().launch_count() == 0);
    }
}

#[cfg(all(test, feature = "door-serve", windows))]
mod windows_tests {
    use super::*;
    use crate::door::app_admission::{AllowedAppRoutes, AppRouteGrants};
    use ostiary::app_admission::AppId;

    #[test]
    fn a_launched_process_is_known_by_id_and_creation_time_until_it_ends() {
        let grants = AppRouteGrants::new(AllowedAppRoutes::none());
        let mut command = std::process::Command::new("cmd.exe");
        command.args(["/c", "exit 0"]);
        let launched = launch_command(&grants, &AppId::new("launched-app"), command).unwrap();
        let Launched { mut child, process } = launched;
        assert_eq!(process.pid, child.id());
        assert!(process.created > 0);
        assert_eq!(grants.current().launch_count(), 1);
        assert!(child.wait().unwrap().success());
        end_process(&grants, &process);
        assert_eq!(grants.current().launch_count(), 0);
    }

    #[test]
    fn a_failed_launch_leaves_no_live_process() {
        let grants = AppRouteGrants::new(AllowedAppRoutes::none());
        assert!(launch(&grants, &AppId::new("missing"), r"C:\nonexistent\djinn-test.exe", &[]).is_err());
        assert_eq!(grants.current().launch_count(), 0);
    }
}
