// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Admission for first-party native applications.
//!
//! The resident host already serves browsers, over an endpoint whose first
//! gate is an extension-id allowlist. A first-party application is a
//! different kind of caller and gets a **different endpoint**, rather than a
//! seat in that allowlist: the browser gate's whole job is to be narrow, and
//! widening it to admit a native app would weaken the one check keeping
//! arbitrary extensions out.
//!
//! **What this gate does and does not decide.** It is the first of two, the
//! same shape the browser path has: this says *a local first-party app of a
//! known name is talking*, the host-owned route table grants a local route,
//! and the ordinary session admission behind both still decides what that app
//! may see. The self-declared hello grants nothing by itself.
//!
//! **What actually proves "first-party" is the endpoint's own permissions.**
//! The socket lives in the user's runtime directory and the named pipe is
//! created for the current user, so reaching it at all means running as the
//! owner. The app id below is a *label*, not a credential: it tells the host
//! and the operator which application is connected, and lets an owner turn
//! one off. Treating a self-declared name as proof would be theatre, and it
//! is not treated as such.

use serde::{Deserialize, Serialize};

use crate::declaration::{AppDeclaration, DeclarationError};

/// Environment override for the first-party application endpoint.
pub const APP_ENDPOINT_ENV: &str = "GRAPHSHELL_APP_ENDPOINT";

/// The hello schema a first-party application opens with.
///
/// Distinct from the browser broker's, so a client that reaches the wrong
/// endpoint is refused with a clear reason rather than half-speaking the
/// other protocol.
pub const APP_HELLO_SCHEMA: &str = "mere.graphshell/app-broker-hello/v1";

/// Route-aware hello schema. Version one remains the installed-client
/// identity default; version two names one host-configured resident route.
pub const APP_ROUTE_HELLO_SCHEMA: &str = "mere.graphshell/app-broker-hello/v2";

/// The route selected by the version-one hello.
pub const APP_IDENTITY_ROUTE: &str = "identity";

#[cfg(all(windows, feature = "native"))]
const DEFAULT_WINDOWS_APP_ENDPOINT: &str = r"\\.\pipe\graphshell-device-app";

/// Which application is connecting.
///
/// A plain name rather than a signed identity: see the module note on why
/// this is a label. Lowercased on construction so `Turnstone` and `turnstone`
/// are one application rather than two, one of which is silently not allowed.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AppId(String);

impl AppId {
    /// Name an application.
    pub fn new(id: impl AsRef<str>) -> Self {
        Self(id.as_ref().trim().to_ascii_lowercase())
    }

    /// The name as matched.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One host-local resident route key.
///
/// This is a routing label, not authority. Authority comes from the
/// host-owned grant (Djinn's `AllowedAppRoutes`) selected after the
/// owner-only door is reached.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AppRouteId(String);

impl AppRouteId {
    /// Validate and name a host-local resident route.
    pub fn new(id: impl Into<String>) -> Result<Self, AppAdmissionError> {
        let id = id.into();
        if id.is_empty() || id.chars().any(char::is_whitespace) {
            return Err(AppAdmissionError::InvalidRoute(id));
        }
        Ok(Self(id))
    }

    /// The route selected by an installed version-one client.
    pub fn identity() -> Self {
        Self(APP_IDENTITY_ROUTE.to_string())
    }

    /// The exact host-local routing key.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for AppRouteId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::fmt::Display for AppId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Why a first-party connection was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AppAdmissionError {
    /// The hello was not this endpoint's protocol.
    WrongSchema(String),
    /// The application is not one this device admits.
    NotAllowed(AppId),
    /// The application is known, but this route is not in its host grant.
    RouteNotGranted { app: AppId, route: AppRouteId },
    /// An explicit owner denial takes precedence over every route grant.
    RouteDenied { app: AppId, route: AppRouteId },
    /// The hello named no application.
    Unnamed,
    /// The route key was empty or ambiguous.
    InvalidRoute(String),
    /// A version-one hello attempted to smuggle a route selection.
    RouteOnLegacyHello,
    /// A version-one hello carried a declaration.
    DeclarationOnLegacyHello,
    /// The declaration was malformed.
    InvalidDeclaration(DeclarationError),
    /// The owner grants this application by declaration, and its hello
    /// declared nothing.
    DeclarationRequired(AppId),
    /// The application's declaration does not name this route.
    RouteUndeclared { app: AppId, route: AppRouteId },
    /// The owner pinned this label to an OS identity the peer does not have.
    IdentityMismatch { app: AppId, expected: String },
    /// The hello's launch handle was malformed.
    InvalidLaunch,
}

impl std::fmt::Display for AppAdmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongSchema(found) => write!(
                f,
                "expected the first-party hello {APP_HELLO_SCHEMA} or \
                 {APP_ROUTE_HELLO_SCHEMA}, got {found}; \
                 a browser belongs on the browser endpoint"
            ),
            Self::NotAllowed(app) => {
                write!(f, "{app} is not an application this device admits")
            }
            Self::RouteNotGranted { app, route } => {
                write!(f, "{app} is not granted the resident route {route}")
            }
            Self::RouteDenied { app, route } => {
                write!(f, "{app} is explicitly denied the resident route {route}")
            }
            Self::Unnamed => f.write_str("the first-party hello named no application"),
            Self::InvalidRoute(route) => write!(
                f,
                "the first-party hello named an invalid resident route {route:?}"
            ),
            Self::RouteOnLegacyHello => {
                f.write_str("the version-one first-party hello cannot select a resident route")
            }
            Self::DeclarationOnLegacyHello => {
                f.write_str("the version-one first-party hello cannot carry a declaration")
            }
            Self::InvalidDeclaration(error) => write!(f, "the hello's declaration is invalid: {error}"),
            Self::DeclarationRequired(app) => {
                write!(f, "{app} is admitted by its declaration, and its hello declared nothing")
            }
            Self::RouteUndeclared { app, route } => {
                write!(f, "{app} did not declare the resident route {route}")
            }
            Self::IdentityMismatch { app, expected } => {
                write!(f, "the peer is not {app}: the owner pinned it to {expected}")
            }
            Self::InvalidLaunch => f.write_str("the hello's launch handle is malformed"),
        }
    }
}

impl std::error::Error for AppAdmissionError {}

/// First message on a first-party application connection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppHello {
    /// Always [`APP_HELLO_SCHEMA`].
    pub schema: String,
    /// Which application is speaking.
    pub app: AppId,
    /// Version two's requested resident route. Absent on the installed
    /// version-one hello, which always means [`APP_IDENTITY_ROUTE`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<AppRouteId>,
    /// What the application states it opens, offers and needs. Version two
    /// only; absent keeps the hello byte-shaped for clients that predate it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declaration: Option<AppDeclaration>,
    /// The handle Djinn launched this process with, as 64 hex digits.
    /// Version two only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launch: Option<String>,
}

impl AppHello {
    /// Open a connection as `app`.
    pub fn new(app: AppId) -> Self {
        Self {
            schema: APP_HELLO_SCHEMA.to_string(),
            app,
            route: None,
            declaration: None,
            launch: None,
        }
    }

    /// Open a route-aware connection as `app`.
    pub fn for_route(app: AppId, route: AppRouteId) -> Self {
        Self {
            schema: APP_ROUTE_HELLO_SCHEMA.to_string(),
            app,
            route: Some(route),
            declaration: None,
            launch: None,
        }
    }

    /// Carry the handle Djinn launched this process with.
    pub fn launched(mut self, handle: LaunchHandle) -> Self {
        self.launch = Some(handle.to_hex());
        self
    }

    /// Carry `declaration` on a route-aware hello.
    pub fn declaring(mut self, declaration: AppDeclaration) -> Self {
        self.declaration = Some(declaration);
        self
    }

    /// Check the protocol and yield the application and route requested.
    pub fn accept(self) -> Result<AppRequest, AppAdmissionError> {
        // Transparent serde can bypass `AppId::new`; normalize the wire value
        // so case and surrounding spaces cannot create a second identity.
        let app = AppId::new(self.app.as_str());
        if app.as_str().is_empty() {
            return Err(AppAdmissionError::Unnamed);
        }
        let route = match self.schema.as_str() {
            APP_HELLO_SCHEMA => {
                if self.route.is_some() {
                    return Err(AppAdmissionError::RouteOnLegacyHello);
                }
                if self.declaration.is_some() || self.launch.is_some() {
                    return Err(AppAdmissionError::DeclarationOnLegacyHello);
                }
                AppRouteId::identity()
            }
            APP_ROUTE_HELLO_SCHEMA => self
                .route
                .ok_or_else(|| AppAdmissionError::InvalidRoute(String::new()))?,
            _ => return Err(AppAdmissionError::WrongSchema(self.schema)),
        };
        // Transparent serde can construct the type without calling `new`, so
        // validate the wire value again at admission.
        let route = AppRouteId::new(route.0)?;
        if let Some(declaration) = &self.declaration {
            declaration
                .validate()
                .map_err(AppAdmissionError::InvalidDeclaration)?;
        }
        let launch = self
            .launch
            .as_deref()
            .map(|hex| LaunchHandle::from_hex(hex).ok_or(AppAdmissionError::InvalidLaunch))
            .transpose()?;
        Ok(AppRequest {
            app,
            route,
            declaration: self.declaration,
            launch,
        })
    }
}

/// The host-relevant facts from one accepted hello.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppRequest {
    pub app: AppId,
    pub route: AppRouteId,
    /// The application's declaration, when its hello carried one.
    pub declaration: Option<AppDeclaration>,
    /// The handle Djinn launched the process with, when its hello carried one.
    pub launch: Option<LaunchHandle>,
}

impl AppRequest {
    /// A request without a declaration, as a host rechecking policy or a
    /// client that predates declarations names one.
    pub fn new(app: AppId, route: AppRouteId) -> Self {
        Self {
            app,
            route,
            declaration: None,
            launch: None,
        }
    }
}

/// A one-time secret Djinn hands a process it launches, by a pipe the child
/// reads once. A connection carrying it is the launched process (or one it
/// shared the secret with): within the same-user boundary, the Linux basis
/// for an application's label.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LaunchHandle([u8; 32]);

impl LaunchHandle {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        self.0.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    pub fn from_hex(hex: &str) -> Option<Self> {
        if hex.len() != 64 || !hex.is_ascii() {
            return None;
        }
        let mut bytes = [0u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).ok()?;
        }
        Some(Self(bytes))
    }
}

impl std::fmt::Debug for LaunchHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LaunchHandle(..)")
    }
}


/// The per-user endpoint first-party applications connect to.
#[cfg(all(
    feature = "native",
    any(unix, windows),
    not(target_arch = "wasm32")
))]
pub fn configured_app_endpoint() -> String {
    std::env::var(APP_ENDPOINT_ENV)
        .ok()
        .filter(|endpoint| !endpoint.trim().is_empty())
        .unwrap_or_else(default_app_endpoint)
}

/// The platform default, ignoring the environment override. Only the device
/// resident (installed or embedded) may bind it.
#[cfg(all(
    feature = "native",
    any(unix, windows),
    not(target_arch = "wasm32")
))]
pub fn default_app_endpoint() -> String {
    #[cfg(windows)]
    {
        DEFAULT_WINDOWS_APP_ENDPOINT.to_string()
    }
    #[cfg(not(windows))]
    {
        unix_app_endpoint(
            std::env::var_os("XDG_RUNTIME_DIR"),
            std::env::var_os("XDG_DATA_HOME"),
            std::env::var_os("HOME"),
        )
        .display()
        .to_string()
    }
}

/// The Unix socket path from the runtime directory, `XDG_DATA_HOME` and
/// `HOME`. The runtime directory, so reaching the socket means being the
/// owner. Without one (macOS never sets it) the socket goes in personae's
/// vault directory, at the same user-only permissions; that derivation is
/// copied from `personae::default_vault_dir` so the contract needs no
/// Dramatis crate (djinn-slimming D8), and a test pins it.
#[cfg(any(all(unix, feature = "native", not(target_arch = "wasm32")), test))]
fn unix_app_endpoint(
    runtime: Option<std::ffi::OsString>,
    data_home: Option<std::ffi::OsString>,
    home: Option<std::ffi::OsString>,
) -> std::path::PathBuf {
    use std::path::PathBuf;
    runtime
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            data_home
                .map(PathBuf::from)
                .or_else(|| home.map(|home| PathBuf::from(home).join(".local/share")))
                .unwrap_or_else(|| PathBuf::from("."))
                .join("personae")
                .join("vault")
        })
        .join("graphshell-app.sock")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::declaration::AppGrant;

    /// A browser reaching this endpoint is refused with a reason that says
    /// where it should have gone, rather than failing deeper in as a
    /// malformed frame.
    #[test]
    fn the_browser_hello_is_refused_by_schema() {
        let wrong = AppHello {
            schema: "mere.graphshell/device-broker-hello/v1".to_string(),
            app: AppId::new("turnstone"),
            route: None,
            declaration: None,
            launch: None,
        };
        let error = wrong.accept().unwrap_err();
        assert!(matches!(error, AppAdmissionError::WrongSchema(_)));
        assert!(
            error.to_string().contains("browser endpoint"),
            "the refusal points at the right endpoint, got: {error}",
        );
    }

    #[test]
    fn a_hello_naming_nothing_is_refused() {
        let unnamed = AppHello::new(AppId::new("   "));
        assert_eq!(unnamed.accept().unwrap_err(), AppAdmissionError::Unnamed);
    }

    #[test]
    fn a_well_formed_hello_yields_its_application() {
        let hello = AppHello::new(AppId::new("turnstone"));
        assert_eq!(
            hello.clone().accept().unwrap(),
            AppRequest::new(AppId::new("turnstone"), AppRouteId::identity())
        );
        let json = serde_json::to_string(&hello).unwrap();
        assert!(
            !json.contains("route"),
            "the legacy hello stays byte-shaped"
        );
        assert_eq!(serde_json::from_str::<AppHello>(&json).unwrap(), hello);
    }

    #[test]
    fn a_legacy_hello_cannot_smuggle_a_route() {
        let hello = AppHello {
            schema: APP_HELLO_SCHEMA.to_string(),
            app: AppId::new("turnstone"),
            route: Some(AppRouteId::new("knot").unwrap()),
            declaration: None,
            launch: None,
        };
        assert_eq!(
            hello.accept().unwrap_err(),
            AppAdmissionError::RouteOnLegacyHello
        );
    }

    // That this endpoint differs from the browser door's is checked beside
    // the browser door, in Graphshell's `native::device_broker`.
    #[cfg(all(
        feature = "native",
        any(unix, windows),
        not(target_arch = "wasm32")
    ))]
    #[test]
    fn the_default_endpoint_is_named() {
        assert!(!default_app_endpoint().is_empty());
    }

    fn knotlike() -> (AppDeclaration, AppGrant) {
        use crate::declaration::NamePattern;
        let declaration = AppDeclaration {
            routes: vec![NamePattern::exact("custody"), NamePattern::prefix("mere/")],
            ..AppDeclaration::default()
        };
        let mut grant = AppGrant::new(AppId::new("knotlike"));
        grant.routes = vec![NamePattern::exact("custody"), NamePattern::prefix("mere/")];
        (declaration, grant)
    }

    #[test]
    fn a_declaration_rides_only_the_route_hello() {
        let (declaration, _) = knotlike();
        let mut legacy = AppHello::new(AppId::new("knotlike"));
        legacy.declaration = Some(declaration.clone());
        assert_eq!(legacy.accept().unwrap_err(), AppAdmissionError::DeclarationOnLegacyHello);
        let hello = AppHello::for_route(AppId::new("knotlike"), AppRouteId::new("custody").unwrap())
            .declaring(declaration);
        let json = serde_json::to_string(&hello).unwrap();
        assert_eq!(serde_json::from_str::<AppHello>(&json).unwrap(), hello);
        let undeclared = AppHello::for_route(AppId::new("knotlike"), AppRouteId::new("custody").unwrap());
        assert!(!serde_json::to_string(&undeclared).unwrap().contains("declaration"));
    }

    #[test]
    fn a_windows_image_matches_without_case_or_separator_style() {
        let pin = crate::declaration::WindowsAppIdentity { image: r"C:\Program Files\Knot\knot.exe".into() };
        assert!(pin.matches(r"c:\program files\knot\KNOT.EXE"));
        assert!(pin.matches("C:/Program Files/Knot/knot.exe"));
        assert!(!pin.matches(r"C:\Program Files\Knot\knot-helper.exe"));
    }

    #[test]
    fn a_launch_handle_rides_only_the_route_hello_as_hex() {
        let handle = LaunchHandle::from_bytes([0xab; 32]);
        let hello = AppHello::for_route(AppId::new("knotlike"), AppRouteId::new("custody").unwrap()).launched(handle);
        assert_eq!(hello.clone().accept().unwrap().launch, Some(handle));
        assert!(!format!("{handle:?}").contains("ab"), "a handle never prints");
        let mut bad = hello.clone();
        bad.launch = Some("zz".into());
        assert_eq!(bad.accept().unwrap_err(), AppAdmissionError::InvalidLaunch);
        let mut legacy = AppHello::new(AppId::new("knotlike"));
        legacy.launch = Some(handle.to_hex());
        assert_eq!(legacy.accept().unwrap_err(), AppAdmissionError::DeclarationOnLegacyHello);
        assert_eq!(LaunchHandle::from_hex(&handle.to_hex()), Some(handle));
    }

    #[test]
    fn the_socket_path_is_pinned() {
        use std::path::Path;
        let path = |runtime: Option<&str>, data: Option<&str>, home: Option<&str>| {
            unix_app_endpoint(runtime.map(Into::into), data.map(Into::into), home.map(Into::into))
        };
        assert_eq!(path(Some("/run/user/501"), Some("/d"), Some("/h")), Path::new("/run/user/501/graphshell-app.sock"));
        assert_eq!(
            path(None, None, Some("/Users/k")),
            Path::new("/Users/k/.local/share/personae/vault/graphshell-app.sock"),
            "macOS sets no XDG directories"
        );
        assert_eq!(path(None, Some("/d"), Some("/h")), Path::new("/d/personae/vault/graphshell-app.sock"));
        assert_eq!(path(None, None, None), Path::new("./personae/vault/graphshell-app.sock"));
    }
}
