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

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::door::declaration::{AppAuthority, AppDeclaration, AppGrant, DeclarationError, IdentityBasis};
use crate::door::route::ResidentEndpointRoute;

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

/// Default notice cadence for the legacy identity grant. The cadence is
/// ignored by that route, while callers granting catalog routes supply their
/// own value through [`ResidentEndpointRoute`].
const DEFAULT_IDENTITY_NOTICE_POLL: Duration = Duration::from_millis(50);

#[cfg(windows)]
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
/// host-owned [`AllowedAppRoutes`] entry selected after the owner-only door is
/// reached.
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

/// The applications this device serves.
///
/// Default-deny with a named default set, the same posture as the browser
/// allowlist: an application the owner has not heard of does not get a
/// session by knowing the endpoint's name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllowedAppRoutes {
    routes: BTreeMap<AppId, BTreeMap<AppRouteId, ResidentEndpointRoute>>,
    defaults: BTreeMap<AppRouteId, ResidentEndpointRoute>,
    denied: BTreeSet<(AppId, AppRouteId)>,
    /// Owner grants for applications admitted by their declarations.
    grants: BTreeMap<AppId, AppGrant>,
    /// Routes the host serves to declared applications whose grant names them.
    served: BTreeMap<AppRouteId, ResidentEndpointRoute>,
    /// Live launch handles, each naming the application Djinn launched with it.
    launches: BTreeMap<LaunchHandle, AppId>,
}

impl Default for AllowedAppRoutes {
    fn default() -> Self {
        Self::new([(
            AppId::new("turnstone"),
            ResidentEndpointRoute::new(APP_IDENTITY_ROUTE, DEFAULT_IDENTITY_NOTICE_POLL)
                .expect("the identity route is valid"),
        )])
    }
}

impl AllowedAppRoutes {
    /// Admit exactly these application-to-route pairs. Repeating an
    /// application grants it more than one route.
    pub fn new(grants: impl IntoIterator<Item = (AppId, ResidentEndpointRoute)>) -> Self {
        let mut allowed = Self::none();
        for (app, route) in grants {
            allowed.grant(app, route);
        }
        allowed
    }

    /// Grant `app` one more route, replacing a grant of the same id.
    pub fn grant(&mut self, app: AppId, route: ResidentEndpointRoute) {
        let id = AppRouteId::new(route.id())
            .expect("ResidentEndpointRoute has already validated its id");
        self.routes.entry(app).or_default().insert(id, route);
    }

    /// Admit none. A device that wants no first-party clients says so rather
    /// than leaving the endpoint unserved and looking broken.
    pub fn none() -> Self {
        Self {
            routes: BTreeMap::new(),
            defaults: BTreeMap::new(),
            denied: BTreeSet::new(),
            grants: BTreeMap::new(),
            served: BTreeMap::new(),
            launches: BTreeMap::new(),
        }
    }

    /// Select the host-configured route granted to this request.
    ///
    /// A request carrying a declaration is admitted only to a route it
    /// declares and the policy permits. An application the owner grants by
    /// declaration must declare; one without such a grant is admitted by its
    /// label's route table, as before declarations.
    pub fn admit(&self, request: &AppRequest) -> Result<ResidentEndpointRoute, AppAdmissionError> {
        match &request.declaration {
            Some(declaration) => {
                if !self.grants.contains_key(&request.app) && !self.routes.contains_key(&request.app) {
                    return Err(AppAdmissionError::NotAllowed(request.app.clone()));
                }
                if !declaration.declares_route(&request.route) {
                    return Err(AppAdmissionError::RouteUndeclared {
                        app: request.app.clone(),
                        route: request.route.clone(),
                    });
                }
            }
            None if self.grants.contains_key(&request.app) => {
                return Err(AppAdmissionError::DeclarationRequired(request.app.clone()));
            }
            None => {}
        }
        self.permits(&request.app, &request.route)
    }

    /// Whether owner policy, as it stands, lets `app` open `route`: a route
    /// granted to its label, a default, or a served route its owner grant
    /// names. Denials win. This does not consult a declaration; a host
    /// rechecking a session admitted earlier uses it.
    pub fn permits(
        &self,
        app: &AppId,
        route: &AppRouteId,
    ) -> Result<ResidentEndpointRoute, AppAdmissionError> {
        let routes = self.routes.get(app);
        let grant = self.grants.get(app);
        if routes.is_none() && grant.is_none() {
            return Err(AppAdmissionError::NotAllowed(app.clone()));
        }
        if self.denied.contains(&(app.clone(), route.clone())) {
            return Err(AppAdmissionError::RouteDenied {
                app: app.clone(),
                route: route.clone(),
            });
        }
        let not_granted = || AppAdmissionError::RouteNotGranted {
            app: app.clone(),
            route: route.clone(),
        };
        if let Some(selected) = routes.and_then(|routes| routes.get(route)) {
            return Ok(selected.clone());
        }
        match grant {
            Some(grant) if grant.grants_route(route) => self
                .served
                .get(route)
                .or_else(|| self.defaults.get(route))
                .cloned()
                .ok_or_else(not_granted),
            Some(_) => Err(not_granted()),
            None => self.defaults.get(route).cloned().ok_or_else(not_granted),
        }
    }

    /// The authority of an admitted declared request: its declaration and
    /// its owner grant. `None` for a request admitted by label alone.
    pub fn authority(&self, request: &AppRequest) -> Option<AppAuthority> {
        let declaration = request.declaration.clone()?;
        let grant = self.grants.get(&request.app)?.clone();
        Some(AppAuthority::new(declaration, grant))
    }

    /// Admit `grant.app` by its declaration, within this grant, replacing
    /// any earlier grant for it.
    pub fn grant_app(&mut self, grant: AppGrant) {
        self.grants.insert(grant.app.clone(), grant);
    }

    /// Accept `handle` as `app`'s launch, until [`Self::end_launch`].
    pub fn begin_launch(&mut self, handle: LaunchHandle, app: AppId) {
        self.launches.insert(handle, app);
    }

    /// Stop accepting `handle`: its process exited.
    pub fn end_launch(&mut self, handle: &LaunchHandle) {
        self.launches.remove(handle);
    }

    /// The application a live launch handle names.
    pub fn identify_launch(&self, handle: &LaunchHandle) -> Option<&AppId> {
        self.launches.get(handle)
    }

    /// How many launch handles are live.
    pub fn launch_count(&self) -> usize {
        self.launches.len()
    }

    /// What `request`'s label rests on, given what the OS said about the
    /// peer. Where the owner pinned an identity for this platform, a peer
    /// without it is refused; elsewhere the label stands as development mode.
    #[cfg(feature = "door-serve")]
    pub fn identify(
        &self,
        request: &AppRequest,
        connected: Option<&peer_facts::Connected>,
    ) -> Result<IdentityBasis, AppAdmissionError> {
        let Some(pinned) = self.grants.get(&request.app).and_then(|grant| grant.identity.as_ref()) else {
            return Ok(IdentityBasis::Development);
        };
        let mismatch = |expected: String| AppAdmissionError::IdentityMismatch {
            app: request.app.clone(),
            expected,
        };
        if cfg!(target_os = "macos") {
            if let Some(signed) = &pinned.macos {
                return match connected.is_some_and(|c| c.signed_as(&signed.team, &signed.identifier)) {
                    true => Ok(IdentityBasis::Signed {
                        team: signed.team.clone(),
                        identifier: signed.identifier.clone(),
                    }),
                    false => Err(mismatch(format!("code signed by {} as {}", signed.team, signed.identifier))),
                };
            }
        }
        if cfg!(windows) {
            if let Some(windows) = &pinned.windows {
                let image = connected.and_then(|c| match &c.peer {
                    peer_facts::Peer::Windows { image, .. } => image.clone(),
                    _ => None,
                });
                return match image.filter(|image| windows.matches(image)) {
                    Some(image) => Ok(IdentityBasis::WindowsImage { image }),
                    None => Err(mismatch(format!("the executable {}", windows.image))),
                };
            }
        }
        if cfg!(target_os = "linux") {
            if pinned.linux.is_some() {
                let launched = request
                    .launch
                    .as_ref()
                    .and_then(|handle| self.launches.get(handle));
                return match launched == Some(&request.app) {
                    true => Ok(IdentityBasis::Launched),
                    false => Err(mismatch("a process Djinn launched".into())),
                };
            }
        }
        Ok(IdentityBasis::Development)
    }

    /// The owner grant for a declared application.
    pub fn app_grant(&self, app: &AppId) -> Option<&AppGrant> {
        self.grants.get(app)
    }

    /// Serve `route` to declared applications whose grant names it.
    pub fn serve(&mut self, route: ResidentEndpointRoute) {
        self.served
            .insert(AppRouteId::new(route.id()).expect("valid route"), route);
    }

    /// Make one route available to every application the owner already
    /// admits. This never turns an unknown app label into an admitted app.
    pub fn grant_default(&mut self, route: ResidentEndpointRoute) {
        self.defaults
            .insert(AppRouteId::new(route.id()).expect("valid route"), route);
    }

    /// Whether the owner has admitted this application independently of
    /// route defaults and recorded denials.
    pub fn is_admitted(&self, app: &AppId) -> bool {
        self.routes.contains_key(app) || self.grants.contains_key(app)
    }

    /// Set or clear an owner denial without altering route grants.
    pub fn set_denied(&mut self, app: AppId, route: AppRouteId, denied: bool) {
        if denied {
            self.denied.insert((app, route));
        } else {
            self.denied.remove(&(app, route));
        }
    }

    /// Remove the route grant without removing the application's admission.
    pub fn revoke(&mut self, app: &AppId, route: &AppRouteId) {
        if let Some(routes) = self.routes.get_mut(app) {
            routes.remove(route);
        }
    }

    /// The application and route pairs admitted, for reporting.
    pub fn iter(&self) -> impl Iterator<Item = (&AppId, &AppRouteId)> {
        let declared = self.grants.iter().flat_map(move |(app, grant)| {
            self.served
                .keys()
                .chain(self.defaults.keys().filter(move |route| !self.served.contains_key(*route)))
                .filter(move |route| grant.grants_route(route))
                // A label-admitted app's routes and defaults are listed below.
                .filter(move |route| {
                    !self.routes.get(app).is_some_and(|routes| {
                        routes.contains_key(*route) || self.defaults.contains_key(*route)
                    })
                })
                .filter(move |route| !self.denied.contains(&(app.clone(), (*route).clone())))
                .map(move |route| (app, route))
        });
        self.routes.iter().flat_map(move |(app, routes)| {
            routes
                .keys()
                .chain(
                    self.defaults
                        .keys()
                        .filter(move |route| !routes.contains_key(*route)),
                )
                .filter(move |route| !self.denied.contains(&(app.clone(), (*route).clone())))
                .map(move |route| (app, route))
        })
        .chain(declared)
    }
}

/// The routes a door admits, shared with its host so the host can grant more
/// while the door serves: a mere ensured after the door opened gets its route
/// then (reservoir plan §7 item 20). Each connection is admitted against the
/// grants as they stand when its hello arrives.
#[derive(Clone, Debug, Default)]
pub struct AppRouteGrants {
    routes: Arc<RwLock<AllowedAppRoutes>>,
}

impl AppRouteGrants {
    pub fn new(routes: AllowedAppRoutes) -> Self {
        Self {
            routes: Arc::new(RwLock::new(routes)),
        }
    }

    /// Grant `app` one more route, for connections from now on.
    pub fn grant(&self, app: AppId, route: ResidentEndpointRoute) {
        self.routes
            .write()
            .expect("app grants are never poisoned")
            .grant(app, route);
    }

    /// The grants as they stand.
    pub fn current(&self) -> AllowedAppRoutes {
        self.routes
            .read()
            .expect("app grants are never poisoned")
            .clone()
    }

    /// Publish an atomic policy update; a connection sees either side.
    pub fn update(&self, change: impl FnOnce(&mut AllowedAppRoutes)) {
        change(&mut self.routes.write().expect("app grants are never poisoned"));
    }

    /// Make a route available to all already admitted applications.
    pub fn grant_default(&self, route: ResidentEndpointRoute) {
        self.update(|routes| routes.grant_default(route));
    }
}

/// The per-user endpoint first-party applications connect to.
#[cfg(all(
    feature = "door-native",
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
    feature = "door-native",
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
        // The runtime directory, so reaching the socket means being the owner.
        // Falling back to the vault directory keeps a session possible on a
        // host without XDG, at the same user-only permissions.
        std::env::var_os("XDG_RUNTIME_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(personae::default_vault_dir)
            .join("graphshell-app.sock")
            .display()
            .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_ids_are_case_and_space_insensitive() {
        assert_eq!(AppId::new("  Turnstone "), AppId::new("turnstone"));
        let request = AppHello::new(AppId::new("TURNSTONE")).accept().unwrap();
        assert!(AllowedAppRoutes::default().admit(&request).is_ok());
    }

    #[test]
    fn an_unknown_application_is_refused() {
        let request = AppHello::new(AppId::new("someone-elses-app"))
            .accept()
            .unwrap();
        let error = AllowedAppRoutes::default().admit(&request).unwrap_err();
        assert_eq!(
            error,
            AppAdmissionError::NotAllowed(AppId::new("someone-elses-app"))
        );
    }

    #[test]
    fn a_device_can_admit_none() {
        let request = AppHello::new(AppId::new("turnstone")).accept().unwrap();
        assert!(AllowedAppRoutes::none().admit(&request).is_err());
        assert_eq!(AllowedAppRoutes::none().iter().count(), 0);
    }

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
    fn a_version_two_hello_requests_one_granted_route() {
        let knot = AppRouteId::new("knot").unwrap();
        let hello = AppHello::for_route(AppId::new("turnstone"), knot.clone());
        assert_eq!(
            hello.clone().accept().unwrap(),
            AppRequest::new(AppId::new("turnstone"), knot.clone())
        );
        let grants = AllowedAppRoutes::new([(
            AppId::new("turnstone"),
            ResidentEndpointRoute::new("knot", Duration::from_millis(7)).unwrap(),
        )]);
        let selected = grants.admit(&hello.accept().unwrap()).unwrap();
        assert_eq!(selected.id(), "knot");
        assert_eq!(selected.notice_poll_interval(), Duration::from_millis(7));
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

    #[test]
    fn an_ungranted_route_is_distinct_from_an_unknown_application() {
        let request =
            AppHello::for_route(AppId::new("turnstone"), AppRouteId::new("knot").unwrap())
                .accept()
                .unwrap();
        assert_eq!(
            AllowedAppRoutes::default().admit(&request).unwrap_err(),
            AppAdmissionError::RouteNotGranted {
                app: AppId::new("turnstone"),
                route: AppRouteId::new("knot").unwrap(),
            }
        );
    }

    // That this endpoint differs from the browser door's is checked beside
    // the browser door, in Graphshell's `native::device_broker`.
    #[cfg(all(
        feature = "door-native",
        any(unix, windows),
        not(target_arch = "wasm32")
    ))]
    #[test]
    fn the_default_endpoint_is_named() {
        assert!(!default_app_endpoint().is_empty());
    }

    fn knotlike() -> (AppDeclaration, AppGrant) {
        use crate::door::declaration::NamePattern;
        let declaration = AppDeclaration {
            routes: vec![NamePattern::exact("custody"), NamePattern::prefix("mere/")],
            ..AppDeclaration::default()
        };
        let mut grant = AppGrant::new(AppId::new("knotlike"));
        grant.routes = vec![NamePattern::exact("custody"), NamePattern::prefix("mere/")];
        (declaration, grant)
    }

    fn route(id: &str) -> ResidentEndpointRoute {
        ResidentEndpointRoute::new(id, Duration::from_millis(50)).unwrap()
    }

    fn declared_request(declaration: &AppDeclaration, route: &str) -> AppRequest {
        AppHello::for_route(AppId::new("knotlike"), AppRouteId::new(route).unwrap())
            .declaring(declaration.clone())
            .accept()
            .unwrap()
    }

    #[test]
    fn a_declared_app_gets_only_what_it_declares_and_its_owner_grants() {
        let (declaration, grant) = knotlike();
        let mut allowed = AllowedAppRoutes::none();
        allowed.grant_app(grant);
        allowed.serve(route("custody"));
        allowed.serve(route("published-site-v1"));
        allowed.grant_default(route("mere/notes"));
        assert_eq!(allowed.admit(&declared_request(&declaration, "custody")).unwrap().id(), "custody");
        assert_eq!(allowed.admit(&declared_request(&declaration, "mere/notes")).unwrap().id(), "mere/notes");
        assert_eq!(
            allowed.admit(&declared_request(&declaration, "published-site-v1")).unwrap_err(),
            AppAdmissionError::RouteUndeclared {
                app: AppId::new("knotlike"),
                route: AppRouteId::new("published-site-v1").unwrap(),
            },
            "served and reachable, but undeclared"
        );
        let mut wider = declaration.clone();
        wider.routes.push(crate::door::declaration::NamePattern::exact("published-site-v1"));
        assert!(matches!(
            allowed.admit(&declared_request(&wider, "published-site-v1")),
            Err(AppAdmissionError::RouteNotGranted { .. })
        ), "declared, but the owner did not grant it");
        assert!(matches!(
            allowed.admit(&declared_request(&declaration, "mere/unserved")),
            Err(AppAdmissionError::RouteNotGranted { .. })
        ), "granted by namespace, but not served");
        allowed.set_denied(AppId::new("knotlike"), AppRouteId::new("mere/notes").unwrap(), true);
        assert!(matches!(
            allowed.admit(&declared_request(&declaration, "mere/notes")),
            Err(AppAdmissionError::RouteDenied { .. })
        ));
        let authority = allowed.authority(&declared_request(&declaration, "custody")).unwrap();
        assert_eq!(authority.app(), &AppId::new("knotlike"));
        let reported: Vec<_> = allowed.iter().map(|(app, route)| (app.as_str(), route.as_str())).collect();
        assert_eq!(reported, [("knotlike", "custody")]);
    }

    #[test]
    fn a_declared_app_cannot_fall_back_to_its_label() {
        let (_, grant) = knotlike();
        let mut allowed = AllowedAppRoutes::none();
        allowed.grant_app(grant);
        allowed.serve(route("custody"));
        let request = AppHello::for_route(AppId::new("knotlike"), AppRouteId::new("custody").unwrap())
            .accept()
            .unwrap();
        assert_eq!(
            allowed.admit(&request).unwrap_err(),
            AppAdmissionError::DeclarationRequired(AppId::new("knotlike"))
        );
        assert!(allowed.authority(&request).is_none());
        assert!(
            allowed.permits(&request.app, &request.route).is_ok(),
            "a host recheck of an admitted session consults policy, not the hello"
        );
    }

    #[test]
    fn an_unknown_app_gains_nothing_by_declaring() {
        let (declaration, _) = knotlike();
        let mut allowed = AllowedAppRoutes::none();
        allowed.serve(route("custody"));
        let request = AppHello::for_route(AppId::new("knotlike"), AppRouteId::new("custody").unwrap())
            .declaring(declaration)
            .accept()
            .unwrap();
        assert_eq!(allowed.admit(&request).unwrap_err(), AppAdmissionError::NotAllowed(AppId::new("knotlike")));
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

    #[cfg(feature = "door-serve")]
    fn pinned(identity: crate::door::declaration::AppIdentity) -> AllowedAppRoutes {
        let (_, mut grant) = knotlike();
        grant.identity = Some(identity);
        let mut allowed = AllowedAppRoutes::none();
        allowed.grant_app(grant);
        allowed
    }

    #[cfg(feature = "door-serve")]
    #[test]
    fn an_unpinned_label_is_development_mode() {
        use crate::door::declaration::IdentityBasis;
        let (declaration, grant) = knotlike();
        let mut allowed = AllowedAppRoutes::none();
        allowed.grant_app(grant);
        let request = declared_request(&declaration, "custody");
        assert_eq!(allowed.identify(&request, None).unwrap(), IdentityBasis::Development);
        let other_platform = pinned(crate::door::declaration::AppIdentity {
            windows: Some(crate::door::declaration::WindowsAppIdentity { image: r"C:\Knot\knot.exe".into() }),
            ..Default::default()
        });
        if !cfg!(windows) {
            assert_eq!(
                other_platform.identify(&request, None).unwrap(),
                IdentityBasis::Development,
                "a pin for another platform leaves this one in development mode"
            );
        }
    }

    #[cfg(all(feature = "door-serve", target_os = "macos"))]
    #[test]
    fn a_macos_pin_refuses_an_unsigned_peer() {
        use std::os::fd::AsRawFd;
        let allowed = pinned(crate::door::declaration::AppIdentity {
            macos: Some(crate::door::declaration::SignedAppIdentity {
                team: "ABCDE12345".into(),
                identifier: "com.merely.knot".into(),
            }),
            ..Default::default()
        });
        let (declaration, _) = knotlike();
        let request = declared_request(&declaration, "custody");
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        let connected = peer_facts::Connected::unix(a.as_raw_fd()).unwrap();
        assert!(matches!(
            allowed.identify(&request, Some(&connected)),
            Err(AppAdmissionError::IdentityMismatch { .. })
        ));
        assert!(matches!(
            allowed.identify(&request, None),
            Err(AppAdmissionError::IdentityMismatch { .. })
        ), "no peer facts never pass a pin");
    }

    #[cfg(all(feature = "door-serve", target_os = "linux"))]
    #[test]
    fn a_linux_pin_needs_a_live_launch_for_that_app() {
        use crate::door::declaration::{AppIdentity, IdentityBasis, LinuxLaunch};
        let mut allowed = pinned(AppIdentity {
            linux: Some(LinuxLaunch { executable: "/usr/bin/knot".into(), args: vec![] }),
            ..Default::default()
        });
        let (declaration, _) = knotlike();
        let handle = LaunchHandle::from_bytes([7; 32]);
        let mut request = declared_request(&declaration, "custody");
        assert!(matches!(allowed.identify(&request, None), Err(AppAdmissionError::IdentityMismatch { .. })));
        request.launch = Some(handle);
        assert!(allowed.identify(&request, None).is_err(), "an unknown handle");
        allowed.begin_launch(handle, AppId::new("someone-else"));
        assert!(allowed.identify(&request, None).is_err(), "a handle for another app");
        allowed.begin_launch(handle, AppId::new("knotlike"));
        assert_eq!(allowed.identify(&request, None).unwrap(), IdentityBasis::Launched);
        allowed.end_launch(&handle);
        assert!(allowed.identify(&request, None).is_err(), "an ended launch");
    }

    #[test]
    fn a_windows_image_matches_without_case_or_separator_style() {
        let pin = crate::door::declaration::WindowsAppIdentity { image: r"C:\Program Files\Knot\knot.exe".into() };
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
    fn a_grant_added_later_admits_the_next_request() {
        let grants = AppRouteGrants::new(AllowedAppRoutes::none());
        let request = AppHello::for_route(
            AppId::new("turnstone"),
            AppRouteId::new("mere/divination").unwrap(),
        )
        .accept()
        .unwrap();
        let before = grants.current();
        assert!(before.admit(&request).is_err());
        grants.grant(
            AppId::new("turnstone"),
            ResidentEndpointRoute::new("mere/divination", Duration::from_millis(50)).unwrap(),
        );
        assert!(grants.current().admit(&request).is_ok());
        assert!(
            before.admit(&request).is_err(),
            "a connection admitted earlier kept the grants it had"
        );
    }
}
