// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0


//! The owner's grants: which applications this device's door admits, on
//! which routes, and what a pinned label rests on. The hello and the types it
//! carries are the door contract, in `ostiary`.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use ostiary::app_admission::{APP_IDENTITY_ROUTE, AppAdmissionError, AppId, AppRequest, AppRouteId, LaunchHandle};
use ostiary::declaration::{AppAuthority, AppGrant};
#[cfg(feature = "door-serve")]
use ostiary::declaration::IdentityBasis;
use ostiary::route::ResidentEndpointRoute;

/// Default notice cadence for the legacy identity grant. The cadence is
/// ignored by that route, while callers granting catalog routes supply their
/// own value through [`ResidentEndpointRoute`].
const DEFAULT_IDENTITY_NOTICE_POLL: Duration = Duration::from_millis(50);

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
    /// Live launched Windows processes, each naming its application.
    #[cfg(feature = "door-serve")]
    processes: BTreeMap<peer_facts::ProcessKey, AppId>,
}

impl Default for AllowedAppRoutes {
    /// Admit none: which applications a device serves is its owner's policy,
    /// not this crate's.
    fn default() -> Self {
        Self::none()
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

    /// Admit `app` to the identity route the version-one hello selects.
    pub fn identity_for(app: AppId) -> Self {
        Self::new([(
            app,
            ResidentEndpointRoute::new(APP_IDENTITY_ROUTE, DEFAULT_IDENTITY_NOTICE_POLL)
                .expect("the identity route is valid"),
        )])
    }

    /// The identity route as hosts serve it.
    pub fn identity_route() -> ResidentEndpointRoute {
        ResidentEndpointRoute::new(APP_IDENTITY_ROUTE, DEFAULT_IDENTITY_NOTICE_POLL)
            .expect("the identity route is valid")
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
            #[cfg(feature = "door-serve")]
            processes: BTreeMap::new(),
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

    /// Accept connections from `process` as `app`'s launch, until
    /// [`Self::end_process`]. Djinn holds the process's handle meanwhile, so
    /// its id names no other process.
    #[cfg(feature = "door-serve")]
    pub fn begin_process(&mut self, process: peer_facts::ProcessKey, app: AppId) {
        self.processes.insert(process, app);
    }

    /// Stop accepting `process`: it exited.
    #[cfg(feature = "door-serve")]
    pub fn end_process(&mut self, process: &peer_facts::ProcessKey) {
        self.processes.remove(process);
    }

    /// How many launches are live: handles, and launched Windows processes.
    pub fn launch_count(&self) -> usize {
        #[cfg(feature = "door-serve")]
        let processes = self.processes.len();
        #[cfg(not(feature = "door-serve"))]
        let processes = 0;
        self.launches.len() + processes
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
                let launched = connected
                    .and_then(|c| c.process())
                    .and_then(|process| self.processes.get(&process));
                if launched == Some(&request.app) {
                    return Ok(IdentityBasis::Launched);
                }
                let image = connected.and_then(|c| match &c.peer {
                    peer_facts::Peer::Windows { image, .. } => image.clone(),
                    _ => None,
                });
                return match image.filter(|image| windows.matches(image)) {
                    Some(image) => Ok(IdentityBasis::WindowsImage { image }),
                    None => Err(mismatch(format!("the executable {} or a process Djinn launched", windows.image))),
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

#[cfg(test)]
mod tests {
    use super::*;
    use ostiary::app_admission::AppHello;
    use ostiary::declaration::AppDeclaration;

    #[test]
    fn app_ids_are_case_and_space_insensitive() {
        assert_eq!(AppId::new("  Turnstone "), AppId::new("turnstone"));
        let request = AppHello::new(AppId::new("TURNSTONE")).accept().unwrap();
        assert!(AllowedAppRoutes::identity_for(AppId::new("turnstone")).admit(&request).is_ok());
    }

    #[test]
    fn an_unknown_application_is_refused() {
        let request = AppHello::new(AppId::new("someone-elses-app"))
            .accept()
            .unwrap();
        let error = AllowedAppRoutes::identity_for(AppId::new("turnstone")).admit(&request).unwrap_err();
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
    fn an_ungranted_route_is_distinct_from_an_unknown_application() {
        let request =
            AppHello::for_route(AppId::new("turnstone"), AppRouteId::new("knot").unwrap())
                .accept()
                .unwrap();
        assert_eq!(
            AllowedAppRoutes::identity_for(AppId::new("turnstone")).admit(&request).unwrap_err(),
            AppAdmissionError::RouteNotGranted {
                app: AppId::new("turnstone"),
                route: AppRouteId::new("knot").unwrap(),
            }
        );
    }

    fn knotlike() -> (AppDeclaration, AppGrant) {
        use ostiary::declaration::NamePattern;
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
        wider.routes.push(ostiary::declaration::NamePattern::exact("published-site-v1"));
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

    #[cfg(feature = "door-serve")]
    fn pinned(identity: ostiary::declaration::AppIdentity) -> AllowedAppRoutes {
        let (_, mut grant) = knotlike();
        grant.identity = Some(identity);
        let mut allowed = AllowedAppRoutes::none();
        allowed.grant_app(grant);
        allowed
    }

    #[cfg(feature = "door-serve")]
    #[test]
    fn an_unpinned_label_is_development_mode() {
        use ostiary::declaration::IdentityBasis;
        let (declaration, grant) = knotlike();
        let mut allowed = AllowedAppRoutes::none();
        allowed.grant_app(grant);
        let request = declared_request(&declaration, "custody");
        assert_eq!(allowed.identify(&request, None).unwrap(), IdentityBasis::Development);
        let other_platform = pinned(ostiary::declaration::AppIdentity {
            windows: Some(ostiary::declaration::WindowsAppIdentity { image: r"C:\Knot\knot.exe".into() }),
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
        let allowed = pinned(ostiary::declaration::AppIdentity {
            macos: Some(ostiary::declaration::SignedAppIdentity {
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
        use ostiary::declaration::{AppIdentity, IdentityBasis, LinuxLaunch};
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

    #[cfg(all(feature = "door-serve", windows))]
    #[tokio::test]
    async fn a_windows_pin_admits_the_launched_process_and_otherwise_its_image() {
        use ostiary::declaration::{AppIdentity, IdentityBasis, WindowsAppIdentity};
        use std::os::windows::io::AsRawHandle;
        use tokio::net::windows::named_pipe::{ClientOptions, ServerOptions};

        let endpoint = format!(r"\\.\pipe\djinn-launch-pin-{}", uuid::Uuid::new_v4());
        let server = ServerOptions::new().first_pipe_instance(true).create(&endpoint).unwrap();
        let _client = ClientOptions::new().open(&endpoint).unwrap();
        server.connect().await.unwrap();
        let connected = peer_facts::Connected::pipe_client(server.as_raw_handle() as _, peer_facts::system_time()).unwrap();
        let process = connected.process().unwrap();
        let (declaration, _) = knotlike();
        let request = declared_request(&declaration, "custody");

        let mut allowed = pinned(AppIdentity {
            windows: Some(WindowsAppIdentity { image: r"C:\Knot\knot.exe".into() }),
            ..Default::default()
        });
        let refused = |allowed: &AllowedAppRoutes| matches!(allowed.identify(&request, Some(&connected)), Err(AppAdmissionError::IdentityMismatch { .. }));
        assert!(refused(&allowed), "neither launched nor the pinned image");
        allowed.begin_process(process, AppId::new("someone-else"));
        assert!(refused(&allowed), "launched for another application");
        allowed.begin_process(process, AppId::new("knotlike"));
        assert_eq!(allowed.identify(&request, Some(&connected)).unwrap(), IdentityBasis::Launched);
        let mut another = process;
        another.created += 1;
        allowed.end_process(&process);
        allowed.begin_process(another, AppId::new("knotlike"));
        assert!(refused(&allowed), "the same id with another creation time is another process");

        let exe = std::env::current_exe().unwrap().to_string_lossy().into_owned();
        let by_image = pinned(AppIdentity { windows: Some(WindowsAppIdentity { image: exe }), ..Default::default() });
        assert!(matches!(by_image.identify(&request, Some(&connected)), Ok(IdentityBasis::WindowsImage { .. })));
        assert!(matches!(by_image.identify(&request, None), Err(AppAdmissionError::IdentityMismatch { .. })), "no peer facts never pass a pin");
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
