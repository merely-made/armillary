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

use ostiary::app_admission::{
    APP_IDENTITY_ROUTE, AppAdmissionError, AppId, AppRequest, AppRouteId, LaunchHandle,
};
use ostiary::declaration::{AppAuthority, AppGrant, NamePattern};
use ostiary::route::ResidentEndpointRoute;

mod identity;

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
    /// Route namespaces closed to applications the owner marks agents (D25).
    agents_closed: Vec<NamePattern>,
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
            agents_closed: Vec::new(),
            served: BTreeMap::new(),
            launches: BTreeMap::new(),
            #[cfg(feature = "door-serve")]
            processes: BTreeMap::new(),
        }
    }

    /// Select the host-configured route granted to this request.
    ///
    /// A request is admitted only by its declaration, to a route it declares
    /// and the policy permits; a hello that declares nothing is refused,
    /// whatever its label (capability door D22, D24).
    pub fn admit(&self, request: &AppRequest) -> Result<ResidentEndpointRoute, AppAdmissionError> {
        match &request.declaration {
            Some(declaration) => {
                if !self.grants.contains_key(&request.app)
                    && !self.routes.contains_key(&request.app)
                {
                    return Err(AppAdmissionError::NotAllowed(request.app.clone()));
                }
                if !declaration.declares_route(&request.route) {
                    return Err(AppAdmissionError::RouteUndeclared {
                        app: request.app.clone(),
                        route: request.route.clone(),
                    });
                }
            }
            None if self.is_admitted(&request.app) => {
                return Err(AppAdmissionError::DeclarationRequired(request.app.clone()));
            }
            None => return Err(AppAdmissionError::NotAllowed(request.app.clone())),
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
        if grant.is_some_and(|grant| grant.agent)
            && self
                .agents_closed
                .iter()
                .any(|closed| closed.matches(route.as_str()))
        {
            return Err(AppAdmissionError::ClosedToAgents {
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

    /// The owner grant for a declared application.
    pub fn app_grant(&self, app: &AppId) -> Option<&AppGrant> {
        self.grants.get(app)
    }

    /// Close every route `pattern` names to applications the owner marks
    /// agents. Like a denial, this wins over every grant (D25).
    pub fn close_to_agents(&mut self, pattern: NamePattern) {
        if !self.agents_closed.contains(&pattern) {
            self.agents_closed.push(pattern);
        }
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
                .chain(
                    self.defaults
                        .keys()
                        .filter(move |route| !self.served.contains_key(*route)),
                )
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
        self.routes
            .iter()
            .flat_map(move |(app, routes)| {
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
mod tests;
