// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;
use ostiary::app_admission::AppHello;
use ostiary::declaration::AppDeclaration;

/// A declaration naming exactly `routes`.
fn declaring(routes: &[&str]) -> AppDeclaration {
    AppDeclaration {
        routes: routes
            .iter()
            .map(|route| ostiary::declaration::NamePattern::exact(*route))
            .collect(),
        ..AppDeclaration::default()
    }
}

#[test]
fn app_ids_are_case_and_space_insensitive() {
    assert_eq!(AppId::new("  Turnstone "), AppId::new("turnstone"));
    let request = AppHello::for_route(AppId::new("TURNSTONE"), AppRouteId::identity())
        .declaring(declaring(&["identity"]))
        .accept()
        .unwrap();
    assert!(
        AllowedAppRoutes::identity_for(AppId::new("turnstone"))
            .admit(&request)
            .is_ok()
    );
}

#[test]
fn a_hello_that_declares_nothing_is_refused_whatever_its_label() {
    let grants = AllowedAppRoutes::identity_for(AppId::new("turnstone"));
    let legacy = AppHello::new(AppId::new("turnstone")).accept().unwrap();
    assert_eq!(
        grants.admit(&legacy).unwrap_err(),
        AppAdmissionError::DeclarationRequired(AppId::new("turnstone"))
    );
    let unknown = AppHello::new(AppId::new("woodshed")).accept().unwrap();
    assert_eq!(
        grants.admit(&unknown).unwrap_err(),
        AppAdmissionError::NotAllowed(AppId::new("woodshed"))
    );
}

#[test]
fn a_route_closed_to_agents_refuses_an_agent_whatever_it_is_granted() {
    let retinue = ResidentEndpointRoute::new("retinue/radios", Duration::from_millis(50)).unwrap();
    let mut grants = AllowedAppRoutes::none();
    grants.serve(retinue);
    grants.close_to_agents(ostiary::declaration::NamePattern::prefix("retinue/"));
    for (app, agent) in [("mcp.agent", true), ("graphshell", false)] {
        let mut grant = AppGrant::new(AppId::new(app));
        grant.routes = vec![ostiary::declaration::NamePattern::prefix("retinue/")];
        grant.agent = agent;
        grants.grant_app(grant);
    }
    let request = |app: &str| {
        AppHello::for_route(AppId::new(app), AppRouteId::new("retinue/radios").unwrap())
            .declaring(declaring(&["retinue/radios"]))
            .accept()
            .unwrap()
    };
    assert_eq!(
        grants.admit(&request("mcp.agent")).unwrap_err(),
        AppAdmissionError::ClosedToAgents {
            app: AppId::new("mcp.agent"),
            route: AppRouteId::new("retinue/radios").unwrap(),
        }
    );
    assert!(
        grants.admit(&request("graphshell")).is_ok(),
        "a granted application that is not an agent opens it"
    );
}

#[test]
fn an_unknown_application_is_refused() {
    let request = AppHello::new(AppId::new("someone-elses-app"))
        .accept()
        .unwrap();
    let error = AllowedAppRoutes::identity_for(AppId::new("turnstone"))
        .admit(&request)
        .unwrap_err();
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
    let hello = hello.declaring(declaring(&["knot"]));
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
    let request = AppHello::for_route(AppId::new("turnstone"), AppRouteId::new("knot").unwrap())
        .declaring(declaring(&["knot"]))
        .accept()
        .unwrap();
    assert_eq!(
        AllowedAppRoutes::identity_for(AppId::new("turnstone"))
            .admit(&request)
            .unwrap_err(),
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
    assert_eq!(
        allowed
            .admit(&declared_request(&declaration, "custody"))
            .unwrap()
            .id(),
        "custody"
    );
    assert_eq!(
        allowed
            .admit(&declared_request(&declaration, "mere/notes"))
            .unwrap()
            .id(),
        "mere/notes"
    );
    assert_eq!(
        allowed
            .admit(&declared_request(&declaration, "published-site-v1"))
            .unwrap_err(),
        AppAdmissionError::RouteUndeclared {
            app: AppId::new("knotlike"),
            route: AppRouteId::new("published-site-v1").unwrap(),
        },
        "served and reachable, but undeclared"
    );
    let mut wider = declaration.clone();
    wider.routes.push(ostiary::declaration::NamePattern::exact(
        "published-site-v1",
    ));
    assert!(
        matches!(
            allowed.admit(&declared_request(&wider, "published-site-v1")),
            Err(AppAdmissionError::RouteNotGranted { .. })
        ),
        "declared, but the owner did not grant it"
    );
    assert!(
        matches!(
            allowed.admit(&declared_request(&declaration, "mere/unserved")),
            Err(AppAdmissionError::RouteNotGranted { .. })
        ),
        "granted by namespace, but not served"
    );
    allowed.set_denied(
        AppId::new("knotlike"),
        AppRouteId::new("mere/notes").unwrap(),
        true,
    );
    assert!(matches!(
        allowed.admit(&declared_request(&declaration, "mere/notes")),
        Err(AppAdmissionError::RouteDenied { .. })
    ));
    let authority = allowed
        .authority(&declared_request(&declaration, "custody"))
        .unwrap();
    assert_eq!(authority.app(), &AppId::new("knotlike"));
    let reported: Vec<_> = allowed
        .iter()
        .map(|(app, route)| (app.as_str(), route.as_str()))
        .collect();
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
    assert_eq!(
        allowed.admit(&request).unwrap_err(),
        AppAdmissionError::NotAllowed(AppId::new("knotlike"))
    );
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
    assert_eq!(
        allowed.identify(&request, None).unwrap(),
        IdentityBasis::Development
    );
    let other_platform = pinned(ostiary::declaration::AppIdentity {
        windows: Some(ostiary::declaration::WindowsAppIdentity {
            image: r"C:\Knot\knot.exe".into(),
        }),
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
    assert!(
        matches!(
            allowed.identify(&request, None),
            Err(AppAdmissionError::IdentityMismatch { .. })
        ),
        "no peer facts never pass a pin"
    );
}

#[cfg(all(feature = "door-serve", target_os = "linux"))]
#[test]
fn a_linux_pin_needs_a_live_launch_for_that_app() {
    use ostiary::declaration::{AppIdentity, IdentityBasis, LinuxLaunch};
    let mut allowed = pinned(AppIdentity {
        linux: Some(LinuxLaunch {
            executable: "/usr/bin/knot".into(),
            args: vec![],
        }),
        ..Default::default()
    });
    let (declaration, _) = knotlike();
    let handle = LaunchHandle::from_bytes([7; 32]);
    let mut request = declared_request(&declaration, "custody");
    assert!(matches!(
        allowed.identify(&request, None),
        Err(AppAdmissionError::IdentityMismatch { .. })
    ));
    request.launch = Some(handle);
    assert!(
        allowed.identify(&request, None).is_err(),
        "an unknown handle"
    );
    allowed.begin_launch(handle, AppId::new("someone-else"));
    assert!(
        allowed.identify(&request, None).is_err(),
        "a handle for another app"
    );
    allowed.begin_launch(handle, AppId::new("knotlike"));
    assert_eq!(
        allowed.identify(&request, None).unwrap(),
        IdentityBasis::Launched
    );
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
    let server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(&endpoint)
        .unwrap();
    let _client = ClientOptions::new().open(&endpoint).unwrap();
    server.connect().await.unwrap();
    let connected =
        peer_facts::Connected::pipe_client(server.as_raw_handle() as _, peer_facts::system_time())
            .unwrap();
    let process = connected.process().unwrap();
    let (declaration, _) = knotlike();
    let request = declared_request(&declaration, "custody");

    let mut allowed = pinned(AppIdentity {
        windows: Some(WindowsAppIdentity {
            image: r"C:\Knot\knot.exe".into(),
        }),
        ..Default::default()
    });
    let refused = |allowed: &AllowedAppRoutes| {
        matches!(
            allowed.identify(&request, Some(&connected)),
            Err(AppAdmissionError::IdentityMismatch { .. })
        )
    };
    assert!(refused(&allowed), "neither launched nor the pinned image");
    allowed.begin_process(process, AppId::new("someone-else"));
    assert!(refused(&allowed), "launched for another application");
    allowed.begin_process(process, AppId::new("knotlike"));
    assert_eq!(
        allowed.identify(&request, Some(&connected)).unwrap(),
        IdentityBasis::Launched
    );
    let mut another = process;
    another.created += 1;
    allowed.end_process(&process);
    allowed.begin_process(another, AppId::new("knotlike"));
    assert!(
        refused(&allowed),
        "the same id with another creation time is another process"
    );

    let exe = std::env::current_exe()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let by_image = pinned(AppIdentity {
        windows: Some(WindowsAppIdentity { image: exe }),
        ..Default::default()
    });
    assert!(matches!(
        by_image.identify(&request, Some(&connected)),
        Ok(IdentityBasis::WindowsImage { .. })
    ));
    assert!(
        matches!(
            by_image.identify(&request, None),
            Err(AppAdmissionError::IdentityMismatch { .. })
        ),
        "no peer facts never pass a pin"
    );
}

#[test]
fn a_grant_added_later_admits_the_next_request() {
    let grants = AppRouteGrants::new(AllowedAppRoutes::none());
    let request = AppHello::for_route(
        AppId::new("turnstone"),
        AppRouteId::new("mere/divination").unwrap(),
    )
    .declaring(declaring(&["mere/divination"]))
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
