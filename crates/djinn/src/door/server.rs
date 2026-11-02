// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

//! Application admission and connect, before any service-specific admission.
//! The owner supplies route resolution; the shared door owns frame intake,
//! hello validation and the nonce transcript. Custody does not require a
//! projection session. A successful handshake does not send Connected: the
//! selected service must finish its own admission first.

use std::future::Future;
use tokio::io::{AsyncRead, AsyncWrite};
use ostiary::{
    app_admission::{AppAdmissionError, AppHello, AppId, AppRequest},
    declaration::{AppAuthority, IdentityBasis},
    frame::{FrameError, read_native_message_async, write_native_message_async},
    local_endpoint::LocalStream,
    route::ResidentEndpointRoute,
    wire::{APP_CONNECT_SCHEMA, AppHostMessage, AppMessage, BrowserChallenge},
};
use super::{
    app_admission::{AllowedAppRoutes, AppRouteGrants},
    link::{LinkError, LocalLink},
    local_endpoint::LocalListener,
};

#[derive(Debug, thiserror::Error)]
pub enum AppServerError {
    #[error(transparent)] Frame(#[from] FrameError),
    #[error(transparent)] Admission(#[from] AppAdmissionError),
    #[error(transparent)] Link(#[from] LinkError),
    #[error("the application stream ended before its hello")] MissingHello,
    #[error("the first application message must answer the host challenge")] ConnectRequired,
    #[error("application connect used another schema")] WrongSchema,
}

pub struct AdmittedApp {
    pub app: AppId,
    pub route: ResidentEndpointRoute,
    /// What the OS said about the peer when it connected, where it would say.
    /// The label above is the application's own statement; this is not.
    pub peer: Option<peer_facts::Peer>,
    /// What the label rests on: a pinned OS identity the peer matched, or
    /// development mode.
    pub basis: IdentityBasis,
    /// What the connection declared and its owner granted; `None` for an
    /// application admitted by label alone.
    pub authority: Option<AppAuthority>,
}

/// Snapshot owner grants once for each accepted same-user connection, and
/// hand each with what the OS says about its peer. The listener tracks
/// children using the surrounding resident task scope.
pub async fn serve_on_with_peer<H, F>(listener: LocalListener, grants: AppRouteGrants, handle: H) -> std::io::Result<()>
where
    H: Fn(Box<dyn LocalStream>, AllowedAppRoutes, Option<peer_facts::Connected>) -> F + Clone + Send + Sync + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    listener
        .serve_with_peer(move |stream, peer| handle(stream, grants.current(), peer))
        .await
}

/// Resolve the host-owned route, record what the OS said about the
/// connection's peer and check it against an identity the owner pinned the
/// label to. A resolver can include current provider leases; it must retain
/// owner denials.
pub async fn admit_from<R, Resolve>(
    reader: &mut R,
    connected: Option<peer_facts::Connected>,
    allowed: &AllowedAppRoutes,
    resolve: Resolve,
) -> Result<AdmittedApp, AppServerError>
where
    R: AsyncRead + Unpin,
    Resolve: FnOnce(&AppRequest, &AllowedAppRoutes) -> Result<ResidentEndpointRoute, AppAdmissionError>,
{
    let hello = read_native_message_async::<_, AppHello>(reader).await?.ok_or(AppServerError::MissingHello)?;
    let request = hello.accept()?;
    let route = resolve(&request, allowed)?;
    let basis = allowed.identify(&request, connected.as_ref())?;
    let authority = allowed.authority(&request);
    let peer = connected.map(|connected| connected.peer);
    Ok(AdmittedApp { app: request.app, route, peer, basis, authority })
}

/// Tell the client why its hello was refused, as a typed frame, before the
/// stream ends (capability door D24). Only an admission refusal crosses; a
/// transport or framing failure ends the stream as before.
pub async fn refuse<W: AsyncWrite + Unpin>(writer: &mut W, error: &AppServerError) -> Result<(), AppServerError> {
    let AppServerError::Admission(refusal) = error else { return Ok(()) };
    write_native_message_async(writer, &AppHostMessage::<(), (), ()>::Refused { refusal: refusal.clone() }).await?;
    Ok(())
}

/// Complete connect after the adapter has captured its per-session surface.
pub async fn connect<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(reader: &mut R, writer: &mut W, app: &AppId) -> Result<Option<LocalLink>, AppServerError> {
    let challenge = BrowserChallenge::fresh();
    write_native_message_async(writer, &AppHostMessage::<(), (), ()>::Challenge { challenge: challenge.clone() }).await?;
    let Some(message) = read_native_message_async::<_, AppMessage<serde::de::IgnoredAny, serde::de::IgnoredAny>>(reader).await? else { return Ok(None); };
    let AppMessage::Connect { schema, host_nonce, client_nonce } = message else { return Err(AppServerError::ConnectRequired); };
    if schema != APP_CONNECT_SCHEMA { return Err(AppServerError::WrongSchema); }
    let link = LocalLink::bind(app.to_string(), &challenge, &host_nonce, &client_nonce)?;
    Ok(Some(link))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use std::time::Duration;

    #[tokio::test]
    async fn admission_keeps_host_route_and_shared_transcript() {
        let (mut client, server) = tokio::io::duplex(4096);
        let host = tokio::spawn(async move {
            let (mut r, mut w) = tokio::io::split(server);
            let grants = AllowedAppRoutes::new([(AppId::new("fixture"), ResidentEndpointRoute::new("custody", Duration::from_millis(50)).unwrap())]);
            let admitted = admit_from(&mut r, None, &grants, |request, grants| grants.admit(request)).await.unwrap();
            let link = connect(&mut r, &mut w, &admitted.app).await.unwrap().unwrap();
            (admitted, link)
        });
        let declaration = ostiary::declaration::AppDeclaration { routes: vec![ostiary::declaration::NamePattern::exact("custody")], ..Default::default() };
        write_native_message_async(&mut client, &AppHello::for_route(AppId::new("fixture"), ostiary::app_admission::AppRouteId::new("custody").unwrap()).declaring(declaration)).await.unwrap();
        let Some(AppHostMessage::<(), (), ()>::Challenge { challenge }) = read_native_message_async(&mut client).await.unwrap() else { panic!("challenge") };
        write_native_message_async(&mut client, &AppMessage::<(), ()>::Connect { schema: APP_CONNECT_SCHEMA.into(), host_nonce: challenge.host_nonce, client_nonce: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([3;32]) }).await.unwrap();
        let (admitted, link) = host.await.unwrap();
        assert_eq!(admitted.app.as_str(), "fixture");
        assert_eq!(admitted.route.id(), "custody");
        assert_eq!(link.client_nonce, [3;32]);
    }

    #[tokio::test]
    async fn a_refused_hello_reaches_the_client_typed() {
        let (mut client, server) = tokio::io::duplex(4096);
        let host = tokio::spawn(async move {
            let (mut r, mut w) = tokio::io::split(server);
            let grants = AllowedAppRoutes::none();
            let error = admit_from(&mut r, None, &grants, |request, grants| grants.admit(request)).await.err().expect("refused");
            refuse(&mut w, &error).await.unwrap();
        });
        write_native_message_async(&mut client, &AppHello::for_route(AppId::new("woodshed"), ostiary::app_admission::AppRouteId::new("custody").unwrap())).await.unwrap();
        let reply: Option<AppHostMessage<(), (), ()>> = read_native_message_async(&mut client).await.unwrap();
        assert_eq!(
            reply,
            Some(AppHostMessage::Refused { refusal: AppAdmissionError::NotAllowed(AppId::new("woodshed")) })
        );
        host.await.unwrap();
    }
}
