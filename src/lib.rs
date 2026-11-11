
use std::sync::Arc;

use futures_util::lock::Mutex;
use regex::Regex;
use tokio_util::compat::FuturesAsyncReadCompatExt;

use wisp_mux::{
    packet::{CloseReason, ConnectPacket, StreamType},
    stream::MuxStream,
    ws::TransportWrite,
    ServerMux, WispError,
};

use worker::{
    console_log,
    console_warn,
    event,
    wasm_bindgen_futures::spawn_local,
    worker_sys::web_sys::WebSocket,
    Context, Env, Error, Headers, Request, Response,
    ResponseBody, Result, Socket, WebSocketPair,
};

use ws_wrapper::WebSocketWrapper;
mod ws_wrapper;

fn to_worker(val: WispError) -> Error {
    Error::RustError(val.to_string())
}

// Handle incoming Wisp TCP streams
async fn stream_handler(
    packet: ConnectPacket,
    stream: MuxStream<impl TransportWrite>,
) -> Result<()> {
    match packet.stream_type {
        StreamType::Tcp => {
            console_log!(
                "TCP connect requested: {}:{}",
                packet.host,
                packet.port
            );

            let mut socket = match Socket::builder()
                .connect(packet.host.clone(), packet.port)
            {
                Ok(socket) => {
                    console_log!(
                        "TCP socket created: {}:{}",
                        packet.host,
                        packet.port
                    );
                    socket
                }
                Err(error) => {
                    console_warn!(
                        "TCP socket creation failed: {:?}",
                        error
                    );

                    stream
                        .close(
                            CloseReason::ServerStreamInvalidInfo
                        )
                        .await
                        .map_err(to_worker)?;

                    return Err(error);
                }
            };

            let mut wisp_socket =
                stream.into_async_rw().compat();

            console_log!(
                "Starting TCP relay for {}:{}",
                packet.host,
                packet.port
            );

            match tokio::io::copy_bidirectional(
                &mut socket,
                &mut wisp_socket,
            )
            .await
            {
                Ok((a, b)) => {
                    console_log!(
                        "TCP relay finished: {} bytes / {} bytes",
                        a,
                        b
                    );
                }

                Err(error) => {
                    console_warn!(
                        "TCP relay failed for {}:{}: {:?}",
                        packet.host,
                        packet.port,
                        error
                    );

                    return Err(error.into());
                }
            }
        }

        StreamType::Udp | StreamType::Other(_) => {
            console_warn!(
                "Rejected unsupported stream type"
            );

            stream
                .close(
                    CloseReason::ServerStreamInvalidInfo
                )
                .await
                .map_err(to_worker)?;
        }
    }

    Ok(())
}

// Handle WebSocket connections
async fn ws_handler(
    ws: WebSocket,
    env: Env,
) -> Result<()> {
    let (tx, rx) = WebSocketWrapper::connect(ws);

    console_log!("Accepted websocket");

    let (server, fut) = ServerMux::new(
        rx.into_read(),
        tx.into_write(),
        128,
        None,
    )
    .await
    .map_err(to_worker)?
    .with_no_required_extensions();

    console_log!("Created Wisp mux");

    spawn_local(async move {
        console_warn!(
            "Mux future result: {:?}",
            fut.await
        );
    });

    let connected_vec =
        Arc::new(Mutex::new(Vec::new()));

    let allowed_host_regex =
        env.var("allowed_host_regex").ok().and_then(|x| {
            let regex =
                Regex::try_from(x.to_string()).ok();

            if regex.is_none() {
                console_warn!(
                    "Invalid allowed_host_regex"
                );
            }

            regex
        });

    while let Some((packet, stream)) =
        server.wait_for_stream().await
    {
        console_log!(
            "Incoming Wisp stream: {}:{}",
            packet.host,
            packet.port
        );

        let connected_vec =
            connected_vec.clone();

        let stream_ident =
            (packet.host.clone(), packet.port);

        let mut locked =
            connected_vec.lock().await;

        // Limit simultaneous connections
        if locked.contains(&stream_ident)
            || locked.len() >= 6
        {
            stream
                .close(
                    CloseReason::ServerStreamThrottled
                )
                .await
                .map_err(to_worker)?;

            console_warn!(
                "Stream throttled: {}:{}",
                packet.host,
                packet.port
            );

            continue;
        }

        // Check allowed hosts
        if let Some(ref regex) =
            allowed_host_regex
        {
            if !regex.is_match(&packet.host) {
                stream
                    .close(
                        CloseReason::ServerStreamBlockedAddress
                    )
                    .await
                    .map_err(to_worker)?;

                console_warn!(
                    "Blocked disallowed host: {}",
                    packet.host
                );

                continue;
            }
        }

        locked.push(stream_ident.clone());
        drop(locked);

        console_log!(
            "Creating TCP stream: {}:{}",
            packet.host,
            packet.port
        );

        spawn_local(async move {
            let result =
                stream_handler(packet, stream).await;

            console_warn!(
                "Stream handler finished: {:?}",
                result
            );

            connected_vec
                .lock()
                .await
                .retain(|x| *x != stream_ident);
        });
    }

    console_warn!("Wisp stream loop ended");

    Ok(())
}

// Cloudflare Worker entry point
#[event(fetch)]
async fn main(
    req: Request,
    env: Env,
    _ctx: Context,
) -> Result<Response> {

    // NEW: Temporary health-check endpoint
    // Does not affect existing WebSocket connections.
    if req.path() == "/health" {
        console_log!("HEALTH CHECK REACHED");

        return Response::ok(
            "WISP_WORKER_HEALTH_OK_V1"
        );
    }

    let upgrade = req
        .headers()
        .get("Upgrade")?
        .unwrap_or_default();

    if !upgrade.eq_ignore_ascii_case("websocket") {
        return Ok(
            Response::from_body(
                ResponseBody::Body(
                    include_bytes!("426.jpg").to_vec()
                )
            )?
            .with_status(426)
            .with_headers(
                Headers::from_iter(
                    [("Content-Type", "image/jpeg")]
                        .into_iter(),
                ),
            ),
        );
    }

    console_log!("Incoming WebSocket upgrade");

    let pair = WebSocketPair::new()?;

    pair.server.accept()?;

    let server = pair.server;

    spawn_local(async move {
        if let Err(error) =
            ws_handler(
                server.as_ref().clone(),
                env
            )
            .await
        {
            console_warn!(
                "WebSocket handler failed: {:?}",
                error
            );
        }
    });

    Response::from_websocket(pair.client)
}
