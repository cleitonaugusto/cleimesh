use libp2p::{
    connection_limits::{self, ConnectionLimits},
    kad::{self, store::MemoryStore},
    gossipsub,
    identify,
    ping,
    relay,
    request_response::{self, ProtocolSupport},
    swarm::NetworkBehaviour,
};
use std::time::Duration;
use libp2p::futures::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "CleiMeshEvent")]
pub struct CleiMeshBehaviour {
    pub kad: kad::Behaviour<MemoryStore>,
    pub gossipsub: gossipsub::Behaviour,
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
    pub relay: relay::Behaviour,
    pub request_response: request_response::Behaviour<ToolCodec>,
    pub limits: connection_limits::Behaviour,
}

/// Largest tool request a peer may send: arguments plus the delegation chain
/// (S11). The length prefix is checked before anything
/// is allocated.
pub const MAX_REQUEST_BYTES: usize = 1024 * 1024;
/// Largest tool response; a bigger output is answered with an error.
pub const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
/// Calls one peer may have running on this node at once.
pub const MAX_IN_FLIGHT_PER_PEER: usize = 4;
/// Connections one peer may keep open, so the per-connection stream limit
/// below also bounds what a single peer can make the node buffer.
const MAX_CONNECTIONS_PER_PEER: u32 = 2;

#[derive(Debug)]
pub enum CleiMeshEvent {
    Kad(kad::Event),
    Gossipsub(gossipsub::Event),
    Identify(identify::Event),
    Ping(ping::Event),
    Relay(relay::Event),
    RequestResponse(request_response::Event<ToolRequest, ToolResponse>),
}

impl From<kad::Event> for CleiMeshEvent {
    fn from(event: kad::Event) -> Self {
        CleiMeshEvent::Kad(event)
    }
}

impl From<gossipsub::Event> for CleiMeshEvent {
    fn from(event: gossipsub::Event) -> Self {
        CleiMeshEvent::Gossipsub(event)
    }
}

impl From<identify::Event> for CleiMeshEvent {
    fn from(event: identify::Event) -> Self {
        CleiMeshEvent::Identify(event)
    }
}

impl From<ping::Event> for CleiMeshEvent {
    fn from(event: ping::Event) -> Self {
        CleiMeshEvent::Ping(event)
    }
}

impl From<relay::Event> for CleiMeshEvent {
    fn from(event: relay::Event) -> Self {
        CleiMeshEvent::Relay(event)
    }
}

impl From<std::convert::Infallible> for CleiMeshEvent {
    fn from(event: std::convert::Infallible) -> Self {
        match event {}
    }
}

impl From<request_response::Event<ToolRequest, ToolResponse>> for CleiMeshEvent {
    fn from(event: request_response::Event<ToolRequest, ToolResponse>) -> Self {
        CleiMeshEvent::RequestResponse(event)
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ToolRequest {
    pub tool_name: String,
    pub payload: serde_json::Value,
    pub request_id: String,
    /// Capability the client presents for this call. Without one, the node
    /// looks for a matching capability it stored itself.
    #[serde(default)]
    pub capability: Option<crate::auth::Capability>,
    /// AAT delegation chain and proof of possession for this call
    /// (S4). Exclusive with `capability`.
    #[serde(default)]
    pub presentation: Option<cleimesh_aat::Presentation>,
    /// Who the call's data is about and why (C3),
    /// recorded in its receipts as a keyed pseudonym and a purpose.
    #[serde(default)]
    pub context: Option<crate::receipts::CallContext>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ToolResponse {
    pub request_id: String,
    pub success: bool,
    pub output: serde_json::Value,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ToolCodec;

impl request_response::Codec for ToolCodec {
    type Protocol = String;
    type Request = ToolRequest;
    type Response = ToolResponse;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_frame(io, MAX_REQUEST_BYTES).await
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_frame(io, MAX_RESPONSE_BYTES).await
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> std::io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_frame(io, &req, MAX_REQUEST_BYTES).await
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> std::io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_frame(io, &res, MAX_RESPONSE_BYTES).await
    }
}

/// Reads one length-prefixed JSON frame, refusing a length above `max`
/// before allocating for it.
async fn read_frame<T, M>(io: &mut T, max: usize) -> std::io::Result<M>
where
    T: AsyncRead + Unpin + Send,
    M: serde::de::DeserializeOwned,
{
    let mut len_buf = [0u8; 8];
    io.read_exact(&mut len_buf).await?;
    let len = u64::from_be_bytes(len_buf);
    if len > max as u64 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("frame of {} bytes, limit is {}", len, max)));
    }
    let mut buf = vec![0u8; len as usize];
    io.read_exact(&mut buf).await?;
    serde_json::from_slice(&buf).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// Writes one length-prefixed JSON frame; the peer would refuse one above `max`.
async fn write_frame<T, M>(io: &mut T, message: &M, max: usize) -> std::io::Result<()>
where
    T: AsyncWrite + Unpin + Send,
    M: serde::Serialize,
{
    let data = serde_json::to_vec(message).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    if data.len() > max {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("frame of {} bytes, limit is {}", data.len(), max)));
    }
    io.write_all(&(data.len() as u64).to_be_bytes()).await?;
    io.write_all(&data).await?;
    Ok(())
}

impl CleiMeshBehaviour {
    /// Builds every sub-protocol on the node's own key, so Kademlia, Identify
    /// and Relay advertise the same PeerId that Noise authenticates.
    pub fn new(keypair: &libp2p::identity::Keypair, request_timeout: Duration) -> Self {
        let local_peer_id = keypair.public().to_peer_id();
        let kad = kad::Behaviour::new(
            local_peer_id,
            MemoryStore::new(local_peer_id),
        );

        // Signed messages: with the default (strict) validation, gossipsub
        // rejects an anonymous config outright.
        let gossipsub = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(keypair.clone()),
            gossipsub::ConfigBuilder::default()
                .max_transmit_size(1024 * 1024)
                .build()
                .expect("valid gossipsub config"),
        ).expect("valid gossipsub");

        let identify = identify::Behaviour::new(
            identify::Config::new("/cleimesh/1.0.0".to_string(), keypair.public())
                .with_interval(Duration::from_secs(30)),
        );

        let ping = ping::Behaviour::new(ping::Config::new().with_interval(Duration::from_secs(10)));

        let relay = relay::Behaviour::new(local_peer_id, Default::default());

        let request_response = request_response::Behaviour::new(
            [(String::from("/cleimesh/tool/1.0.0"), ProtocolSupport::Full)],
            // A few streams beyond the in-flight limit, so the node's own
            // refusal (with a reason) is what a busy peer usually sees.
            request_response::Config::default()
                .with_request_timeout(request_timeout)
                .with_max_concurrent_streams(4 * MAX_IN_FLIGHT_PER_PEER),
        );
        let limits = connection_limits::Behaviour::new(
            ConnectionLimits::default().with_max_established_per_peer(Some(MAX_CONNECTIONS_PER_PEER)),
        );

        Self {
            kad,
            gossipsub,
            identify,
            ping,
            relay,
            request_response,
            limits,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::futures::io::Cursor;

    #[tokio::test]
    async fn a_frame_round_trips() {
        let mut wire = Cursor::new(Vec::new());
        write_frame(&mut wire, &serde_json::json!({"message": "hello"}), 1024).await.unwrap();
        wire.set_position(0);
        let read: serde_json::Value = read_frame(&mut wire, 1024).await.unwrap();
        assert_eq!(read, serde_json::json!({"message": "hello"}));
    }

    // Before S11 the length prefix was trusted: u64::MAX made the node try
    // to allocate that much before reading a single byte of the body.
    #[tokio::test]
    async fn an_oversized_length_is_refused_before_allocating() {
        let mut wire = Cursor::new(u64::MAX.to_be_bytes().to_vec());
        let error = read_frame::<_, serde_json::Value>(&mut wire, MAX_REQUEST_BYTES).await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("limit is"), "{error}");
    }

    #[tokio::test]
    async fn a_frame_over_the_limit_is_not_written() {
        let mut wire = Cursor::new(Vec::new());
        let error = write_frame(&mut wire, &"x".repeat(2048), 1024).await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(wire.get_ref().is_empty(), "nothing should reach the wire");
    }
}
