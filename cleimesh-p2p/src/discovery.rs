use libp2p::{
    kad::{self, store::MemoryStore},
    gossipsub::{self},
    PeerId,
    Multiaddr,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use crate::protocol::{AgentProtocol, MeshMessage};

pub struct MeshDiscovery {
    kad: kad::Behaviour<MemoryStore>,
    gossipsub: gossipsub::Behaviour,
    local_agent: AgentProtocol,
    known_agents: Arc<RwLock<HashMap<PeerId, AgentProtocol>>>,
}

impl MeshDiscovery {
    pub fn new(local_agent: AgentProtocol) -> Self {
        let kad = kad::Behaviour::new(
            local_agent.agent_id.parse().unwrap_or_else(|_| PeerId::random()), 
            MemoryStore::new(local_agent.agent_id.parse().unwrap_or_else(|_| PeerId::random()))
        );
        
        let gossipsub = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Anonymous,
            gossipsub::ConfigBuilder::default().build().expect("valid config"),
        ).expect("valid gossipsub");

        Self {
            kad,
            gossipsub,
            local_agent,
            known_agents: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn announce(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let msg = MeshMessage::Announcement(crate::protocol::AgentAnnouncement {
            agent: self.local_agent.clone(),
            ttl: 300,
        });
        
        let topic = gossipsub::IdentTopic::new(msg.topic());
        self.gossipsub.subscribe(&topic)?;
        self.gossipsub.publish(topic, serde_json::to_vec(&msg)?)?;
        Ok(())
    }

    pub async fn find_agents_with_capability(&mut self, capability: &str) -> Vec<PeerId> {
        let agents = self.known_agents.read().await;
        agents.iter()
            .filter(|(_, agent)| agent.capabilities.iter().any(|c| c == capability))
            .map(|(peer_id, _)| *peer_id)
            .collect()
    }

    pub async fn delegate_task(&mut self, _peer: PeerId, task: crate::protocol::TaskDelegation) -> Result<(), Box<dyn std::error::Error>> {
        let msg = MeshMessage::Delegation(task);
        let topic = gossipsub::IdentTopic::new(msg.topic());
        self.gossipsub.publish(topic, serde_json::to_vec(&msg)?)?;
        Ok(())
    }

    pub fn on_agent_announcement(&mut self, peer: PeerId, agent: AgentProtocol) {
        let mut agents = self.known_agents.blocking_write();
        agents.insert(peer, agent.clone());
        
        if let Ok(addr) = agent.agent_id.parse::<Multiaddr>() {
            self.kad.add_address(&peer, addr);
        }
    }

    pub fn on_capability_query(&mut self, _peer: PeerId, _requester_id: String, _capabilities: Vec<String>) {
        let response = MeshMessage::CapabilityResponse { 
            responder_id: self.local_agent.agent_id.clone(), 
            capabilities: self.local_agent.capabilities.clone() 
        };
        
        let msg = response;
        let topic = gossipsub::IdentTopic::new(msg.topic());
        let _ = self.gossipsub.publish(topic, serde_json::to_vec(&msg).unwrap_or_default());
    }

    pub fn bootstrap(&mut self) {
        self.kad.bootstrap().ok();
    }
}