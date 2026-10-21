//! Persistent node identity.
//!
//! Capabilities are granted to a PeerId, so the key behind it must survive
//! restarts. The key is stored as the libp2p protobuf encoding of an Ed25519
//! keypair, with mode 0600. A file that exists but cannot be read, has loose
//! permissions or does not decode is an error: the key is never replaced
//! silently, because that would quietly invalidate every granted capability.

use cleimesh_core::Result;
use libp2p::identity::{Keypair, PublicKey};
use libp2p::PeerId;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// File name of the identity used by `cleimesh start`.
pub const NODE_KEY_FILE: &str = "identity.key";
/// File name of the identity used by one-shot clients such as `cleimesh invoke`.
pub const CLIENT_KEY_FILE: &str = "client.key";

/// `<config dir>/cleimesh/<file_name>`, e.g. `~/.config/cleimesh/identity.key`.
pub fn default_key_path(file_name: &str) -> Option<PathBuf> {
    directories::ProjectDirs::from("", "", "cleimesh").map(|dirs| dirs.config_dir().join(file_name))
}

/// Loads the keypair at `path`, or generates and stores a new Ed25519 one if
/// the file does not exist.
pub fn load_or_generate(path: &Path) -> Result<Keypair> {
    match fs::read(path) {
        Ok(bytes) => {
            check_permissions(path)?;
            // Decoding an Ed25519 keypair also checks that the public half
            // matches the secret half.
            Keypair::from_protobuf_encoding(&bytes).map_err(|e| {
                anyhow::anyhow!("Node identity {} is corrupt ({}); refusing to replace it", path.display(), e).into()
            })
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let keypair = Keypair::generate_ed25519();
            store(path, &keypair)?;
            tracing::info!("Generated node identity at {}", path.display());
            Ok(keypair)
        }
        Err(e) => Err(anyhow::anyhow!("Cannot read node identity {}: {}", path.display(), e).into()),
    }
}

/// The keypair as an Ed25519 signing key for AATs: the same key signs a
/// node's root tokens, or a holder's derivations and proofs of possession.
pub fn aat_signing_key(keypair: &Keypair) -> Result<cleimesh_aat::SigningKey> {
    let ed25519 = keypair.clone().try_into_ed25519().map_err(|_| anyhow::anyhow!("key is not Ed25519"))?;
    let secret: [u8; 32] = ed25519.secret().as_ref().try_into().map_err(|_| anyhow::anyhow!("bad Ed25519 secret length"))?;
    Ok(cleimesh_aat::SigningKey::from_bytes(&secret))
}

/// The AAT holder key behind an Ed25519 PeerId, which embeds its public
/// key: a token for that PeerId is held by whoever has its key file.
pub fn holder_jwk(peer: &PeerId) -> Result<cleimesh_aat::Jwk> {
    let not_ed25519 = || anyhow::anyhow!("PeerId {} does not embed an Ed25519 key", peer);
    let public = PublicKey::try_decode_protobuf(peer.as_ref().digest()).map_err(|_| not_ed25519())?;
    let ed25519 = public.try_into_ed25519().map_err(|_| not_ed25519())?;
    let key = cleimesh_aat::VerifyingKey::from_bytes(&ed25519.to_bytes()).map_err(|_| not_ed25519())?;
    Ok(cleimesh_aat::Jwk::from_key(&key))
}

/// Writes the key to a temporary file created with mode 0600, then renames it
/// into place, so a crash never leaves a half-written key behind.
fn store(path: &Path, keypair: &Keypair) -> Result<()> {
    let bytes = keypair
        .to_protobuf_encoding()
        .map_err(|e| anyhow::anyhow!("Cannot encode node identity: {}", e))?;
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)
            .map_err(|e| anyhow::anyhow!("Cannot create {}: {}", dir.display(), e))?;
    }

    let tmp = path.with_extension("key.tmp");
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let write = || -> std::io::Result<()> {
        let mut file = options.open(&tmp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&tmp, path)
    };
    write().map_err(|e| {
        let _ = fs::remove_file(&tmp);
        anyhow::anyhow!("Cannot write node identity {}: {}", path.display(), e).into()
    })
}

#[cfg(unix)]
fn check_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path)
        .map_err(|e| anyhow::anyhow!("Cannot stat node identity {}: {}", path.display(), e))?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        return Err(anyhow::anyhow!(
            "Node identity {} is accessible by other users (mode {:o}); run `chmod 600` on it",
            path.display(),
            mode & 0o777
        )
        .into());
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_permissions(_path: &Path) -> Result<()> {
    Ok(())
}
