use chacha20::{cipher::StreamCipher, ChaCha20};
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, ChaChaPoly1305, KeyInit};
use x25519_dalek::{PublicKey, StaticSecret};

// for early_kdf
const INITIAL_ENCRYPTION_KEY_INFO: &str = "initial_encryption_key";
const SERVER_EPHEMERAL_PUBLIC_KEY_MAC_KEY_INFO: &str = "server_ephemeral_public_key_mac_key";

// for session_kdf
const S2C_STREAM_KEY_INFO: &str = "s2c_stream_key";
const C2S_STREAM_KEY_INFO: &str = "c2s_stream_key";

pub struct MorfPeer {
  tx_cipher: Option<ChaCha20Poly1305>,
  rx_cipher: Option<ChaCha20Poly1305>,
  client_handshake_state: Option<ClientHandshakeState>,
  tx_counter: u16,
  rx_counter: u16,
}

struct ClientHandshakeState {
  ephemeral_secret: StaticSecret,
  server_ephemeral_key_mac_key: [u8; 32],
}

#[derive(Clone)]
pub struct UnauthenticatedClientHandshake {
  pub device_static_public_key_hash: [u8; 16],

  pub server_ephemeral_public_key: PublicKey,
  pub server_ephemeral_secret_key: StaticSecret,
  pub client_ephemeral_public_key: PublicKey,
}

impl UnauthenticatedClientHandshake {
  pub fn authenticate(self, device_static_public_key: &PublicKey, peer: &mut MorfPeer) {
    let mut session_key_material = [0u8; 64];
    session_key_material[0..32].copy_from_slice(
      self
        .server_ephemeral_secret_key
        .diffie_hellman(device_static_public_key)
        .as_bytes(),
    );
    session_key_material[32..64].copy_from_slice(
      self
        .server_ephemeral_secret_key
        .diffie_hellman(&self.client_ephemeral_public_key)
        .as_bytes(),
    );

    let tx_stream_key: [u8; 32] = blake3::derive_key(S2C_STREAM_KEY_INFO, &session_key_material);
    let rx_stream_key: [u8; 32] = blake3::derive_key(C2S_STREAM_KEY_INFO, &session_key_material);

    assert!(peer.tx_cipher.is_none() && peer.rx_cipher.is_none());
    assert!(peer.client_handshake_state.is_none());

    peer.tx_cipher = Some(ChaChaPoly1305::new(&tx_stream_key.into()));
    peer.rx_cipher = Some(ChaChaPoly1305::new(&rx_stream_key.into()));
  }
}

impl MorfPeer {
  pub fn client_initiate_handshake(
    ephemeral_secret: [u8; 32],
    server_public_key: &PublicKey,
    device_static_public_key: &PublicKey,
  ) -> (Self, impl AsMut<[u8]> + AsRef<[u8]>) {
    let ephemeral_secret = StaticSecret::from(ephemeral_secret);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);
    let early_key_material = ephemeral_secret.diffie_hellman(server_public_key);

    let initial_encryption_key: [u8; 32] =
      blake3::derive_key(INITIAL_ENCRYPTION_KEY_INFO, early_key_material.as_bytes());
    let mut init_cipher = <ChaCha20 as chacha20::cipher::KeyIvInit>::new(
      &initial_encryption_key.into(),
      &[0u8; 12].into(),
    );

    let device_static_public_key_hash =
      &mut (<[u8; 32]>::from(blake3::hash(device_static_public_key.as_bytes())))[..16];
    init_cipher.apply_keystream(device_static_public_key_hash);

    let mut output = [0u8; 49];
    output[0] = 3;
    output[1..33].copy_from_slice(ephemeral_public.as_bytes());
    output[33..49].copy_from_slice(&device_static_public_key_hash);

    let server_ephemeral_key_mac_key = blake3::derive_key(
      SERVER_EPHEMERAL_PUBLIC_KEY_MAC_KEY_INFO,
      early_key_material.as_bytes(),
    );

    (
      Self {
        tx_cipher: None,
        rx_cipher: None,
        client_handshake_state: Some(ClientHandshakeState {
          ephemeral_secret,
          server_ephemeral_key_mac_key,
        }),
        tx_counter: 0,
        rx_counter: 0,
      },
      output,
    )
  }

  pub fn server_accept_handshake(
    ephemeral_secret: [u8; 32],
    static_secret: &StaticSecret,
    packet: &[u8],
  ) -> Result<
    (
      Self,
      UnauthenticatedClientHandshake,
      impl AsMut<[u8]> + AsRef<[u8]>,
    ),
    (),
  > {
    if packet.len() != 49 || packet[0] != 3 {
      return Err(());
    }

    let client_ephemeral_public_key =
      PublicKey::from(<[u8; 32]>::try_from(&packet[1..33]).unwrap());
    let mut device_static_public_key_hash: [u8; 16] = packet[33..49].try_into().unwrap();

    let ephemeral_secret = StaticSecret::from(ephemeral_secret);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);

    let early_key_material = static_secret.diffie_hellman(&client_ephemeral_public_key);

    let mut init_cipher = <ChaCha20 as chacha20::cipher::KeyIvInit>::new(
      &blake3::derive_key(INITIAL_ENCRYPTION_KEY_INFO, early_key_material.as_bytes()).into(),
      &[0u8; 12].into(),
    );

    init_cipher.apply_keystream(&mut device_static_public_key_hash);

    // Derive the MAC key for server ephemeral public key
    let server_ephemeral_key_mac_key = blake3::derive_key(
      SERVER_EPHEMERAL_PUBLIC_KEY_MAC_KEY_INFO,
      early_key_material.as_bytes(),
    );
    let mut output = [0u8; 49];
    output[0] = 1;
    output[1..33].copy_from_slice(ephemeral_public.as_bytes());
    output[33..49].copy_from_slice(
      &blake3::keyed_hash(&server_ephemeral_key_mac_key, ephemeral_public.as_bytes()).as_bytes()
        [..16],
    );

    Ok((
      Self {
        tx_cipher: None,
        rx_cipher: None,
        client_handshake_state: None,
        tx_counter: 0,
        rx_counter: 0,
      },
      UnauthenticatedClientHandshake {
        device_static_public_key_hash,
        server_ephemeral_public_key: ephemeral_public,
        server_ephemeral_secret_key: ephemeral_secret,
        client_ephemeral_public_key,
      },
      output,
    ))
  }

  pub fn client_finalize_handshake(
    &mut self,
    device_static_secret_key: &StaticSecret,
    packet: &[u8],
  ) -> Result<(), ()> {
    if packet.len() != 49 || packet[0] != 1 {
      return Err(());
    }

    let Some(st) = &self.client_handshake_state else {
      return Err(());
    };

    if !constant_time_eq::constant_time_eq(
      &blake3::keyed_hash(&st.server_ephemeral_key_mac_key, &packet[1..33]).as_bytes()[..16],
      &packet[33..49],
    ) {
      return Err(());
    }

    // at this point the packet is authenticated

    let server_ephemeral_public_key =
      PublicKey::from(<[u8; 32]>::try_from(&packet[1..33]).unwrap());

    let mut session_key_material = [0u8; 64];
    session_key_material[0..32].copy_from_slice(
      device_static_secret_key
        .diffie_hellman(&server_ephemeral_public_key)
        .as_bytes(),
    );
    session_key_material[32..64].copy_from_slice(
      st.ephemeral_secret
        .diffie_hellman(&server_ephemeral_public_key)
        .as_bytes(),
    );

    let tx_stream_key: [u8; 32] = blake3::derive_key(C2S_STREAM_KEY_INFO, &session_key_material);
    let rx_stream_key: [u8; 32] = blake3::derive_key(S2C_STREAM_KEY_INFO, &session_key_material);

    self.tx_cipher = Some(ChaChaPoly1305::new(&tx_stream_key.into()));
    self.rx_cipher = Some(ChaChaPoly1305::new(&rx_stream_key.into()));
    self.client_handshake_state = None;

    Ok(())
  }

  pub fn unseal<'a>(&mut self, packet: &'a mut [u8]) -> Result<&'a mut [u8], ()> {
    let Some(rx_cipher) = &self.rx_cipher else {
      return Err(());
    };
    if packet.len() < 19 || packet[0] != 2 {
      return Err(());
    }

    let packet_len = packet.len();

    let untrusted_counter = u16::from_be_bytes(packet[1..3].try_into().unwrap());
    let tag = <[u8; 16]>::try_from(&packet[packet_len - 16..]).unwrap();
    let content = &mut packet[3..packet_len - 16];

    if untrusted_counter <= self.rx_counter {
      return Err(());
    }

    let mut nonce = [0u8; 12];
    nonce[10..12].copy_from_slice(&untrusted_counter.to_be_bytes());

    rx_cipher
      .decrypt_in_place_detached(&nonce.into(), &[], content, &tag.into())
      .map_err(|_| ())?;

    self.rx_counter = untrusted_counter;
    Ok(content)
  }

  pub fn seal(&mut self, packet: &mut [u8]) -> Result<([u8; 3], [u8; 16]), ()> {
    let Some(tx_cipher) = &self.tx_cipher else {
      return Err(());
    };

    let next_counter = match self.tx_counter.checked_add(1) {
      Some(next_counter) => next_counter,
      None => return Err(()),
    };
    self.tx_counter = next_counter;

    let mut nonce = [0u8; 12];
    nonce[10..12].copy_from_slice(&self.tx_counter.to_be_bytes());
    let tag = tx_cipher
      .encrypt_in_place_detached(&nonce.into(), &[], packet)
      .unwrap();

    let mut prefix = [0u8; 3];
    prefix[0] = 2;
    prefix[1..3].copy_from_slice(&self.tx_counter.to_be_bytes());
    Ok((prefix, tag.into()))
  }
}
