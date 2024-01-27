use base64::Engine;
use rand::{Rng, SeedableRng};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::peer::MorfPeer;

#[test]
fn roundtrip() {
  let server_secret = StaticSecret::from(rand::thread_rng().gen::<[u8; 32]>());
  let server_public = PublicKey::from(&server_secret);

  let device_static_secret_key = StaticSecret::from(rand::thread_rng().gen::<[u8; 32]>());
  let device_static_public_key = PublicKey::from(&device_static_secret_key);

  let (mut client, handshake_packet) = MorfPeer::client_initiate_handshake(
    rand::thread_rng().gen(),
    &server_public,
    &device_static_public_key,
  );
  let (mut server, handshake_info, handshake_packet) = MorfPeer::server_accept_handshake(
    rand::thread_rng().gen(),
    &server_secret,
    handshake_packet.as_ref(),
  )
  .unwrap();

  // Device static public key hash should match
  assert_eq!(
    blake3::hash(device_static_public_key.as_bytes()).as_bytes()[..16],
    handshake_info.device_static_public_key_hash[..]
  );

  // Server should refuse to encrypt or decrypt anything before finalizing handshake
  assert!(server.seal(&mut [0]).is_err());
  assert!(server.unseal(&mut [2u8; 30]).is_err());

  // Finalize auth on server side
  handshake_info.authenticate(&device_static_public_key, &mut server);

  // Client should refuse to encrypt or decrypt anything before finalizing handshake
  assert!(client.seal(&mut [0]).is_err());
  assert!(client.unseal(&mut [2u8; 30]).is_err());

  // Finalize client handshake
  client
    .client_finalize_handshake(&device_static_secret_key, handshake_packet.as_ref())
    .unwrap();

  // Packets encrypted by client should be readable by server
  {
    let mut packet = Vec::from(b"test");
    let (prefix, tag) = client.seal(&mut packet).unwrap();
    let full_packet = [&prefix[..], &packet[..], &tag[..]].concat();
    assert_eq!(server.unseal(&mut full_packet.clone()).unwrap(), b"test");
    // same-session replay protection
    assert!(server.unseal(&mut full_packet.clone()).is_err());
  }

  // Packets encrypted by server should be readable by client
  {
    let mut packet = Vec::from(b"test");
    let (prefix, tag) = server.seal(&mut packet).unwrap();
    let full_packet = [&prefix[..], &packet[..], &tag[..]].concat();
    assert_eq!(client.unseal(&mut full_packet.clone()).unwrap(), b"test");
    // same-session replay protection
    assert!(client.unseal(&mut full_packet.clone()).is_err());
  }
}

#[test]
fn check_ciphertext() {
  let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(0);
  let server_secret = StaticSecret::from(rng.gen::<[u8; 32]>());
  let server_public = PublicKey::from(&server_secret);

  let device_static_secret_key = StaticSecret::from(rng.gen::<[u8; 32]>());
  let device_static_public_key = PublicKey::from(&device_static_secret_key);

  let (mut client, client_handshake_packet) =
    MorfPeer::client_initiate_handshake(rng.gen(), &server_public, &device_static_public_key);
  let (mut server, handshake_info, server_handshake_packet) =
    MorfPeer::server_accept_handshake(rng.gen(), &server_secret, client_handshake_packet.as_ref())
      .unwrap();
  let handshake_info_device_static_public_key_hash = handshake_info.device_static_public_key_hash;
  handshake_info.authenticate(&device_static_public_key, &mut server);
  client
    .client_finalize_handshake(&device_static_secret_key, server_handshake_packet.as_ref())
    .unwrap();

  let mut packet = Vec::from(b"test");
  let (prefix, tag) = client.seal(&mut packet).unwrap();
  let full_packet_1 = [&prefix[..], &packet[..], &tag[..]].concat();

  let mut packet = Vec::from(b"test");
  let (prefix, tag) = client.seal(&mut packet).unwrap();
  let full_packet_2 = [&prefix[..], &packet[..], &tag[..]].concat();

  let mut packet = Vec::from(b"test");
  let (prefix, tag) = server.seal(&mut packet).unwrap();
  let full_packet_3 = [&prefix[..], &packet[..], &tag[..]].concat();

  let mut packet = Vec::from(b"test");
  let (prefix, tag) = server.seal(&mut packet).unwrap();
  let full_packet_4 = [&prefix[..], &packet[..], &tag[..]].concat();

  assert_eq!(
    base64::engine::general_purpose::STANDARD.encode(client_handshake_packet.as_ref()),
    "A8gHzXTONYbJ9tR2d0U1v0P36c7k/xFKWxLRl28fSh42HZP1NITDbdHqzOB94AdOWw=="
  );
  assert_eq!(
    base64::engine::general_purpose::STANDARD.encode(handshake_info_device_static_public_key_hash),
    "rQi7K0plwLPeAb2ZnkjMxw=="
  );
  assert_eq!(
    base64::engine::general_purpose::STANDARD.encode(server_handshake_packet.as_ref()),
    "ATo0uXENMCyX+aOeGs5uH1B4QHTWWHYI+hO9zrvHeng11WjF8G12OauH2cynIOKFhw=="
  );
  assert_eq!(
    base64::engine::general_purpose::STANDARD.encode(&full_packet_1),
    "AgABuykflVCnNcq9Pie2G976UXLoeYc="
  );
  assert_eq!(
    base64::engine::general_purpose::STANDARD.encode(&full_packet_2),
    "AgACuRkGyABHk7AKWqbfZc48iOo33y0="
  );
  assert_eq!(
    base64::engine::general_purpose::STANDARD.encode(&full_packet_3),
    "AgABbamXk6yAc0YeHbkQvO77wgE/SHQ="
  );
  assert_eq!(
    base64::engine::general_purpose::STANDARD.encode(&full_packet_4),
    "AgAC5ryo5+VtCn8EwwEE2Ww7NecmksQ="
  );
}
