use anyhow::anyhow;
use byteorder::{ByteOrder, NetworkEndian, ReadBytesExt, WriteBytesExt};
use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use rand::{rngs::ThreadRng, Rng, RngCore};
use sha1::Sha1;

use std::{
    cell::RefCell,
    fmt::Debug,
    io::{BufRead, Cursor, Read, Seek, SeekFrom::Current, Write},
    net::{
        IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr,
        SocketAddr::{V4, V6},
        UdpSocket,
    },
    rc::Rc,
    time::{Duration, Instant},
};

const COOKIE: u32 = 0x2112A442;
const COOKIE_MOST_SIGNIFICANT: u16 = 0x2112;

const BIND: u16 = 1;
const ALLOCATE: u16 = 3;
const REFRESH: u16 = 4;
const SEND: u16 = 6;
const DATA: u16 = 7;
const CREATE_PERM: u16 = 8;
const CHANNEL_BIND: u16 = 9;

const CLASS_MASK: u16 = 0x110;

const CLASS_REQUEST: u16 = 0x000;
const CLASS_INDICATION: u16 = 0x010;
const CLASS_SUCCESS: u16 = 0x100;
const CLASS_FAILURE: u16 = 0x110;

const ATTRIBUTE_MAPPED: u16 = 0x0001;
const ATTRIBUTE_USERNAME: u16 = 0x0006;
const ATTRIBUTE_MESSAGE_INTEGRITY: u16 = 0x0008;
const ATTRIBUTE_ERROR: u16 = 0x0009;
const ATTRIBUTE_LIFETIME: u16 = 0x000D;
const ATTRIBUTE_XOR_PEER: u16 = 0x0012;
const ATTRIBUTE_DATA: u16 = 0x0013;
const ATTRIBUTE_REALM: u16 = 0x0014;
const ATTRIBUTE_NONCE: u16 = 0x0015;
const ATTRIBUTE_XOR_RELAYED: u16 = 0x0016;
const ATTRIBUTE_REQUESTED_TRANSPORT: u16 = 0x0019;
const ATTRIBUTE_XOR_MAPPED: u16 = 0x0020;

const STUB_LEN: usize = 8;

fn bind_pls() -> Message {
    let mut message = Message::default();
    message.class = CLASS_REQUEST;
    message.method = BIND;
    ThreadRng::default().fill_bytes(&mut message.transaction_id);
    message
}

fn allocate_pls() -> Message {
    let mut message = Message::default();
    message.class = CLASS_REQUEST;
    message.method = ALLOCATE;
    message.requested_transport = Some(17); // IPPROTO_UDP

    ThreadRng::default().fill_bytes(&mut message.transaction_id);
    message
}

fn refresh_pls() -> Message {
    let mut message = Message::default();
    message.class = CLASS_REQUEST;
    message.method = REFRESH;

    ThreadRng::default().fill_bytes(&mut message.transaction_id);
    message
}

fn permission_pls() -> Message {
    let mut message = Message::default();
    message.class = CLASS_REQUEST;
    message.method = CREATE_PERM;

    ThreadRng::default().fill_bytes(&mut message.transaction_id);
    message
}

fn send_data_pls() -> Message {
    let mut message = Message::default();
    message.class = CLASS_INDICATION;
    message.method = SEND;

    ThreadRng::default().fill_bytes(&mut message.transaction_id);
    message
}

#[derive(Debug)]
pub enum SocketHandle {
    Udp(Rc<RefCell<(Option<SocketAddr>, UdpSocket)>>),
    Turn(Rc<RefCell<TurnClient>>),
}

impl SocketHandle {
    fn send_to(&self, buf: &[u8], addr: SocketAddr) -> anyhow::Result<usize> {
        match self {
            SocketHandle::Udp(socket) => Ok(socket.borrow().1.send_to(buf, addr)?),
            SocketHandle::Turn(socket) => Ok(socket.borrow().send_to(buf, addr)?),
        }
    }

    fn recv_from(&self, buf: &mut [u8]) -> anyhow::Result<(usize, SocketAddr)> {
        match self {
            SocketHandle::Udp(socket) => Ok(socket.borrow().1.recv_from(buf)?),
            SocketHandle::Turn(socket) => Ok(socket.borrow().recv_from(buf)?),
        }
    }

    pub fn relay_addr(&self) -> Option<SocketAddr> {
        match self {
            SocketHandle::Udp(socket) => socket.borrow().0.clone(),
            SocketHandle::Turn(socket) => socket.borrow().relay_addr,
        }
    }

    pub fn set_relay_addr(&self, addr: SocketAddr) {
        match self {
            SocketHandle::Udp(socket) => socket.borrow_mut().0 = Some(addr),
            SocketHandle::Turn(_socket) => unimplemented!(),
        }
    }

    pub fn reflexive_addr(&self) -> Option<SocketAddr> {
        match self {
            SocketHandle::Udp(socket) => socket.borrow().0.clone(),
            SocketHandle::Turn(socket) => socket.borrow().reflexive_addr,
        }
    }

    pub fn add_permission(&self, addr: SocketAddr) -> anyhow::Result<()> {
        match self {
            SocketHandle::Udp(_socket) => Ok(()),
            SocketHandle::Turn(socket) => socket.borrow_mut().add_permission(addr),
        }
    }

    pub fn allocate(&self) -> anyhow::Result<()> {
        match self {
            SocketHandle::Udp(_socket) => unimplemented!(),
            SocketHandle::Turn(socket) => socket.borrow_mut().allocate(),
        }
    }

    pub fn refresh(&self) -> anyhow::Result<()> {
        match self {
            SocketHandle::Udp(_socket) => Ok(()),
            SocketHandle::Turn(socket) => socket.borrow_mut().refresh(),
        }
    }

    pub fn relay_to_client_multiple(
        &self,
        recv_client: &SocketHandle,
        count: usize,
        size: usize,
    ) -> (usize, usize, usize, Vec<usize>) {
        // send response
        let mut found = vec![false; count];

        let mut rand = ThreadRng::default();
        let mut stub = [0 as u8; STUB_LEN];
        rand.fill_bytes(&mut stub);
        let min_length = STUB_LEN + 3;
        assert!(count < 256);
        assert!(min_length <= size);
        assert!(size <= 0xFFFF);
        for i in 0..count {
            let length = rand.gen_range(min_length..=size) as u16;
            let mut buf = Vec::with_capacity(length as usize);
            buf.extend(stub);
            buf.write_u16::<NetworkEndian>(length).unwrap();
            buf.resize(length.into(), i as u8);

            NetworkEndian::write_u16(&mut buf[STUB_LEN..STUB_LEN + 2], length as u16);
            let _ = self.send_to(&buf, recv_client.relay_addr().unwrap());
        }

        let mut buf = [0; 65536];

        let mut recv = 0;
        let mut recv_err = 0;
        let rtts = vec![];

        let mut left = count;

        while left > 0 {
            match recv_client.recv_from(&mut buf) {
                Ok((length, _)) => {
                    let buf = &buf[0..length];
                    left -= 1;
                    if length < min_length {
                        println!("rx too short");
                        recv_err += 1;
                    } else if buf[0..STUB_LEN] == stub {
                        let intended_length = NetworkEndian::read_u16(&buf[STUB_LEN..STUB_LEN + 2]);
                        if length < intended_length.into() {
                            println!("rx short");
                            recv_err += 1;
                        } else if length > intended_length.into() {
                            println!("rx long");
                            recv_err += 1;
                        } else {
                            let n = buf[STUB_LEN + 2];
                            let other_count = buf[STUB_LEN + 2..length]
                                .iter()
                                .filter(|x| **x != n)
                                .count();
                            if n as usize >= found.len() {
                                println!(
                                    "invalid value in buffer {} packet length {} {:?}",
                                    n, length, buf
                                );
                                recv_err += 1;
                            } else if other_count > 0 {
                                println!(
                                    "buffer isn't uniform {} values are not {}",
                                    other_count, n
                                );
                                recv_err += 1;
                            } else {
                                let n = n as usize;
                                if found[n] {
                                    println!("duplicate");
                                    recv_err += 1;
                                } else {
                                    recv += 1;
                                    found[n] = true;
                                }
                            }
                        }
                    } else {
                        println!("wrong batch");
                        recv_err += 1;
                    }
                }
                Err(_) => {
                    return (count, recv, recv_err, rtts);
                }
            }
        }
        (count, recv, recv_err, rtts)
    }

    pub fn relay_to_client(
        &self,
        recv_client: &SocketHandle,
    ) -> anyhow::Result<(Duration, SocketAddr)> {
        // send response
        let buf = [0x21]; // !
        let start = Instant::now();
        self.send_to(&buf, recv_client.relay_addr().unwrap())?;

        let mut buf = [0; 65536];
        let (_bytes, src) = recv_client.recv_from(&mut buf)?;

        let finish = Instant::now();
        let time = finish.duration_since(start);
        Ok((time, src))
    }

    pub fn send_from_peer(&self, peer: &SocketHandle) -> anyhow::Result<(Duration, SocketAddr)> {
        // send relay
        let buf = [0x21]; // !
        let start = Instant::now();
        peer.send_to(&buf, self.relay_addr().unwrap())?;

        let mut buf = [0; 65536];
        let (_bytes, src) = self.recv_from(&mut buf)?;

        let finish = Instant::now();
        let time = finish - start;
        Ok((time, src))
    }
}

#[derive(Debug)]
pub struct TurnClient {
    server: SocketAddr,
    username: String,
    password: String,
    nonce: Option<Vec<u8>>,
    realm: Option<String>,
    pub relay_addr: Option<SocketAddr>,
    pub reflexive_addr: Option<SocketAddr>,
    socket: SocketHandle,
}

impl TurnClient {
    pub fn new(socket: SocketHandle, server: SocketAddr, username: &str, password: &str) -> Self {
        TurnClient {
            server,
            username: username.to_owned(),
            password: password.to_owned(),
            nonce: None,
            realm: None,
            relay_addr: None,
            reflexive_addr: None,
            socket,
        }
    }

    pub fn allocate(&mut self) -> anyhow::Result<()> {
        // send unauthorized allocation --- will fail
        let mut request = allocate_pls();
        let buf = request.serialize();
        let start = Instant::now();
        self.socket.send_to(&buf, self.server)?;

        let mut buf = [0; 65536];
        let (bytes, src) = self.socket.recv_from(&mut buf)?;
        let finish = Instant::now();
        let time = finish.duration_since(start);
        let message = parse(None, &buf[0..bytes])?;

        if message.class != CLASS_FAILURE || message.error.unwrap_or(0) != 401 {
            println!(
                "unexpected response from first allocation {:?} {:?}: {:?}",
                time, src, message
            );
            unimplemented!();
        }

        // send authorized allocation --- should succeed
        let mut request = allocate_pls();
        request.username = Some(self.username.clone());
        request.password = Some(self.password.clone());

        self.realm = message.realm.to_owned();
        request.realm = message.realm;
        request.nonce = message.nonce;

        let buf = request.serialize();
        let start = Instant::now();
        self.socket.send_to(&buf, self.server)?;

        let mut buf = [0; 65536];
        let (bytes, src) = self.socket.recv_from(&mut buf)?;
        let finish = Instant::now();
        let time = finish.duration_since(start);
        let message = parse(Some(&request), &buf[0..bytes])?;

        if message.class != CLASS_SUCCESS || message.xor_relayed.is_none() {
            println!(
                "unexpected response from authorized allocation {:?} {:?}: {:?}",
                time, src, message
            );
            unimplemented!();
        }

        self.nonce = message.nonce;
        self.relay_addr = message.xor_relayed;
        self.reflexive_addr = message.xor_addr;
        Ok(())
    }

    pub fn refresh(&mut self) -> anyhow::Result<()> {
        let mut request = refresh_pls();
        request.username = Some(self.username.clone());
        request.password = Some(self.password.clone());
        request.realm = self.realm.clone();
        request.nonce = self.nonce.clone();

        let buf = request.serialize();
        let start = Instant::now();
        self.socket.send_to(&buf, self.server)?;

        let mut buf = [0; 65536];
        let (bytes, src) = self.socket.recv_from(&mut buf)?;
        let finish = Instant::now();
        let time = finish.duration_since(start);
        let message = parse(Some(&request), &buf[0..bytes])?;

        if message.class == CLASS_FAILURE && message.error.unwrap_or(0) == 438 {
            println!("nonce expired");
            self.nonce = message.nonce;
            return self.refresh();
        }

        if message.class != CLASS_SUCCESS {
            println!(
                "unexpected response from refresh {:?} {:?}: {:?}, {:?}",
                time, src, message, self
            );
            unimplemented!();
        }
        self.nonce = message.nonce;
        Ok(())
    }

    pub fn add_permission(&mut self, addr: SocketAddr) -> anyhow::Result<()> {
        // send permission request to allow our (reflexive) IP to send to us.
        let mut request = permission_pls();
        request.username = Some(self.username.clone());
        request.password = Some(self.password.clone());
        request.realm = self.realm.clone();
        request.nonce = self.nonce.clone();

        request.xor_peer.push(addr);

        let buf = request.serialize();
        let start = Instant::now();
        self.socket.send_to(&buf, self.server)?;

        let mut buf = [0; 65536];
        let (bytes, src) = self.socket.recv_from(&mut buf)?;
        let finish = Instant::now();
        let time = finish.duration_since(start);
        let message = parse(Some(&request), &buf[0..bytes])?;

        if message.class != CLASS_SUCCESS {
            println!(
                "unexpected response from create permission {:?} {:?}: {:?}",
                time, src, message
            );
            unimplemented!();
        }

        self.nonce = message.nonce;
        Ok(())
    }

    fn send_to(&self, buf: &[u8], addr: SocketAddr) -> anyhow::Result<usize> {
        let mut request = send_data_pls();
        request.data = Some(buf.to_vec());
        request.xor_peer = vec![addr];
        let orig_size = buf.len();
        let buf = request.serialize();
        let full_size = buf.len();
        let size = self.socket.send_to(&buf, self.server)?;
        Ok(size - (full_size - orig_size))
    }

    fn recv_from(&self, buf: &mut [u8]) -> anyhow::Result<(usize, SocketAddr)> {
        let (bytes, src) = self.socket.recv_from(buf)?;
        let message = parse(None, &buf[0..bytes])?;
        if message.class == CLASS_INDICATION && message.method == DATA {
            let data = message.data.unwrap();
            let len = data.len();
            buf[0..len].copy_from_slice(&data);
            Ok((len, message.xor_peer[0]))
        } else {
            println!("relayed? {:?}: {:?}", src, message);
            Err(anyhow!("unexpected relay"))
        }
    }

    pub fn relay_to_peer(
        &self,
        addr: SocketAddr,
        recv: &UdpSocket,
    ) -> anyhow::Result<(Duration, SocketAddr)> {
        // send response
        let buf = [0x21]; // !
        let start = Instant::now();
        self.send_to(&buf, addr)?;

        let mut buf = [0; 65536];
        let (_bytes, src) = recv.recv_from(&mut buf)?;

        let finish = Instant::now();
        let time = finish.duration_since(start);
        Ok((time, src))
    }

    pub fn bind(&self) -> anyhow::Result<(Duration, SocketAddr)> {
        let mut request = bind_pls();
        let buf = request.serialize();
        let start = Instant::now();
        self.socket.send_to(&buf, self.server)?;

        let mut buf = [0; 65536];
        let (bytes, src) = self.socket.recv_from(&mut buf)?;
        let finish = Instant::now();
        let time = finish.duration_since(start);
        let message = parse(Some(&request), &buf[0..bytes])?;

        if message.class != CLASS_SUCCESS {
            println!(
                "unexpected response from bind {:?} {:?}: {:?}",
                time, src, message
            );
            unimplemented!();
        }

        Ok((time, message.xor_addr.unwrap()))
    }
}

#[derive(Default)]
struct Message {
    method: u16,
    class: u16,
    transaction_id: [u8; 12],
    error: Option<u16>,
    error_message: Option<String>,
    realm: Option<String>,
    nonce: Option<Vec<u8>>,
    xor_addr: Option<SocketAddr>,
    addr: Option<SocketAddr>,
    xor_relayed: Option<SocketAddr>,
    xor_peer: Vec<SocketAddr>,
    username: Option<String>,
    password: Option<String>,
    key: Option<[u8; 16]>,
    requested_transport: Option<u8>,
    lifetime: Option<u32>,
    data: Option<Vec<u8>>,
}

impl Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut binding = f.debug_struct("Message");
        let f = binding
            .field(
                "method",
                match self.method {
                    BIND => &"bind",
                    ALLOCATE => &"allocate",
                    REFRESH => &"refresh",
                    SEND => &"send",
                    DATA => &"data",
                    CREATE_PERM => &"create_perm",
                    CHANNEL_BIND => &"channel_bind",
                    _ => unimplemented!(),
                },
            )
            .field(
                "class",
                match self.class {
                    CLASS_SUCCESS => &"success",
                    CLASS_FAILURE => &"failure",
                    CLASS_REQUEST => &"request",
                    CLASS_INDICATION => &"indication",
                    _ => unreachable!(),
                },
            );
        let f = if let Some(error) = &self.error {
            f.field("error", error)
        } else {
            f
        };

        let f = if let Some(error_message) = &self.error_message {
            f.field("error_message", error_message)
        } else {
            f
        };

        let f = if let Some(realm) = &self.realm {
            f.field("realm", realm)
        } else {
            f
        };

        let f = if let Some(nonce) = &self.nonce {
            f.field("nonce", nonce)
        } else {
            f
        };

        let f = if let Some(xor_addr) = &self.xor_addr {
            f.field("xor_addr", xor_addr)
        } else {
            f
        };

        let f = if let Some(addr) = &self.addr {
            f.field("addr", addr)
        } else {
            f
        };

        let f = if let Some(xor_relayed) = &self.xor_relayed {
            f.field("xor_relayed", xor_relayed)
        } else {
            f
        };

        let f = if let Some(lifetime) = &self.lifetime {
            f.field("lifetime", lifetime)
        } else {
            f
        };

        let f = if let Some(data) = &self.data {
            f.field("data", data)
        } else {
            f
        };

        let f = if !self.xor_peer.is_empty() {
            f.field("xor_peer", &self.xor_peer)
        } else {
            f
        };

        f.finish()
    }
}

fn parse(request: Option<&Message>, data: &[u8]) -> anyhow::Result<Message> {
    let mut cursor = Cursor::new(data);

    let message_type = cursor.read_u16::<NetworkEndian>()?;
    let class = message_type & CLASS_MASK;
    let method = message_type & !CLASS_MASK;
    let len = cursor.read_u16::<NetworkEndian>()?;
    if len & 0x3 != 0 {
        unimplemented!()
    }
    let cookie = cursor.read_u32::<NetworkEndian>()?;
    if cookie != COOKIE {
        unimplemented!()
    }
    let mut transaction_id = [0; 12];
    if transaction_id.len() != cursor.read(&mut transaction_id)? {
        unimplemented!()
    }

    let mut message = Message::default();
    message.method = method;
    message.class = class;

    if let Some(request) = request {
        // copy request auth values into response
        message.key = request.key;
        message.username = request.username.clone();
        message.password = request.password.clone();
        message.realm = request.realm.clone();
        message.nonce = request.nonce.clone();
    }

    message.parse_attributes(&mut cursor, &transaction_id)?;
    message.transaction_id = transaction_id;
    Ok(message)
}

impl Message {
    fn parse_attributes(
        &mut self,
        cursor: &mut Cursor<&[u8]>,
        transaction_id: &[u8],
    ) -> anyhow::Result<()> {
        while cursor.fill_buf()?.len() != 0 {
            let attribute_type = cursor.read_u16::<NetworkEndian>()?;
            let len = cursor.read_u16::<NetworkEndian>()?;
            let mut value = vec![0; len as usize];
            if len as usize != cursor.read(&mut value)? {
                unimplemented!();
            }
            if len & 3 != 0 {
                let padding = 4 - (len & 3);
                cursor.seek(Current(padding as i64))?;
            }

            match attribute_type {
                ATTRIBUTE_MESSAGE_INTEGRITY => self.parse_message_integrity(&value, cursor)?,
                ATTRIBUTE_ERROR => self.parse_error(&value)?,
                ATTRIBUTE_LIFETIME => self.parse_lifetime(&value)?,
                ATTRIBUTE_XOR_PEER => {
                    self.xor_peer = vec![Self::parse_xor_address(&value, transaction_id)?]
                }
                ATTRIBUTE_DATA => self.parse_data(&value),
                ATTRIBUTE_REALM => self.parse_realm(&value)?,
                ATTRIBUTE_NONCE => self.parse_nonce(&value)?,
                ATTRIBUTE_MAPPED => self.parse_mapped(&value)?,
                ATTRIBUTE_XOR_RELAYED => {
                    self.xor_relayed = Some(Self::parse_xor_address(&value, transaction_id)?)
                }
                ATTRIBUTE_XOR_MAPPED => {
                    self.xor_addr = Some(Self::parse_xor_address(&value, transaction_id)?)
                }
                other => {
                    if other < 0x8000 {
                        println!("{} {} {:?}", attribute_type, len, value);
                        println!("must parse attribute type {}", other);
                        unimplemented!();
                    }
                }
            }
        }
        Ok(())
    }

    fn parse_error(&mut self, value: &[u8]) -> anyhow::Result<()> {
        if value.len() < 4 {
            unimplemented!();
        }
        self.error = Some(((value[2] & 0xF) as u16 * 100) + value[3] as u16);

        if value.len() > 4 {
            self.error_message = Some(std::str::from_utf8(&value[4..])?.to_owned());
        }
        Ok(())
    }

    fn parse_lifetime(&mut self, value: &[u8]) -> anyhow::Result<()> {
        if value.len() != 4 {
            println!("lifetime: {:?}", value);
            unimplemented!();
        }
        self.lifetime = Some(NetworkEndian::read_u32(&value[0..4]));
        Ok(())
    }

    fn parse_data(&mut self, value: &[u8]) {
        self.data = Some(value.to_owned());
    }

    fn parse_realm(&mut self, value: &[u8]) -> anyhow::Result<()> {
        if let Some(realm) = &self.realm {
            if realm != std::str::from_utf8(value)? {
                unimplemented!();
            }
        }
        self.realm = Some(std::str::from_utf8(value)?.to_owned());
        Ok(())
    }

    fn parse_nonce(&mut self, value: &[u8]) -> anyhow::Result<()> {
        self.nonce = Some(value.to_owned());
        Ok(())
    }

    fn parse_xor_address(value: &[u8], transaction_id: &[u8]) -> anyhow::Result<SocketAddr> {
        if value.len() == 8 && value[1] == 1 {
            let port = NetworkEndian::read_u16(&value[2..4]) ^ COOKIE_MOST_SIGNIFICANT;
            let ip = NetworkEndian::read_u32(&value[4..8]) ^ COOKIE;
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port))
        } else if value.len() == 20 && value[1] == 2 {
            let port = NetworkEndian::read_u16(&value[2..4]) ^ COOKIE_MOST_SIGNIFICANT;
            let transaction_id = NetworkEndian::read_uint128(transaction_id, 12);
            let ip =
                NetworkEndian::read_u128(&value[4..20]) ^ ((COOKIE as u128) << 96 | transaction_id);
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port))
        } else {
            println!("xor mapped {:?}", value);
            unimplemented!();
        }
    }

    fn parse_mapped(&mut self, value: &[u8]) -> anyhow::Result<()> {
        if value.len() == 8 && value[1] == 1 {
            let port = NetworkEndian::read_u16(&value[2..4]);
            let ip = NetworkEndian::read_u32(&value[4..8]);
            self.addr = Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port));
        } else if value.len() == 20 && value[1] == 2 {
            let port = NetworkEndian::read_u16(&value[2..4]);
            let ip = NetworkEndian::read_u128(&value[4..20]);
            self.addr = Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port));
        } else {
            println!("mapped {:?}", value);
            unimplemented!();
        }
        Ok(())
    }

    fn parse_message_integrity(
        &self,
        value: &[u8],
        cursor: &mut Cursor<&[u8]>,
    ) -> anyhow::Result<()> {
        let mut mac = Hmac::<Sha1>::new_from_slice(&self.key.unwrap()).unwrap();
        let position = cursor.position();
        let mut packet = vec![0; position as usize - 24];
        cursor.set_position(0);
        cursor.read(&mut packet)?;
        let len = packet.len() - 20 + 24;
        packet[2] = ((len & 0xFF00) >> 8) as u8;
        packet[3] = (len & 0xFF) as u8;
        mac.update(&packet);
        mac.verify_slice(value)?;
        cursor.set_position(position);
        Ok(())
    }

    fn serialize(&mut self) -> Vec<u8> {
        let mut packet = vec![];

        let message_type = self.method | self.class;
        packet.write_u16::<NetworkEndian>(message_type).unwrap();
        packet.write_u16::<NetworkEndian>(0).unwrap();
        packet.write_u32::<NetworkEndian>(COOKIE).unwrap();
        packet.write(&self.transaction_id).unwrap();

        if self.error.is_some() || self.xor_addr.is_some() || self.addr.is_some() {
            unimplemented!();
        }

        self.add_requested_transport(&mut packet);
        self.add_xor_peer(&mut packet, &self.transaction_id);
        self.add_data(&mut packet);

        if self.username.is_some()
            && self.password.is_some()
            && self.realm.is_some()
            && self.nonce.is_some()
        {
            if self.key.is_none() {
                let mut hasher = Md5::new();
                hasher.update(self.username.as_ref().unwrap().as_bytes());
                hasher.update(b":");
                hasher.update(&self.realm.as_ref().unwrap().as_bytes());
                hasher.update(b":");
                hasher.update(&self.password.as_ref().unwrap().as_bytes());
                let key = hasher.finalize();
                self.key = Some(key.into());
            }
            self.add_username(&mut packet);
            self.add_realm(&mut packet);
            self.add_nonce(&mut packet);
            self.add_message_integrity(&mut packet);
        } else if self.username.is_some()
            || self.password.is_some()
            || self.realm.is_some()
            || self.nonce.is_some()
        {
            unimplemented!();
        }

        let len = packet.len() - 20;

        packet[2] = ((len & 0xFF00) >> 8) as u8;
        packet[3] = (len & 0xFF) as u8;
        packet
    }

    fn add_username(&self, packet: &mut Vec<u8>) {
        Self::add_tlv(
            packet,
            ATTRIBUTE_USERNAME,
            self.username.as_ref().unwrap().as_bytes(),
        );
    }

    fn add_realm(&self, packet: &mut Vec<u8>) {
        Self::add_tlv(
            packet,
            ATTRIBUTE_REALM,
            self.realm.as_ref().unwrap().as_bytes(),
        );
    }

    fn add_nonce(&self, packet: &mut Vec<u8>) {
        Self::add_tlv(packet, ATTRIBUTE_NONCE, self.nonce.as_ref().unwrap());
    }

    fn add_data(&self, packet: &mut Vec<u8>) {
        if let Some(data) = &self.data {
            Self::add_tlv(packet, ATTRIBUTE_DATA, data);
        }
    }

    fn add_requested_transport(&self, packet: &mut Vec<u8>) {
        if let Some(transport) = self.requested_transport {
            let mut buf = [0; 4];
            buf[0] = transport;
            Self::add_tlv(packet, ATTRIBUTE_REQUESTED_TRANSPORT, &buf);
        }
    }

    fn add_xor_peer(&self, packet: &mut Vec<u8>, transaction_id: &[u8]) {
        for peer in &self.xor_peer {
            match peer {
                V4(peer) => {
                    let mut buf = [0; 8];

                    buf[1] = 1; // address family = ipv4
                    NetworkEndian::write_u16(&mut buf[2..4], peer.port() ^ COOKIE_MOST_SIGNIFICANT);
                    let ip: u32 = NetworkEndian::read_u32(&peer.ip().octets()) ^ COOKIE;
                    NetworkEndian::write_u32(&mut buf[4..8], ip);
                    Self::add_tlv(packet, ATTRIBUTE_XOR_PEER, &buf);
                }

                V6(peer) => {
                    let mut buf = [0; 20];

                    buf[1] = 2; // address family = ipv6
                    NetworkEndian::write_u16(&mut buf[2..4], peer.port() ^ COOKIE_MOST_SIGNIFICANT);
                    let transaction_id = NetworkEndian::read_uint128(transaction_id, 12);
                    let ip: u128 = NetworkEndian::read_u128(&peer.ip().octets())
                        ^ ((COOKIE as u128) << 96 | transaction_id);
                    NetworkEndian::write_u128(&mut buf[4..20], ip);
                    Self::add_tlv(packet, ATTRIBUTE_XOR_PEER, &buf);
                }
            }
        }
    }

    fn add_message_integrity(&self, packet: &mut Vec<u8>) {
        // Update packet length to what it will be once the message integrity attribute is added
        // length - 20 byte fixed packet, + 2 byte type + 2 byte length + 20 byte hmace
        let len = packet.len() - 20 + 24;
        packet[2] = ((len & 0xFF00) >> 8) as u8;
        packet[3] = (len & 0xFF) as u8;

        let mut mac = Hmac::<Sha1>::new_from_slice(&self.key.unwrap()).unwrap();
        mac.update(packet);
        let result = mac.finalize().into_bytes();
        if result.len() != 20 {
            unimplemented!();
        }
        Self::add_tlv(packet, ATTRIBUTE_MESSAGE_INTEGRITY, &result);
    }

    fn add_tlv(packet: &mut Vec<u8>, attribute_type: u16, value: &[u8]) {
        packet.write_u16::<NetworkEndian>(attribute_type).unwrap();
        let len = value.len() as u16;
        packet.write_u16::<NetworkEndian>(len as u16).unwrap();
        packet.write(value).unwrap();
        let remainder = len & 0x3;
        if remainder != 0 {
            let remainder = 4 - remainder;
            let padding = vec![0; remainder as usize];
            packet.write(&padding).unwrap();
        }
    }
}

pub fn fmt_ms(d: Duration) -> String {
    if d == Duration::MAX {
        format!("timeout")
    } else {
        format!("{:.1}", d.as_micros() as f32 / 1000.0)
    }
}

pub fn fmt_diff(a: Duration, b: Duration) -> String {
    if a > b {
        format!("{:.1}", (a - b).as_micros() as f32 / 1000.0)
    } else {
        format!("{:+.1}", -((b - a).as_micros() as f32 / 1000.0))
    }
}
