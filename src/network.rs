use crate::{
    block::Block,
    utils::{decode_varint, encode_hex, encode_varint, hash256},
};
use anyhow::{bail, Result};
use rand::Rng;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{
    fmt,
    io::{Cursor, Read, Seek, Write},
    net::TcpStream,
};

#[derive(Debug, Clone)]
pub struct NetworkEnvelope {
    pub command: Vec<u8>,
    pub payload: Vec<u8>,
    pub magic: Vec<u8>,
}

impl NetworkEnvelope {
    pub fn new(command: Vec<u8>, payload: Vec<u8>, testnet: bool) -> NetworkEnvelope {
        NetworkEnvelope {
            command,
            payload,
            magic: if !testnet {
                vec![0xf9, 0xbe, 0xb4, 0xd9]
            } else {
                vec![0x0b, 0x11, 0x09, 0x07]
            },
        }
    }

    pub fn parse<T: Read>(buffer: &mut T, testnet: bool) -> Result<NetworkEnvelope> {
        // magic number
        let mut magic_bytes = [0u8; 4];
        buffer.read_exact(&mut magic_bytes).unwrap();
        let magic = magic_bytes.to_vec();
        if magic == vec![0, 0, 0, 0] {
            bail!("Connection reset!")
        }

        let expected_magic = if !testnet {
            vec![0xf9, 0xbe, 0xb4, 0xd9]
        } else {
            vec![0x0b, 0x11, 0x09, 0x07]
        };

        if magic != expected_magic {
            bail!(
                "magic is not right {} vs {}",
                encode_hex(&magic),
                encode_hex(&expected_magic)
            )
        }

        // command 12 bytes
        let mut command_bytes = [0u8; 12];
        buffer.read_exact(&mut command_bytes).unwrap();
        //
        let mut command = command_bytes.to_vec();
        // removestrip the trailing zeros
        if let Some(i) = command.iter().rposition(|x| *x != 0) {
            let new_len = i + 1;
            command.truncate(new_len);
        };

        // paload length 4 bytes, little endian
        let mut payload_length_bytes = [0u8; 4];
        buffer.read_exact(&mut payload_length_bytes).unwrap();
        let payload_length = u32::from_le_bytes(payload_length_bytes);

        // checksum 4 bytes, first for of hash256 of payload
        let mut checksum_bytes = [0u8; 4];
        buffer.read_exact(&mut checksum_bytes).unwrap();
        let checksum = checksum_bytes.to_vec();

        // payload is of length `payload_length`
        let mut payload: Vec<u8> = vec![0u8; payload_length as usize];
        buffer.read_exact(&mut payload).unwrap();

        // verify checksum
        let hash = hash256(&payload);
        if hash[..4] != checksum {
            bail!("checksum not match!")
        }

        Ok(NetworkEnvelope {
            command,
            payload,
            magic,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = vec![];
        // add network magic
        buffer.append(&mut self.magic.clone());
        // add command
        let mut command = self.command.clone();
        // fill 0's
        if self.command.len() < 12 {
            let mut zeros: Vec<u8> = vec![0; 12 - self.command.len()];
            command.append(&mut zeros);
        }
        buffer.append(&mut command);

        // add payload length
        let payload_length = self.payload.len() as u32;
        let payload_length_bytes = payload_length.to_le_bytes();
        buffer.append(&mut payload_length_bytes.to_vec());

        // add checksum
        let hash = hash256(&self.payload);
        buffer.append(&mut hash[..4].to_vec());

        // add payload
        buffer.append(&mut self.payload.clone());

        buffer
    }

    pub fn cursor(&self) -> Cursor<Vec<u8>> {
        Cursor::new(self.payload.clone())
    }

    pub fn command_str(&self) -> String {
        std::str::from_utf8(&self.command).unwrap().into()
    }

    pub fn version_payload(
        version: Option<u32>,
        services: Option<u64>,
        timestamp: Option<u64>,
        receiver_services: Option<u64>,
        receiver_ip: Option<Vec<u8>>,
        receiver_port: Option<u16>,
        sender_services: Option<u64>,
        sender_ip: Option<Vec<u8>>,
        sender_port: Option<u16>,
        nonce: Option<u64>,
        user_agent: Option<String>,
        latest_block: Option<u32>,
        relay: Option<bool>,
    ) -> Vec<u8> {
        let mut result: Vec<u8> = vec![];

        // version is 4 bytes little-endian
        let version = version.unwrap_or(70015);
        result.append(&mut version.to_le_bytes().to_vec());

        // services is 8 bytes le
        let services = services.unwrap_or(0);
        result.append(&mut services.to_le_bytes().to_vec());

        // timestamp is 8 bytes le
        let timestamp = timestamp.unwrap_or(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );
        result.append(&mut timestamp.to_le_bytes().to_vec());

        // receiver services is 8 bytes le
        let receiver_services = receiver_services.unwrap_or(0);
        result.append(&mut receiver_services.to_le_bytes().to_vec());

        // IPV4 is 10 00 bytes and 2 ff bytes then receiver ip
        result.append(&mut [0u8; 10].to_vec());
        result.append(&mut [255u8; 2].to_vec());
        let mut receiver_ip = receiver_ip.unwrap_or([0u8; 4].to_vec());
        result.append(&mut receiver_ip);

        // receiver port is 2 bytes, big edian
        let receiver_port = receiver_port.unwrap_or(8333);
        result.append(&mut receiver_port.to_be_bytes().to_vec());

        //
        // sender services is 8 bytes le
        let sender_services = sender_services.unwrap_or(0);
        result.append(&mut sender_services.to_le_bytes().to_vec());

        // IPV4 is 10 00 bytes and 2 ff bytes then sender ip
        result.append(&mut [0u8; 10].to_vec());
        result.append(&mut [255u8; 2].to_vec());
        let mut sender_ip = sender_ip.unwrap_or([0u8; 4].to_vec());
        result.append(&mut sender_ip);

        // sender port is 2 bytes, big edian
        let sender_port = sender_port.unwrap_or(8333);
        result.append(&mut sender_port.to_be_bytes().to_vec());

        // nonce should be 8 bytes
        let mut rng = rand::thread_rng();
        let nonce = nonce.unwrap_or(rng.gen());
        result.append(&mut nonce.to_le_bytes().to_vec());

        // useragent is a variable string, so varint first
        let mut useragent = user_agent
            .unwrap_or("/programmingbitcoin:0.1/".into())
            .as_bytes()
            .to_vec();
        let mut useragent_length = encode_varint(useragent.len() as u64);
        result.append(&mut useragent_length);
        result.append(&mut useragent);

        // latest block is 4 bytes little endian
        let latest_block = latest_block.unwrap_or(0);
        result.append(&mut latest_block.to_le_bytes().to_vec());

        let relay = relay.unwrap_or(false);
        if relay {
            result.push(1);
        } else {
            result.push(0);
        }

        result
    }

    pub fn verack_payload() -> Vec<u8> {
        vec![]
    }

    // 8 bytes
    pub fn ping_pong_payload(nonce: Vec<u8>) -> Vec<u8> {
        nonce
    }

    pub fn get_headers_payload(
        version: Option<u32>,
        num_hashes: u64,
        start_block: Vec<u8>,
        end_block: Option<Vec<u8>>,
    ) -> Vec<u8> {
        let mut result: Vec<u8> = vec![];
        // protocol version is 4 bytes little-endian
        let version_bytes = match version {
            Some(v) => v.to_le_bytes(),
            None => 70015u32.to_le_bytes(),
        };
        result.append(&mut version_bytes.to_vec());

        // number of hashes is a varint
        result.append(&mut encode_varint(num_hashes));

        // start block is in little-endian
        let mut s = start_block.clone();
        s.reverse();
        result.append(&mut s);

        // end block is in little-endian
        let mut e = match end_block {
            Some(b) => b.clone(),
            None => vec![0u8; 32].to_vec(),
        };
        e.reverse();
        result.append(&mut e);

        result
    }

    pub fn parse_headers_message<T: Read + Seek>(buffer: &mut T) -> Vec<Block> {
        let num_headers = decode_varint(buffer);
        let mut blocks: Vec<Block> = vec![];
        for _ in 0..num_headers {
            blocks.push(Block::parse(buffer).unwrap());
            let num_txs = decode_varint(buffer);
            if num_txs != 0 {
                panic!("number of txs not 0 in block header");
            }
        }

        blocks
    }

    pub fn encode_command(command: String) -> Vec<u8> {
        command.into_bytes()
    }

    pub fn decode_command(command: &Vec<u8>) -> String {
        std::str::from_utf8(&command).unwrap().into()
    }
}

impl fmt::Display for NetworkEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}: {}",
            std::str::from_utf8(&self.command).unwrap(),
            encode_hex(&self.payload)
        )
    }
}

pub struct SimpleNode {
    pub host: String,
    pub port: u32,
    pub testnet: bool,
    pub stream: TcpStream,
}

impl SimpleNode {
    pub fn new(host: String, port: u32, testnet: bool) -> SimpleNode {
        // let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

        let stream = TcpStream::connect(format!("{}:{}", host, port)).unwrap();

        SimpleNode {
            host,
            port,
            testnet,
            stream,
        }
    }

    pub fn handshake(&mut self) -> bool {
        // 发送version message
        let msg = NetworkEnvelope::new(
            NetworkEnvelope::encode_command("version".into()),
            NetworkEnvelope::version_payload(
                None, None, None, None, None, None, None, None, None, None, None, None, None,
            ),
            false,
        );
        self.send(msg);

        // 接收verack
        self.wait_for(vec!["verack".into()]);

        true
    }

    pub fn send(&mut self, message: NetworkEnvelope) -> bool {
        println!("sending: {}", message);
        self.stream.write(&message.serialize()).unwrap();
        true
    }

    pub fn read(&mut self) -> NetworkEnvelope {
        let envelop = NetworkEnvelope::parse(&mut self.stream, self.testnet).unwrap();
        println!("receiving: {}", envelop);
        envelop
    }

    // 读取commands列表中的一个命令信息
    pub fn wait_for(&mut self, commands: Vec<String>) -> NetworkEnvelope {
        let mut envelop: NetworkEnvelope;
        loop {
            envelop = self.read();
            let cmd = NetworkEnvelope::decode_command(&envelop.command);
            if cmd == "version" {
                let verack_msg = NetworkEnvelope::new(
                    NetworkEnvelope::encode_command("verack".into()),
                    NetworkEnvelope::verack_payload(),
                    false,
                );
                self.send(verack_msg);
            } else if cmd == "ping" {
                let pong_msg = NetworkEnvelope::new(
                    NetworkEnvelope::encode_command("pong".into()),
                    envelop.payload,
                    false,
                );
                self.send(pong_msg);
            } else if commands.contains(&cmd) {
                break;
            } else {
                println!("read an unexpect message: {}", cmd);
            }
        }
        envelop
    }
}

#[allow(unused_imports)]
mod tests {
    use super::{NetworkEnvelope, SimpleNode};
    use crate::utils::{decode_hex, encode_hex};
    use std::io::Cursor;

    #[test]
    pub fn test_network_envelope_parse() {
        let msg = decode_hex("f9beb4d976657261636b000000000000000000005df6e0e2").unwrap();
        let mut stream = Cursor::new(msg);
        let envelope = NetworkEnvelope::parse(&mut stream, false).unwrap();
        assert!("verack" == std::str::from_utf8(&envelope.command).unwrap());
        assert!(envelope.payload.len() == 0);

        let msg = decode_hex("f9beb4d976657273696f6e0000000000650000005f1a69d2721101000100000000000000bc8f5e5400000000010000000000000000000000000000000000ffffc61b6409208d010000000000000000000000000000000000ffffcb0071c0208d128035cbc97953f80f2f5361746f7368693a302e392e332fcf05050001").unwrap();
        let mut stream = Cursor::new(msg.clone());
        let envelope = NetworkEnvelope::parse(&mut stream, false).unwrap();
        assert!("version" == std::str::from_utf8(&envelope.command).unwrap());
        assert!(envelope.payload == msg[24..].to_vec());
    }

    #[test]
    pub fn test_network_envelope_serialize() {
        let msg = decode_hex("f9beb4d976657261636b000000000000000000005df6e0e2").unwrap();
        let mut stream = Cursor::new(msg.clone());
        let envelope = NetworkEnvelope::parse(&mut stream, false).unwrap();
        assert!(msg == envelope.serialize());

        let msg = decode_hex("f9beb4d976657273696f6e0000000000650000005f1a69d2721101000100000000000000bc8f5e5400000000010000000000000000000000000000000000ffffc61b6409208d010000000000000000000000000000000000ffffcb0071c0208d128035cbc97953f80f2f5361746f7368693a302e392e332fcf05050001").unwrap();
        let mut stream = Cursor::new(msg.clone());
        let envelope = NetworkEnvelope::parse(&mut stream, false).unwrap();
        assert!(msg == envelope.serialize());
    }

    #[test]
    pub fn test_network_envelope_headers_message() {
        let block_hex = "0000000000000000001237f46acddf58578a37e213d2a6edc4884a2fcad05ba3";
        let want = "7f11010001a35bd0ca2f4a88c4eda6d213e2378a5758dfcd6af437120000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        let headers_msg =
            NetworkEnvelope::get_headers_payload(None, 1, decode_hex(block_hex).unwrap(), None);
        assert!(encode_hex(&headers_msg) == want);
    }

    #[test]
    pub fn test_network_envelope_parse_headers_message() {
        let payload = decode_hex("0200000020df3b053dc46f162a9b00c7f0d5124e2676d47bbe7c5d0793a500000000000000ef445fef2ed495c275892206ca533e7411907971013ab83e3b47bd0d692d14d4dc7c835b67d8001ac157e670000000002030eb2540c41025690160a1014c577061596e32e426b712c7ca00000000000000768b89f07044e6130ead292a3f51951adbd2202df447d98789339937fd006bd44880835b67d8001ade09204600").unwrap();
        let mut buffer = Cursor::new(payload);
        let headers = NetworkEnvelope::parse_headers_message(&mut buffer);
        assert!(headers.len() == 2);
    }

    #[test]
    pub fn test_network_envelope_version_message() {
        let payload = NetworkEnvelope::version_payload(
            None,
            None,
            Some(0),
            None,
            None,
            None,
            None,
            None,
            None,
            Some(0),
            None,
            None,
            None,
        );
        assert!(encode_hex(&payload) == "7f11010000000000000000000000000000000000000000000000000000000000000000000000ffff00000000208d000000000000000000000000000000000000ffff00000000208d0000000000000000182f70726f6772616d6d696e67626974636f696e3a302e312f0000000000");
    }

    #[test]
    pub fn test_network_envelope_handshake() {
        let mut node = SimpleNode::new("testnet.programmingbitcoin.com".into(), 18333, true);
        node.handshake();
    }
}
