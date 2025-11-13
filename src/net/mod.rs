use crate::error::{BackendError, BackendErrorKind};
use crate::rules::{Action, Direction, Rule, When};

use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::udp::{MutableUdpPacket, UdpPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::{MutablePacket, Packet};
use pnet::transport::{transport_channel, TransportChannelType, TransportProtocol, TransportReceiver, TransportSender};

use log::{debug, info, error};
use nfqueue::Message;
use regex::Regex;
use std::sync::{Arc, RwLock};

#[derive(Clone)]
struct State {
    count: u32,
    ruleset: Arc<RwLock<Vec<Rule>>>,
    sender: Arc<RwLock<TransportSender>>,
    receiver: Arc<RwLock<TransportReceiver>>,
}

pub fn intercept(
    input_queue_num: u16,
    output_queue_num: u16,
    ruleset: Vec<Rule>,
) -> Result<(), BackendError> {
    let (sender, receiver) = transport_channel(9068, TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Udp))).unwrap();

    let state = State {
        count: 0,
        ruleset: Arc::new(RwLock::new(ruleset)),
        sender: Arc::new(RwLock::new(sender)),
        receiver: Arc::new(RwLock::new(receiver)),
    };

    let state_clone = state.clone();
    let input_thread = std::thread::spawn(move || {
        let mut input_q = nfqueue::Queue::new(state_clone);

        input_q.open();
        input_q.unbind(libc::AF_INET);
        let rc = input_q.bind(libc::AF_INET);
        assert!(rc == 0, "Failed to bind to input queue");
        input_q.create_queue(input_queue_num, input_callback);
        input_q.set_mode(nfqueue::CopyMode::CopyPacket, 0xffff);
        input_q.run_loop();
    });

    let state_clone = state.clone();
    let output_thread = std::thread::spawn(move || {
        let mut output_q = nfqueue::Queue::new(state_clone);
        output_q.open();
        output_q.unbind(libc::AF_INET);
        let rc = output_q.bind(libc::AF_INET);
        assert!(rc == 0, "Failed to bind to output queue");
        output_q.create_queue(output_queue_num, output_callback);
        output_q.set_mode(nfqueue::CopyMode::CopyPacket, 0xffff);

        output_q.run_loop();
    });

    input_thread.join().unwrap();
    output_thread.join().unwrap();

    Ok(())
}

fn input_callback(msg: &Message, state: &mut State) {
    debug!(
        "Packet received [id: 0x{:x}] mark: {}",
        msg.get_id(),
        msg.get_nfmark()
    );
    state.count += 1;

    let mut data = msg.get_payload().to_owned();
    let ip_header = Ipv4Packet::new(&mut data);

    if ip_header.is_none() {
        debug!("Non ipv4 packet received");
        msg.set_verdict(nfqueue::Verdict::Accept);
        return;
    }

    let header = ip_header.unwrap();
    debug!("Got IPv4 Packet: {:?}", header);

    let source = header.get_source();
    let destination = header.get_destination();

    if let Some(udp_packet) = UdpPacket::new(header.payload()) {
        debug!("Got UDP Packet: {:?}", udp_packet);

        if is_sip_packet(udp_packet.payload()) {
            if let Ok(uri) = get_uri(udp_packet.payload()) {
                info!("INBOUND => {} => {} | {}", source, destination, uri);
                if let Ok(mut modified_packet) = apply_rules_to_sip_packet(
                    udp_packet.payload(),
                    state.ruleset.clone(),
                    Direction::In,
                ) {
                    debug!("Modified data size: {}", modified_packet.len());
                    send_new_packet(
                        udp_packet.to_immutable(),
                        header.to_immutable(),
                        &mut modified_packet,
                        msg,
                    );
                    return;
                }
            }
        }
    }

    msg.set_verdict(nfqueue::Verdict::Accept);
}

fn output_callback(msg: &Message, state: &mut State) {
    debug!(
        "Packet sent [id: 0x{:x}] mark: {}",
        msg.get_id(),
        msg.get_nfmark()
    );
    state.count += 1;

    let mut data = msg.get_payload().to_owned();
    let ip_header = MutableIpv4Packet::new(&mut data);

    if ip_header.is_none() {
        debug!("Non ipv4 packet received");
        msg.set_verdict(nfqueue::Verdict::Accept);
        return;
    }

    let mut header = ip_header.unwrap();
    debug!("Got IPv4 Packet: {:?}", header);

    let source = header.get_source();
    let destination = header.get_destination();

    if let Some(udp_packet) = MutableUdpPacket::new(header.payload_mut()) {
        debug!("Got UDP Packet: {:?}", udp_packet);

        if is_sip_packet(udp_packet.payload()) {
            if let Ok(uri) = get_uri(udp_packet.payload()) {
                info!("INBOUND => {} => {} | {}", source, destination, uri);
                if let Ok(mut modified_packet) = apply_rules_to_sip_packet(
                    udp_packet.payload(),
                    state.ruleset.clone(),
                    Direction::Out,
                ) {
                    let payload_size = modified_packet.len();
                    debug!("Modified data size: {}", payload_size);

                    let mut udp_pkt = MutableUdpPacket::new(&mut modified_packet[..]).unwrap();
                    udp_pkt.set_source(udp_packet.get_source());
                    udp_pkt.set_destination(udp_packet.get_destination());
                    udp_pkt.set_length(payload_size as u16);
                    udp_pkt.set_checksum(0);

                    // allow up to 20 byte header + payload
                    let mut new_buffer = vec![0x0; 20 + payload_size];
                    new_buffer[..20].copy_from_slice(header.packet()[0..20].as_ref());
                    
                    let mut new_pkt = MutableIpv4Packet::new(&mut new_buffer[..]).unwrap();

                    new_pkt.set_total_length(payload_size as u16 + 20);
                    new_pkt.set_payload(&udp_pkt.packet()[..]);
                    new_pkt.set_checksum(pnet::packet::ipv4::checksum(&new_pkt.to_immutable()));

                    debug!("Constructed new IPV4 Packet: {:?}", new_pkt);
                    debug!("Constructed new UDP Packet: {:?}", udp_pkt);

                    match state.sender.write().unwrap().send_to(new_pkt.to_immutable(), new_pkt.get_destination().into()) {
                        Ok(_) => {
                            debug!("Sent modified packet to {}", new_pkt.get_destination());
                        },
                        Err(e) => {
                            error!("Failed to send modified packet to {}: {}", new_pkt.get_destination(), e);
                        }
                    }

                    msg.set_verdict_full(nfqueue::Verdict::Stolen, 0, &data);
                    return;
                }
            }
        }
    }

    msg.set_verdict(nfqueue::Verdict::Accept);
}

// Constructs a new packet from the original ipv4 / udp packets
fn send_new_packet(udp: UdpPacket, ip_header: Ipv4Packet, payload: &mut [u8], msg: &Message) {
    let size = payload.len();
    let p = payload.as_mut();

    let mut new_udp = MutableUdpPacket::new(p).unwrap();
    new_udp.set_source(udp.get_source());
    new_udp.set_destination(udp.get_destination());
    new_udp.set_length(size as u16);
    new_udp.set_checksum(pnet::packet::udp::ipv4_checksum(
        &new_udp.to_immutable(),
        &ip_header.get_source(),
        &ip_header.get_destination(),
    ));

    debug!("Constructed new udp packet: {:?}", new_udp);
    
    // Since new_udp's payload is a part of the same buffer, modify it directly
    let udp_data = new_udp.packet_mut(); // Work with the full packet
    let mut new_ip = MutableIpv4Packet::new(udp_data).unwrap();
    new_ip.set_source(ip_header.get_source());
    new_ip.set_destination(ip_header.get_destination());
    new_ip.set_identification(ip_header.get_identification());
    new_ip.set_flags(ip_header.get_flags());
    new_ip.set_ttl(ip_header.get_ttl());
    new_ip.set_next_level_protocol(ip_header.get_next_level_protocol());
    new_ip.set_version(ip_header.get_version());
    new_ip.set_dscp(ip_header.get_dscp());
    new_ip.set_ecn(ip_header.get_ecn());
    new_ip.set_fragment_offset(ip_header.get_fragment_offset());
    new_ip.set_header_length(ip_header.get_header_length());
    new_ip.set_options(&ip_header.get_options());
    new_ip.set_total_length(size as u16 + 20);
    new_ip.set_checksum(pnet::packet::ipv4::checksum(&new_ip.to_immutable()));

    debug!("Constructed new packet: {:?}", new_ip);

    msg.set_verdict_full(nfqueue::Verdict::Accept, 0, &new_ip.payload());
    info!(
        "Accepted modified packet, new size: {}",
        new_ip.payload().len()
    );
}

// A very naive check, we are relying on SIP/2.0 to be present on the first line
fn is_sip_packet(payload: &[u8]) -> bool {
    if let Ok(payload_str) = std::str::from_utf8(payload) {
        if payload_str.contains("SIP/2.0") {
            return true;
        }
    }
    false
}

fn get_uri(payload: &[u8]) -> Result<String, BackendError> {
    if let Ok(payload_str) = std::str::from_utf8(payload) {
        if let Some(first_line) = payload_str.lines().next() {
            return Ok(first_line.to_string());
        }
    }

    Err(BackendError::new(
        BackendErrorKind::General,
        "Failed to get URI from SIP packet".to_string(),
    ))
}

fn regex_match(regex: &str, payload: &[u8]) -> bool {
    if let Ok(payload_str) = std::str::from_utf8(payload) {
        if let Ok(regex) = Regex::new(regex) {
            if regex.is_match(payload_str) {
                return true;
            }
        }
    }
    false
}

fn apply_actions(payload: &str, actions: &Vec<Action>) -> Result<String, BackendError> {
    let mut lines: Vec<String> = payload.to_string().lines().map(String::from).collect();

    for action in actions {
        match action {
            Action::Delete { key } => {
                debug!("Deleting headers: {:?}", key);
                for k in key {
                    for line in lines.iter() {
                        if line.contains(k) {
                            info!("Deleting line: {}", line);
                        }
                    }
                }
                // Filter out lines that match the keys
                lines.retain(|line| !key.iter().any(|k| line.contains(k)));
            }
            Action::Add { key_value } => {
                debug!("Adding headers: {:?}", key_value);

                // Insert after first line
                for (k, v) in key_value {
                    info!("Adding header: {}: {}", k, v);

                    let new_line = format!("{}: {}", k, v);
                    lines.insert(1, new_line);
                }
            }
            Action::Mod {
                key,
                match_pattern,
                replace,
            } => {
                debug!(
                    "Modifying header: {} with regex: {} and replace: {}",
                    key, match_pattern, replace
                );
                let re = Regex::new(match_pattern)?;
                lines = lines
                    .iter()
                    .map(|line| {
                        if line.contains(key) {
                            re.replace(line, replace.as_str()).to_string()
                        } else {
                            line.clone()
                        }
                    })
                    .collect();
            }
        }
    }

    let new_buffer = lines.join("\n");
    debug!(
        "New buffer: {} -> {} \n{}",
        payload.len(),
        new_buffer.len(),
        new_buffer
    );

    Ok(new_buffer)
}

fn apply_rules_to_sip_packet(
    payload: &[u8],
    ruleset: Arc<RwLock<Vec<Rule>>>,
    direction: Direction,
) -> Result<Vec<u8>, BackendError> {
    let uri = get_uri(payload)?;
    let mut modified: bool = false;
    let mut buffer = std::str::from_utf8(payload)?.to_string();

    for rule in ruleset.write().unwrap().iter_mut() {
        // URI match
        debug!("Checking rule \"{}\" in uri: \"{}\"", rule.uri, uri);
        if !uri.contains(&rule.uri) {
            debug!("URI did not match rule \"{}\"", rule.uri);
            continue;
        }
        debug!("URI matched rule \"{}\"", rule.uri);

        // Direction match
        if rule.direction != direction && rule.direction != Direction::Both {
            debug!(
                "Direction \"{}\" did not match rule \"{}\"",
                direction, rule.direction
            );
            continue;
        }
        debug!(
            "Direction \"{}\" matched rule \"{}\"",
            direction, rule.direction
        );

        // Match regex
        if let Some(regex) = &rule.match_regex {
            debug!(
                "Checking rule \"{}\" in regex \"{}\"",
                rule.match_regex.as_ref().unwrap(),
                regex
            );
            if !regex_match(regex, payload) {
                continue;
            }
            debug!(
                "Regex matched rule \"{}\"",
                rule.match_regex.as_ref().unwrap()
            );
        }

        // Trigger match
        match rule.when {
            When::Always => {
                debug!("Trigger matched rule \"always\"");
                buffer = apply_actions(&buffer, &rule.actions)?;
                modified = true;
                rule.trigger_count += 1;
            }
            When::Once => {
                debug!("Trigger matched rule \"once\"");

                if rule.trigger_count == 0 {
                    debug!("Trigger count is 0, applying actions");
                    buffer = apply_actions(&buffer, &rule.actions)?;
                    modified = true;
                } else {
                    debug!(
                        "Trigger count is {} > 0, not applying actions",
                        rule.trigger_count
                    );
                }

                rule.trigger_count += 1;
            }
        }
    }

    if !modified {
        Err(BackendError::new(
            BackendErrorKind::General,
            "No actions applied".to_string(),
        ))
    } else {
        Ok(buffer.to_string().into_bytes())
    }
}
