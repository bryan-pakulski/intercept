use crate::error::{BackendError, BackendErrorKind};
use crate::rules::{Action, Direction, Rule, When};

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::udp::{MutableUdpPacket, UdpPacket};
use pnet::packet::{MutablePacket, Packet, PacketSize};
use std::net::{IpAddr, Ipv4Addr};

use log::{debug, error, info};
use nfqueue::Message;
use regex::Regex;
use std::sync::{Arc, RwLock};

#[derive(Clone)]
struct State {
    count: u32,
    ruleset: Arc<RwLock<Vec<Rule>>>,
}

pub fn intercept(
    input_queue_num: u16,
    output_queue_num: u16,
    ruleset: Vec<Rule>,
) -> Result<(), BackendError> {
    let state = State {
        count: 0,
        ruleset: Arc::new(RwLock::new(ruleset)),
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

    if let Some(header) = Ipv4Packet::new(msg.get_payload()) {
        match header.get_next_level_protocol() {
            IpNextHeaderProtocols::Udp => {
                if let Some(payload) = UdpPacket::new(header.payload()) {
                    if is_sip_packet(payload.payload()) {
                        let source = IpAddr::V4(header.get_source());
                        let destination = IpAddr::V4(header.get_destination());

                        if let Ok(uri) = get_uri(payload.payload()) {
                            info!("INBOUND => {} => {} | {}", source, destination, uri);
                            if let Ok(modified_packet) = apply_rules_to_sip_packet(
                                payload.payload(),
                                state.ruleset.clone(),
                                Direction::In,
                            ) {
                                debug!("Sending modified packet");

                                msg.set_verdict_full(
                                    nfqueue::Verdict::Accept,
                                    msg.get_nfmark(),
                                    modified_packet.as_slice(),
                                );
                                return;
                            }
                        }
                    }
                }
            }
            _ => {
                debug!(
                    "Received packet with protocol: {:?}",
                    header.get_next_level_protocol()
                );
            }
        }
    } else {
        debug!("Non IPv4 packet received");
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
    
    if let Some(mut header) = MutableIpv4Packet::new(&mut ip_header.unwrap().payload_mut()) {
        debug!("Got IPv4 Packet: {:?}", header);

        let source = header.to_immutable().get_source();
        let destination = header.get_destination();

        if let Some(udp_packet) = MutableUdpPacket::new(&mut header.packet_mut()) {
            debug!("Got UDP Packet: {:?}", udp_packet);

            if is_sip_packet(udp_packet.payload()) {

                if let Ok(uri) = get_uri(udp_packet.payload()) {
                    info!("OUTBOUND => {} => {} | {}", source, destination, uri);
                    if let Ok(mut modified_packet) = apply_rules_to_sip_packet(
                        udp_packet.payload(),
                        state.ruleset.clone(),
                        Direction::Out,
                    ) {
                        let new_size = modified_packet.len();

                        let mut new_pkt = MutableUdpPacket::new(&mut modified_packet[..]).unwrap();
                        new_pkt.set_source(udp_packet.get_source());
                        new_pkt.set_destination(udp_packet.get_destination());
                        new_pkt.set_length(new_size as u16);
                        new_pkt.set_checksum(pnet::packet::udp::ipv4_checksum(&new_pkt.to_immutable(), &source, &destination));
                        
                        let new_len = new_pkt.get_length();
                        let mut new_data = new_pkt.payload_mut().to_owned();
                        
                        debug!("Created UDP packet: {:?}", new_pkt);

                        let mut ip4_pkt = MutableIpv4Packet::new(&mut new_data).unwrap();
                        ip4_pkt.set_version(header.get_version());
                        ip4_pkt.set_next_level_protocol(header.get_next_level_protocol());
                        ip4_pkt.set_total_length(new_len);
                        ip4_pkt.set_source(source);
                        ip4_pkt.set_destination(destination);
                        ip4_pkt.set_options(&vec![]);
                        ip4_pkt.set_identification(header.get_identification());
                        ip4_pkt.set_dscp(header.get_dscp());
                        ip4_pkt.set_checksum(pnet::packet::ipv4::checksum(&ip4_pkt.to_immutable()));
                        ip4_pkt.set_ttl(header.get_ttl());
                        ip4_pkt.set_flags(header.get_flags());
                        ip4_pkt.set_header_length(header.get_header_length());
                        
                        debug!("Created ipv4 packet: {} \n {:?}", ip4_pkt.get_total_length(), ip4_pkt);

                        msg.set_verdict_full(
                            nfqueue::Verdict::Accept,
                            msg.get_nfmark(),
                            ip4_pkt.packet_mut(),
                        );
                    }
                }
            }
        }
    }

    msg.set_verdict(nfqueue::Verdict::Accept);

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
