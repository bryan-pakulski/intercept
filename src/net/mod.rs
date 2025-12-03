use crate::error::{BackendError, BackendErrorKind};
use crate::rules::{Action, Direction, Rule, When};

use pnet::packet::ipv4::{MutableIpv4Packet};
use pnet::packet::udp::{MutableUdpPacket};
use pnet::packet::{MutablePacket, Packet};

use log::{debug, info};
use nfqueue_rs::Message;
use regex::Regex;
use std::sync::{Arc, RwLock};

struct ScopedTimer {
    timer: std::time::Instant,
    msg: String,
}

impl ScopedTimer {
    fn new(msg: String) -> ScopedTimer {
        ScopedTimer {
            timer: std::time::Instant::now(),
            msg,
        }
    }
}

impl<'a> Drop for ScopedTimer {
    fn drop(&mut self) {
        debug!("{} - {}us", self.msg, self.timer.elapsed().as_micros());
    }
}

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
        let mut input_q = nfqueue_rs::Queue::new(state_clone).unwrap();

        input_q.unbind(libc::AF_INET);
        let rc = input_q.bind(libc::AF_INET);
        assert!(rc == 0, "Failed to bind to input queue");
        input_q.create_queue(input_queue_num, input_callback);
        input_q.set_mode(nfqueue_rs::CopyMode::CopyPacket, 0xffff);
        input_q.run_loop();
    });

    let state_clone = state.clone();
    let output_thread = std::thread::spawn(move || {
        let mut output_q = nfqueue_rs::Queue::new(state_clone).unwrap();
        output_q.unbind(libc::AF_INET);
        let rc = output_q.bind(libc::AF_INET);
        assert!(rc == 0, "Failed to bind to output queue");
        output_q.create_queue(output_queue_num, output_callback);
        output_q.set_mode(nfqueue_rs::CopyMode::CopyPacket, 0xffff);

        output_q.run_loop();
    });

    input_thread.join().unwrap();
    output_thread.join().unwrap();

    Ok(())
}

fn input_callback(msg: &Message, state: &mut State) {
    let _scoped_timer = ScopedTimer::new(format!("Packet 0x{:x} processed", msg.get_id()));
    debug!(
        "Packet received [id: 0x{:x}] mark: {}",
        msg.get_id(),
        msg.get_nfmark()
    );
    state.count += 1;

    let mut data = msg.get_payload().to_vec();
    let ip_header = MutableIpv4Packet::new(&mut data);

    if ip_header.is_none() {
        debug!("Non ipv4 packet received");
        msg.set_verdict(nfqueue_rs::Verdict::Accept);
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
                if let Ok(modified_packet) = apply_rules_to_sip_packet(
                    udp_packet.payload(),
                    state.ruleset.clone(),
                    Direction::In,
                ) {
                    let payload_size = modified_packet.len();
                    let mut buf = vec![0u8; 8 + payload_size];
                    
                    {
                        let mut udp_pkt = MutableUdpPacket::new(&mut buf).unwrap();
                        udp_pkt.set_source(udp_packet.get_source());
                        udp_pkt.set_destination(udp_packet.get_destination());
                        udp_pkt.set_length(payload_size as u16);
                        udp_pkt.set_payload(&modified_packet);
                        udp_pkt.set_checksum(0);
                        debug!("Constructed new udp packet: {:?}", udp_pkt);
                    }

                    let mut ipv4_buf = vec![0u8; buf.len() + 20];
                    {
                        // Copy original headers
                        ipv4_buf[..20].copy_from_slice(&header.packet()[..20]);
                        let mut ipv4_pkt = MutableIpv4Packet::new(&mut ipv4_buf[..]).unwrap();
                        ipv4_pkt.set_total_length(buf.len() as u16 + 20);
                        ipv4_pkt.set_payload(&buf);
                        ipv4_pkt.set_checksum(pnet::packet::ipv4::checksum(&ipv4_pkt.to_immutable()));
                        debug!("Constructed new ipv4 packet: {:?}", ipv4_pkt);
                    }
                    
                    msg.set_verdict_full(nfqueue_rs::Verdict::Accept, 0, &ipv4_buf);
                    return;
                }
            }
        }
    }

    msg.set_verdict(nfqueue_rs::Verdict::Accept);
}

fn output_callback(msg: &Message, state: &mut State) {
    let _scoped_timer = ScopedTimer::new(format!("Packet 0x{:x} processed", msg.get_id()));
    debug!(
        "Packet sent [id: 0x{:x}] mark: {}",
        msg.get_id(),
        msg.get_nfmark()
    );
    state.count += 1;

    let mut data = msg.get_payload().to_vec();
    let ip_header = MutableIpv4Packet::new(&mut data);

    if ip_header.is_none() {
        debug!("Non ipv4 packet received");
        msg.set_verdict(nfqueue_rs::Verdict::Accept);
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
                info!("OUTBOUND => {} => {} | {}", source, destination, uri);
                if let Ok(modified_packet) = apply_rules_to_sip_packet(
                    udp_packet.payload(),
                    state.ruleset.clone(),
                    Direction::Out,
                ) {
                    let payload_size = modified_packet.len();
                    let mut buf = vec![0u8; 8 + payload_size];
                    
                    {
                        let mut udp_pkt = MutableUdpPacket::new(&mut buf).unwrap();
                        udp_pkt.set_source(udp_packet.get_source());
                        udp_pkt.set_destination(udp_packet.get_destination());
                        udp_pkt.set_length(payload_size as u16);
                        udp_pkt.set_payload(&modified_packet);
                        udp_pkt.set_checksum(0);
                        debug!("Constructed new udp packet: {:?}", udp_pkt);
                    }

                    let mut ipv4_buf = vec![0u8; buf.len() + 20];
                    {
                        // Copy original headers
                        ipv4_buf[..20].copy_from_slice(&header.packet()[..20]);
                        let mut ipv4_pkt = MutableIpv4Packet::new(&mut ipv4_buf[..]).unwrap();
                        ipv4_pkt.set_total_length(buf.len() as u16 + 20);
                        ipv4_pkt.set_payload(&buf);
                        ipv4_pkt.set_checksum(pnet::packet::ipv4::checksum(&ipv4_pkt.to_immutable()));
                        debug!("Constructed new ipv4 packet: {:?}", ipv4_pkt);
                    }
                    
                    msg.set_verdict_full(nfqueue_rs::Verdict::Stop, 0, &ipv4_buf);
                    return;
                }
            }
        }
    }

    msg.set_verdict(nfqueue_rs::Verdict::Accept);
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
    let parts: Vec<&str> = payload.splitn(2, "\r\n\r\n").collect();

    let headers_str = parts[0];
    let body_str = if parts.len() > 1 { parts[1] } else { "" };

    let mut header_lines: Vec<String> = headers_str.split("\r\n").map(String::from).collect();

    for action in actions {
        match action {
            Action::Delete { key } => {
                debug!("Deleting headers: {:?}", key);
                for k in key {
                    for header in header_lines.iter_mut() {
                        if header.contains(k) {
                            info!("Deleting line: {}", header);
                        }
                    }
                }
                // Filter out lines that match the keys
                header_lines.retain(|header| !key.iter().any(|k| header.contains(k)));
            }
            Action::Add { key_value } => {
                debug!("Adding headers: {:?}", key_value);

                // Insert after first line
                for (k, v) in key_value {
                    info!("Adding header: {}: {}", k, v);

                    let new_line = format!("{}: {}", k, v);
                    header_lines.insert(1, new_line);
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
                for header in header_lines.iter_mut() {
                    if header.contains(key) {
                        *header = re.replace(header, replace.as_str()).to_string();
                    }
                }
            }
        }
    }

    let body_len = body_str.len();
    for header in header_lines.iter_mut() {
        let lower = header.to_lowercase();
        if lower.starts_with("content-length:") || lower.starts_with("l:") {
            *header = format!("Content-Length: {}", body_len);
            break;
        }
    }

    let new_headers = header_lines.join("\r\n");
    let final_buffer: String;

    if parts.len() == 2 {
        final_buffer = format!("{}\r\n\r\n{}", new_headers, parts[1]);
    } else {
        final_buffer = new_headers;
    }

    Ok(final_buffer)
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
