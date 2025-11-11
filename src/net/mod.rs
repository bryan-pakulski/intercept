use crate::error::{BackendError, BackendErrorKind};
use crate::rules::{Rule, Direction, When};

use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::net::IpAddr;

use std::sync::{Arc, RwLock};
use log::{debug, info, warn};
use nfqueue::Message;
use regex::Regex;

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
    let state = State { count: 0, ruleset: Arc::new(RwLock::new(ruleset)) };

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
    debug!("Packet received [id: 0x{:x}]\n", msg.get_id());
    state.count += 1;

    if let Some(header) = Ipv4Packet::new(msg.get_payload()) {
        match header.get_next_level_protocol() {
            IpNextHeaderProtocols::Udp => {
                if let Some(payload) = UdpPacket::new(header.payload()) {
                    if is_sip_packet(payload.payload()) {
                        let source = IpAddr::V4(header.get_source());
                        let destination = IpAddr::V4(header.get_destination());

                        if let Ok(uri) = get_uri(payload.payload()) {
                            println!("INBOUND => {} => {} | {}", source, destination, uri);
                            if let Ok(modified_packet) =
                                apply_rules_to_sip_packet(payload.payload(), state.ruleset.clone(), Direction::In)
                            {
                                // Send modified packet
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
    debug!("Packet sent [id: 0x{:x}]\n", msg.get_id());
    state.count += 1;

    if let Some(header) = Ipv4Packet::new(msg.get_payload()) {
        match header.get_next_level_protocol() {
            IpNextHeaderProtocols::Udp => {
                if let Some(payload) = UdpPacket::new(header.payload()) {
                    if is_sip_packet(payload.payload()) {
                        let source = IpAddr::V4(header.get_source());
                        let destination = IpAddr::V4(header.get_destination());

                        if let Ok(uri) = get_uri(payload.payload()) {
                            println!("OUTBOUND => {} => {} | {}", source, destination, uri);
                            if let Ok(modified_packet) =
                                apply_rules_to_sip_packet(payload.payload(), state.ruleset.clone(), Direction::Out)
                            {
                                // Send modified packet
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

fn apply_rules_to_sip_packet(
    payload: &[u8],
    ruleset: Arc<RwLock<Vec<Rule>>>,
    direction: Direction,
) -> Result<Vec<u8>, BackendError> {
    let uri = get_uri(payload)?;

    for rule in ruleset.read().unwrap().iter() {

        // URI match
        debug!("Checking rule \"{}\" in uri: \"{}\"", rule.uri, uri);
        if !uri.contains(&rule.uri) {
            debug!("URI did not match rule \"{}\"", rule.uri);
            continue;
        }
        debug!("URI matched rule \"{}\"", rule.uri);
        
        // Direction match
        if rule.direction != direction && rule.direction != Direction::Both {
            debug!("Direction \"{}\" did not match rule \"{}\"", direction, rule.direction);
            continue;
        }
        debug!("Direction \"{}\" matched rule \"{}\"", direction, rule.direction);
        
        // Match regex
        if let Some(regex) = &rule.match_regex {
            debug!("Checking rule \"{}\" in regex \"{}\"", rule.match_regex.as_ref().unwrap(), regex);
            if !regex_match(regex, payload) {
                continue;
            }
            debug!("Regex matched rule \"{}\"", rule.match_regex.as_ref().unwrap());
        }

        // Trigger match
        match rule.when {
            When::Always => {
                debug!("Trigger matched rule \"always\"");
            },
            When::Once => {
                debug!("Trigger matched rule \"once\"");
            }
        }
    }

    Ok(vec![])
}
