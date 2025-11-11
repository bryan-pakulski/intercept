extern crate pnet;

use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use pnet::transport::{self, TransportChannelType, TransportProtocol};

use crate::rules::{Direction, Rule};
use log::{debug, info, warn};

pub fn listen(interface: &str, port: u16, ruleset: &Vec<Rule>) {
    // Find the network interface
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface: &NetworkInterface| iface.name == interface)
        .expect("Could not find the specified interface");

    // Collect local IP addresses
    let local_ips: Vec<_> = interface
        .ips
        .iter()
        .filter(|ip| ip.is_ipv4())
        .map(|ip| ip.ip())
        .collect();

    // Create a channel for reading packets
    let mut rx = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(_, rx)) => rx,
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    };

    // Create a channel for sending modified packets
    let (mut tx, _) = transport::transport_channel(
        4096,
        TransportChannelType::Layer3(IpNextHeaderProtocols::Udp),
    )
    .expect("Error creating transport channel");

    // One line iterator
    for ip in local_ips.iter() {
        println!("IP address: {}", ip);
    }
    println!("Listening on port {} {}", port, interface.name);

    loop {
        match rx.next() {
            Ok(packet) => {
                if let Some(ethernet_packet) = EthernetPacket::new(packet) {
                    if ethernet_packet.get_ethertype() == EtherTypes::Ipv4 {
                        if let Some(ipv4_packet) = Ipv4Packet::new(ethernet_packet.payload()) {
                            if ipv4_packet.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
                                if let Some(udp_packet) = UdpPacket::new(ipv4_packet.payload()) {
                                    if udp_packet.get_destination() == port {
                                        debug!(
                                            "UDP packet received: {}:{} => {}:{}",
                                            ipv4_packet.get_source(),
                                            udp_packet.get_source(),
                                            ipv4_packet.get_destination(),
                                            udp_packet.get_destination()
                                        );
                                        let payload = udp_packet.payload();
                                        if is_sip_packet(payload) {
                                            println!(
                                                "SIP packet received from: {}:{} => {}:{}",
                                                ipv4_packet.get_source(),
                                                udp_packet.get_source(),
                                                ipv4_packet.get_destination(),
                                                udp_packet.get_destination()
                                            );

                                            let direction = if local_ips
                                                .contains(&ipv4_packet.get_source().into())
                                            {
                                                Direction::Out
                                            } else if local_ips
                                                .contains(&ipv4_packet.get_destination().into())
                                            {
                                                Direction::In
                                            } else {
                                                debug!(
                                                    "Unable to determine direction, skipping..."
                                                );
                                                println!("Unable to determine direction, skipping packet...");
                                                continue;
                                            };

                                            apply_rules_to_sip_packet(payload);

                                            let mut mod_packet =
                                                MutableEthernetPacket::owned(packet.to_vec())
                                                    .unwrap();

                                            modify_packet(&mut mod_packet);

                                            tx.send_to(
                                                mod_packet,
                                                std::net::IpAddr::V4(ipv4_packet.get_destination()),
                                            )
                                            .expect("Failed to send packet");
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => println!("Error reading...: {}", e),
        }
    }
}

fn is_sip_packet(payload: &[u8]) -> bool {
    // A very naive check
    if let Ok(payload_str) = std::str::from_utf8(payload) {
        if payload_str.contains("SIP/2.0") {
            return true;
        }
    }
    false
}

// Placeholder for your implementation of applying rules
fn apply_rules_to_sip_packet(payload: &[u8]) {
    println!(
        "Processing SIP packet: {:?}",
        String::from_utf8_lossy(payload)
    );
    // Insert your rule processing code here
}

// Implement your packet modification logic
fn modify_packet(packet: &mut MutableEthernetPacket) {
    // Add your logic to modify the packet here
}
