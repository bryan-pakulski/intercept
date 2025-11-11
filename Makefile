setup:
	sudo iptables -I INPUT -p udp --dport 5060 -j NFQUEUE --queue-num 0 --queue-bypass
	sudo iptables -I OUTPUT -p udp --dport 5060 -j NFQUEUE --queue-num 1 --queue-bypass

build:
	cargo build

run: build
	sudo RUST_LOG=debug ./target/debug/intercept -i 0 -o 1 -r examples/modify_initial_invite.json

clean:
	sudo iptables -D INPUT -p udp --dport 5060 -j NFQUEUE --queue-num 0 --queue-bypass
	sudo iptables -D OUTPUT -p udp --dport 5060 -j NFQUEUE --queue-num 1 --queue-bypass
