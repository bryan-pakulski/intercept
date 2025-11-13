setup:
	sudo iptables -I INPUT -t mangle -p udp --dport 5060 -j NFQUEUE --queue-num 0 --queue-bypass
	sudo iptables -I OUTPUT -t mangle -p udp --dport 5060 -j NFQUEUE --queue-num 1 --queue-bypass

build:
	cargo build

release:
	cargo build --release

run: build
	sudo RUST_BACKTRACE=1 RUST_LOG=trace ./target/debug/intercept -i 0 -o 1 -r examples/modify_initial_invite.json

clean:
	sudo iptables -D INPUT -t mangle -p udp --dport 5060 -j NFQUEUE --queue-num 0 --queue-bypass
	sudo iptables -D OUTPUT -t mangle -p udp --dport 5060 -j NFQUEUE --queue-num 1 --queue-bypass
