<h2 align="center">SIP packet interceptor for header manipulation, written in rust</h2>

<p align="center">
<img width="320" height="320" alt="intercept" src="https://github.com/user-attachments/assets/b744a41b-5db2-48c7-b072-039de6439e3e" />
</p>

# About

This is a simple SIP packet interceptor written in Rust with the intention of being used for testing & debugging SIP network stacks.

The main functionality of interceptor is to modify SIP headers based on user defined rulesets, providing
a quick and powerful way to manipulate voip traffic without the need to craft fully custom scenarios i.e. sipp

## Usage

This application relies on iptables / nfqueues to send packets to the interceptor in userspace.

We use a bypass flag on iptables to allow packets to pass through when the interceptor is not running.

In order to correctly operate we need two queues, one for INPUT and one for OUTPUT so that we can determine the direction of the packet:

#### Queue setup
```
sudo iptables -t mangle -I INPUT -p udp --dport 5060 -j NFQUEUE --queue-num 0 --queue-bypass
sudo iptables -t mangle -I OUTPUT -p udp --dport 5060 -j NFQUEUE --queue-num 1 --queue-bypass
```

#### Program usage

```
./intercept -i <input-queue-num> -o <output-queue-num> -r <ruleset>
```


#### Cleanup

```
sudo iptables -D INPUT -p udp --dport 5060 -j NFQUEUE --queue-num 0 --queue-bypass
sudo iptables -D OUTPUT -p udp --dport 5060 -j NFQUEUE --queue-num 1 --queue-bypass
```


## Dependencies
- libnetfilter_queue

## Rules

Intercept rules are simple JSON with some predefined insertion points allowing you to control what messages are modified based on direction / regex matching.

It is currently only intended to modify sip headers.

Formatting is as follows:

```

[
  {
    "uri" : "INVITE",             -> Message type, does a partial match against the URI on top of the message
    "direction": "in|out|both",   -> Direction to perform modifications
    "when": "always|once",        -> Only run once or always modify
    "match": "regex",             -> optional trigger, i.e. only run if a certain IP addr is present, if empty will always run actions
    "actions": [ 
      {"delete": ["Diversion", "History-Info"]},                                       -> Will delete any header/s present that match this key                                             (supports multiple)
      {"add": {"Diversion": "1234", "History-Info": "1234"}},                           -> Will add headers with the provided values                                                        (supports multiple)
      {"mod": {"Diversion": {"match": "regex", replace: "Field to replace with"}}},     -> Will take the requested header and replace matched values with the one provided                  (supports multiple)
    ],
  },
  ...
]

```

## Examples

Example rulesets can be found in the `examples/` folder.

## Development

A makefile is provided for convenience to build and run the interceptor. for testing simple rulesets you can use `nc` to send packets locally, i.e.:

```
echo "INVITE sip:99990243214321@10.10.10.123 SIP/2.0" | nc -u -w1 127.0.0.1 5060
```

## Debug logging

Verbose logging can be enabled by setting the `RUST_LOG` environment variable to `debug` or calling directly with:

`RUST_LOG=debug ./intercept -q <queue-num> -r <ruleset>`
