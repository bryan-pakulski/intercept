<p align="center">
<img width="320" height="320" alt="intercept" src="https://github.com/user-attachments/assets/b744a41b-5db2-48c7-b072-039de6439e3e" />
</p>

<h2 align="center">SIP packet interceptor for header manipulation, written in rust</h2>

# Usage
Set up libnetfilter queues to queue packets to the interceptor in userspace, we use bypass to allow packets to pass through when the interceptor is not running, we need two queues, one for input and one for OUTPUT so that we can determine the direction of the packet:

`sudo iptables -I INPUT -p udp --dport 5060 -j NFQUEUE --queue-num 0 --queue-bypass`
`sudo iptables -I OUTPUT -p udp --dport 5060 -j NFQUEUE --queue-num 1 --queue-bypass`

Run the interceptor:

`./intercept -q <queue-num>-r <ruleset>`


Cleanup:
`sudo iptables -D INPUT -p udp --dport 5060 -j NFQUEUE --queue-num 0 --queue-bypass`
`sudo iptables -D OUTPUT -p udp --dport 5060 -j NFQUEUE --queue-num 1 --queue-bypass`

## About

This is a simple SIP packet proxy / interceptor written in Rust. The main purpose is to sit inbetween two parties and modify SIP packets based on a ruleset.

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

## Debugging

Verbose logging can be enabled by setting the `RUST_LOG` environment variable to `debug` or calling directly with:

`RUST_LOG=debug ./intercept -q <queue-num> -r <ruleset>`