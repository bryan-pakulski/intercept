<p align="center">
<img width="320" height="320" alt="intercept" src="https://github.com/user-attachments/assets/b744a41b-5db2-48c7-b072-039de6439e3e" />
</p>

<h2 align="center">SIP packet interceptor for header manipulation, written in rust</h2>

# Usage
`./intercept -i <interface> -p <port> -r <ruleset>`

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

Example rulesets can be found in the examples folder.

## Debugging

Verbone logging can be enabled by setting the `RUST_LOG` environment variable to `debug` or calling directly with:

`RUST_LOG=debug ./intercept -i <interface> -p <port> -r <ruleset>`