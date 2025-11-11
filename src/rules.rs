use serde_derive::Deserialize;
use std::collections::HashMap;

#[derive(Deserialize, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    In,
    Out,
    Both,
}

impl std::fmt::Display for Direction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Direction::In => write!(f, "in"),
            Direction::Out => write!(f, "out"),
            Direction::Both => write!(f, "both"),
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum When {
    Always,
    Once,
}

#[derive(Deserialize, Debug)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Action {
    Delete {
        key: Vec<String>,
    },
    Add {
        key_value: HashMap<String, String>,
    },
    Mod {
        key: String,
        match_pattern: String,
        replace: String,
    },
}

#[derive(Deserialize, Debug)]
pub struct Rule {
    pub uri: String,
    pub direction: Direction,
    pub when: When,
    #[serde(default)]
    pub match_regex: Option<String>,
    pub actions: Vec<Action>,

    // Not included in the JSON, internal state, incremented on each trigger
    #[serde(skip)]
    pub trigger_count: usize,
}

// Tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize() {
        let json_data = r#"
        [
          {
            "uri": "INVITE",
            "direction": "both",
            "when": "always",
            "match": "",
            "actions": [
              {
                "type": "delete",
                "key": ["Diversion", "History-Info"]
              },
              {
                "type": "add",
                "key_value": { "Diversion": "1234", "History-Info": "1234" }
              },
              {
                "type": "mod",
                "key": "Diversion",
                "match_pattern": "regex-pattern",
                "replace": "Field to replace with"
              }
            ]
          },
          {
            "uri": "200 OK",
            "direction": "in",
            "when": "once",
            "match": "",
            "actions": [
              {
                "type": "delete",
                "key": ["Require"]
              }
            ]
          }
        ]
        "#;

        let rules: Vec<Rule> = serde_json::from_str(json_data).unwrap();

        assert_eq!(rules.len(), 2);
    }
}
