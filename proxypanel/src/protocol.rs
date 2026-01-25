use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ProtocolMode {
    Tcp,
    Udp,
    Both,
}

impl Default for ProtocolMode {
    fn default() -> Self {
        ProtocolMode::Tcp
    }
}

impl ProtocolMode {
    pub fn uses_tcp(self) -> bool {
        matches!(self, ProtocolMode::Tcp | ProtocolMode::Both)
    }

    pub fn uses_udp(self) -> bool {
        matches!(self, ProtocolMode::Udp | ProtocolMode::Both)
    }
}

pub const RULE_FIELD_HTML: &str = r#"
        <label>Protocol</label>
        <select id="protocol" onchange="syncJsonFromForm()">
          <option value="tcp">TCP</option>
          <option value="udp">UDP</option>
          <option value="both">Both</option>
        </select>
"#;

pub const RULE_HEADER_HTML: &str = r#"<th>Protocol</th>"#;

pub const RULE_JSON_FIELDS: &str = ", protocol";

pub const RULE_JS_HOOKS: &str = r#"
function protocolApplyTemplate(tpl) {
  const select = document.getElementById("protocol");
  if (select) {
    select.value = tpl.protocol || "tcp";
  }
}

function protocolSyncJson(payload) {
  const select = document.getElementById("protocol");
  if (select) {
    payload.protocol = select.value;
  }
}

function protocolSyncForm(payload) {
  const select = document.getElementById("protocol");
  if (select && payload.protocol !== undefined) {
    select.value = payload.protocol;
  }
}

function protocolReset() {
  const select = document.getElementById("protocol");
  if (select) {
    select.value = "tcp";
  }
}

function protocolNormalizePayload(payload) {
  if (!payload.protocol) {
    payload.protocol = "tcp";
  }
}

function protocolRenderRuleColumns(rule) {
  return `<td>${rule.protocol || "tcp"}</td>`;
}
"#;
