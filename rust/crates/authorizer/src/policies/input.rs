use cgw_abi::Source;
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Input {
    Parse {
        id: String,
        source: Source,
    },
    Inspect {
        set: Source,
    },
    Add {
        set: Source,
        id: String,
        policy: Value,
    },
    Remove {
        set: Source,
        id: String,
    },
    Merge {
        set: Source,
        other: Source,
        rename_duplicates: bool,
    },
}
