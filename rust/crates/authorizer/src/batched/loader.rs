use crate::entity_uid;
use cedar_policy::{Entities, Entity, EntityLoader, EntityUid, Schema};
use cgw_abi::{Callback, OpError};
use serde::Deserialize;
use serde_json::value::RawValue;
use std::collections::{HashMap, HashSet};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Batch {
    entities: Vec<Box<RawValue>>,
    missing: Vec<serde_json::Value>,
}

fn exchange(callback: Callback, bytes: &[u8], max_bytes: usize) -> Result<Vec<u8>, OpError> {
    let mut input = bytes.to_vec();
    let len = callback.call(1, &mut input);
    if len <= 0 || len as usize > max_bytes {
        return Err(OpError::msg("loader", "invalid loader response size"));
    }
    let mut out = vec![0; len as usize];
    if callback.call(2, &mut out) != 0 {
        return Err(OpError::msg("loader", "entity loader read failed"));
    }
    Ok(out)
}

pub(super) struct Loader<'a> {
    pub(super) schema: &'a Schema,
    pub(super) cached: &'a Entities,
    pub(super) max_bytes: usize,
    pub(super) callback: Callback,
    pub(super) error: Option<OpError>,
}

impl Loader<'_> {
    fn batch(
        &self,
        uids: &HashSet<EntityUid>,
    ) -> Result<HashMap<EntityUid, Option<Entity>>, OpError> {
        let mut found = HashMap::new();
        let mut missing = Vec::new();
        for uid in uids {
            match self.cached.get(uid) {
                Some(entity) => {
                    found.insert(uid.clone(), Some(entity.clone()));
                }
                None => missing.push(uid),
            }
        }
        if missing.is_empty() {
            return Ok(found);
        }
        missing.sort_unstable();
        let bytes = serde_json::to_vec(
            &missing
                .iter()
                .map(|id| serde_json::json!({"type": id.type_name().to_string(), "id": id.id().unescaped()}))
                .collect::<Vec<_>>(),
        )
        .map_err(|e| OpError::msg("loader", e.to_string()))?;
        let batch: Batch =
            serde_json::from_slice(&exchange(self.callback, &bytes, self.max_bytes)?)
                .map_err(|e| OpError::msg("entities", e.to_string()))?;
        for json in batch.entities {
            let entity = Entity::from_json_str(json.get(), Some(self.schema))
                .map_err(|e| OpError::new("entities", &e))?;
            if self.cached.get(&entity.uid()).is_some() {
                return Err(OpError::msg(
                    "entities",
                    "loader cannot redefine a cached entity",
                ));
            }
            if found.insert(entity.uid(), Some(entity)).is_some() {
                return Err(OpError::msg("entities", "duplicate loaded entity UID"));
            }
        }
        for json in batch.missing {
            let uid = entity_uid(json, "entities")?;
            if self.cached.get(&uid).is_some() {
                return Err(OpError::msg(
                    "entities",
                    "loader cannot mark a cached entity missing",
                ));
            }
            if found.insert(uid, None).is_some() {
                return Err(OpError::msg(
                    "entities",
                    "duplicate or conflicting missing UID",
                ));
            }
        }
        Ok(found)
    }
}

impl EntityLoader for Loader<'_> {
    fn load_entities(&mut self, uids: &HashSet<EntityUid>) -> HashMap<EntityUid, Option<Entity>> {
        if self.error.is_some() {
            return HashMap::new();
        }
        match self.batch(uids) {
            Ok(batch) => batch,
            Err(err) => {
                // Upstream's infallible trait requires latching failures until evaluation returns.
                self.error = Some(err);
                HashMap::new()
            }
        }
    }
}
