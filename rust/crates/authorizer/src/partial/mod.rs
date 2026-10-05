//! Type-aware partial evaluation preserves native residuals and known input data.
mod evaluate;
mod input;
mod residual;
mod resume;
pub(crate) use evaluate::{import_partial, partial_authorize};
pub(crate) use input::{PartialInput, PartialUidInput, parse_partial_entities};
pub(crate) use resume::reauthorize;
#[cfg(test)]
mod tests;
