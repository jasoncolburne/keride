pub(crate) mod endorsement;
pub(crate) mod event;
pub(crate) mod message;
pub(crate) mod schemer;
pub(crate) mod tel;
pub(crate) mod verification;

use super::KeriStore;
use crate::error::{err, Error, Result};
use cesride::{
    common::Ids,
    counter,
    data::{dat, Value},
    Counter, Creder, Matter, Sadder, Saider, Seqner, Serder,
};

pub(crate) fn compact_acdc(creder: &Creder) -> Result<(Creder, Vec<Value>)> {
    let mut crd = creder.crd();
    let mut sads = vec![];

    compact_sad(&mut crd, &mut sads)?;

    Ok((Creder::new_with_ked(&crd, Some(&creder.code()), Some(&creder.kind()))?, sads))
}

pub(crate) fn compact_sad(sad: &mut Value, sads: &mut Vec<Value>) -> Result<(Value, Vec<Value>)> {
    let map = sad.to_map()?;
    for (key, mut value) in map.clone() {
        sad[key.as_str()] = if value.to_map().is_ok() {
            compact_sad(&mut value, sads)?;

            if value.to_map()?.contains_key("d") {
                sads.push(value.clone());
                value["d"].clone()
            } else {
                value
            }
        } else {
            value
        };
    }

    if map.contains_key("d") {
        let (saider, _) = Saider::saidify(sad, None, None, None, None)?;
        sad["d"] = dat!(&saider.qb64()?);
    }

    Ok((sad.clone(), sads.clone()))
}

pub(crate) fn expand_acdc(
    creder: &Creder,
    to_expand: &[Vec<&str>],
    store: &impl KeriStore,
) -> Result<Creder> {
    let mut crd = creder.crd();

    for path in to_expand {
        let mut value = &mut crd;
        for (i, component) in path.iter().enumerate() {
            if i == path.len() - 1 {
                value[*component] = store.get_sad(&value[*component].to_string()?)?;
            } else {
                value = &mut value[*component];
            }
        }
    }

    super::saidify_value(&mut crd, Some(Ids::d), Some(false), Some(true))?;
    Creder::new_with_ked(&crd, Some(&creder.code()), Some(&creder.kind()))
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
pub fn issue_acdc(
    store: &impl KeriStore,
    status: &str, // public management tel registry identifier
    issuer: &str, // controlled identifier label
    schema: &str,
    data: &str,
    recipient: Option<&str>,
    private: Option<bool>,
    source: Option<&str>,
    rules: Option<&str>,
    partially_disclosable: Option<&str>,
) -> Result<(String, String, String, String, Vec<Value>)> {
    let value: serde_json::Value = serde_json::from_str(data)?;
    let data = Value::from(&value);

    let rules_value;
    let source_value;
    let partially_disclosable_value;

    let rules = if let Some(rules) = rules {
        let value: serde_json::Value = serde_json::from_str(rules)?;
        rules_value = Value::from(&value);
        Some(&rules_value)
    } else {
        None
    };

    let source = if let Some(source) = source {
        let value: serde_json::Value = serde_json::from_str(source)?;
        source_value = Value::from(&value);
        Some(&source_value)
    } else {
        None
    };

    let partially_disclosable = if let Some(partially_disclosable) = partially_disclosable {
        let value: serde_json::Value = serde_json::from_str(partially_disclosable)?;
        partially_disclosable_value = Value::from(&value);
        Some(&partially_disclosable_value)
    } else {
        None
    };

    let (acdc, sads) = event::create(
        schema,
        issuer,
        &data,
        recipient,
        private,
        None,
        Some(status),
        source,
        rules,
        partially_disclosable,
        None,
        None,
    )?;

    let acdc_said = acdc.said()?;
    let (iss_said, iss) = tel::vc::issue(&acdc_said, status)?;

    let sn = store.count_key_events(issuer)? as u128;
    let dig = store.get_latest_key_event_said(issuer)?;
    let data = dat!([{
        "i": &acdc_said,
        "s": "0",
        "d": &iss_said,
    }]);
    let keys = store.get_current_keys(issuer)?;
    let (ixn_said, ixn) = super::kmi::interact(&keys, issuer, &dig, sn, &data)?;
    drop(keys);

    let counter = Counter::new_with_code_and_count(counter::Codex::SealSourceCouples, 1)?;
    let seqner = Seqner::new_with_sn(sn)?;
    let iss = iss + &counter.qb64()? + &seqner.qb64()? + &ixn_said;
    let acdc = acdc.crd().to_json()? + &counter.qb64()? + &seqner.qb64()? + &ixn_said;

    Ok((acdc_said, ixn, iss, acdc, sads))
}

pub fn revoke_acdc(
    store: &impl KeriStore,
    status: &str,
    issuer: &str,
    said: &str,
) -> Result<(String, String)> {
    let priors = store.get_tel(said)?;
    if priors.len() != 1 {
        return err!(Error::Value);
    }
    let serder = Serder::new_with_raw(priors[0].as_bytes())?;

    let (rev_said, rev) = tel::vc::revoke(said, status, &serder.said()?)?;

    let sn = store.count_key_events(issuer)? as u128;
    let dig = store.get_latest_key_event_said(issuer)?;
    let data = dat!([{
        "i": said,
        "s": "1",
        "d": &rev_said,
    }]);
    let key_set = store.get_current_keys(issuer)?;
    let (ixn_said, ixn) = super::kmi::interact(&key_set, issuer, &dig, sn, &data)?;
    drop(key_set);

    let counter = Counter::new_with_code_and_count(counter::Codex::SealSourceCouples, 1)?;
    let seqner = Seqner::new_with_sn(sn)?;
    let rev = rev + &counter.qb64()? + &seqner.qb64()? + &ixn_said;

    Ok((ixn, rev))
}
