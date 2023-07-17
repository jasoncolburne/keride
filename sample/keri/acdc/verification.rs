use crate::error::{err, Error, Result};

use cesride::{
    common::{Ids, Ilkage, Serialage},
    data::{dat, Value},
    Creder, Matter, Sadder, Saider, Serder,
};
use parside::{message::SealSourceCouples, Group};

use super::super::KeriStore;
use super::schemer::cache as schema_cache;

const DEFAULT_CREDENTIAL_EXPIRY_SECONDS: i64 = 36000000000;

pub(crate) fn chains_to_saids(chains: &Value) -> Result<Vec<String>> {
    let chains = chains.clone();
    let edges = if chains.to_map().is_ok() {
        vec![chains]
    } else if chains.to_vec().is_ok() {
        chains.to_vec()?
    } else {
        return err!(Error::Verification);
    };

    let mut result = vec![];
    for edge in &edges {
        for (label, node) in edge.to_map()? {
            if [Ids::d, "o"].contains(&label.as_str()) {
                continue;
            }

            result.push(node["n"].to_string()?);
        }
    }

    Ok(result)
}

pub(crate) fn acdc_status(store: &impl KeriStore, said: &str) -> Result<bool> {
    let message = store.get_acdc(said)?;
    let acdc = Creder::new_with_raw(message.as_bytes())?;

    let vc = acdc.crd().to_map()?;
    let prov = if vc.contains_key("e") {
        let mut sad = store.get_sad(&vc["e"].to_string()?)?;
        for (key, _) in sad.to_map()? {
            if !["d", "o"].contains(&key.as_str()) {
                sad[key.as_str()] = store.get_sad(&sad[key.as_str()].to_string()?)?;
            }
        }
        sad
    } else {
        dat!({})
    };

    for edge in &chains_to_saids(&prov)? {
        if !acdc_status(store, edge)? {
            return Ok(false);
        }
    }

    let event = store.get_latest_transaction_event(said)?;
    let state = Serder::new_with_raw(event.as_bytes())?;

    let dtnow = chrono::Utc::now();
    let dte = chrono::DateTime::parse_from_rfc3339(&state.ked()["dt"].to_string()?)?
        .with_timezone(&chrono::Utc);
    if (dtnow - dte).num_seconds() > DEFAULT_CREDENTIAL_EXPIRY_SECONDS {
        return err!(Error::Validation);
    }

    Ok(![Ilkage::rev, Ilkage::brv].contains(&state.ked()["t"].to_string()?.as_str()))
}

pub(crate) fn verify_acdc(
    store: &impl KeriStore,
    creder: &Creder,
    seal_source_couples: &SealSourceCouples,
) -> Result<bool> {
    if creder.status()?.is_none() {
        return err!(Error::Validation);
    };

    let (compacted, _) = super::compact_acdc(creder)?;

    let vcid = compacted.said()?;
    let schema = creder.schema()?;

    let vc = creder.crd().to_map()?;
    let prov = if vc.contains_key("e") {
        let string_result = vc["e"].to_string();
        if string_result.is_ok() {
            store.get_sad(&string_result?)?
        } else {
            vc["e"].clone()
        }
    } else {
        dat!({})
    };

    let saider = Saider::new_with_qb64(&creder.said()?)?;
    if !saider.verify(&creder.crd(), Some(false), Some(true), Some(Serialage::JSON), None, None)? {
        return err!(Error::Verification);
    }

    let event = store.get_latest_transaction_event(&vcid)?;
    let state = Serder::new_with_raw(event.as_bytes())?;
    let dtnow = chrono::Utc::now();
    let dte = chrono::DateTime::parse_from_rfc3339(&state.ked()["dt"].to_string()?)?
        .with_timezone(&chrono::Utc);
    if (dtnow - dte).num_seconds() > DEFAULT_CREDENTIAL_EXPIRY_SECONDS {
        return err!(Error::Validation);
    }

    // added brv here for safety even though unimplemented
    if [Ilkage::rev, Ilkage::brv].contains(&state.ked()[Ids::t].to_string()?.as_str()) {
        return err!(Error::Validation);
    }

    if !schema_cache().verify(&schema, std::str::from_utf8(&creder.raw())?)? {
        return err!(Error::Validation);
    }

    if seal_source_couples.value.len() != 1 {
        return err!(Error::Decoding);
    }
    let source_saider = &seal_source_couples.value()[0].saider;
    let source_seqner = &seal_source_couples.value()[0].seqner;

    let key_event = store.get_key_event(&creder.issuer()?, source_seqner.sn()? as u32)?;
    let serder = Serder::new_with_raw(key_event.as_bytes())?;

    if source_saider.qb64()? != serder.said()? {
        return err!(Error::Verification);
    }

    let mut rooted = false;

    let seals = serder.ked()["a"].to_vec()?;
    for seal in &seals {
        if seal["i"].to_string()? == vcid {
            rooted = true;
        }
    }

    if !rooted {
        return err!(Error::Verification);
    }

    let edges = if prov.to_map().is_ok() {
        vec![prov]
    } else if prov.to_vec().is_ok() {
        prov.to_vec()?
    } else {
        return err!(Error::Verification);
    };

    for edge in &edges {
        for (label, node) in edge.to_map()? {
            if [Ids::d, "o"].contains(&label.as_str()) {
                continue;
            }

            let node =
                if node.to_string().is_ok() { store.get_sad(&node.to_string()?)? } else { node };

            let map = node.to_map()?;

            let node_said = map["n"].to_string()?;
            let message = store.get_acdc(&node_said)?;
            let pacdc = Creder::new_with_raw(message.as_bytes())?;

            if map.contains_key("s") {
                let node_schema = map["s"].to_string()?;
                if !schema_cache().verify(&node_schema, std::str::from_utf8(&pacdc.raw())?)? {
                    return err!(Error::Validation);
                }
            }

            let mut operators = if map.contains_key("o") {
                let result = map["o"].to_string();
                if result.is_ok() {
                    vec![result?]
                } else {
                    map["o"].to_vec()?.iter().map(|o| o.to_string().unwrap()).collect()
                }
            } else {
                vec![]
            };

            // capture not, and remove everything but unary operators
            let not = operators.contains(&"NOT".to_string());
            if not {
                return err!(Error::Value);
            }
            let mut indices = vec![];
            for (i, value) in operators.iter().enumerate() {
                if value == "NOT" || !["I2I", "NI2I", "DI2I"].contains(&value.as_str()) {
                    indices.push(i);
                }
            }
            indices.reverse();
            for index in indices {
                operators.remove(index);
            }

            // if we have nothing left, add defaults
            let subject_said = pacdc.crd()["a"].to_string()?;
            let data = store.get_sad(&subject_said)?;
            let node_subject = data.to_map()?;
            if operators.is_empty() {
                if node_subject.contains_key(&"i".to_string()) {
                    operators.push("I2I".to_string());
                } else {
                    operators.push("NI2I".to_string());
                }
            }

            // if the programmer specified two unary operators, we have a problem
            if operators.len() != 1 {
                return err!(Error::Validation);
            }

            // actual validation logic
            match operators[0].as_str() {
                "I2I" => {
                    if node_subject["i"].to_string()? != creder.issuer()? {
                        return err!(Error::Validation);
                    }
                }
                "NI2I" => {}
                "DI2I" => unimplemented!(),
                _ => return err!(Error::Validation),
            }

            if !acdc_status(store, &node_said)? {
                return err!(Error::Validation);
            }
        }
    }

    let result = store.get_acdc(&vcid);
    let existing = result.is_ok();
    if existing {
        let message = result.unwrap();
        let eacdc = Creder::new_with_raw(message.as_bytes())?;

        // this seems very bad, it means something is in the database that shouldn't be there. how did it get there?
        if vcid != eacdc.said()? {
            return err!(Error::Programmer);
        }
    }

    Ok(existing)
}
