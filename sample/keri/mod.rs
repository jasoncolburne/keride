pub(crate) mod acdc;
pub(crate) mod kmi;
pub(crate) mod labels;
pub(crate) mod parsing;
pub(crate) mod verification;

use crate::error::Result;
use cesride::{
    common::Ids,
    data::{dat, Value},
    Diger, Matter, Saider, Salter, Siger, Signer, Verfer,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Serialize, Deserialize, Zeroize)]
pub struct KeySet {
    keys: Vec<String>,
    index_offset: usize,
    transferable: bool,
}

impl KeySet {
    pub fn generate(
        code: Option<&str>,
        count: Option<usize>,
        offset: usize,
        transferable: Option<bool>,
        path: &str,
        tier: Option<&str>,
        temp: Option<bool>,
    ) -> Result<Self> {
        let transferable = transferable.unwrap_or(false);
        let salter = Salter::new_with_defaults(tier)?;
        let mut keys = vec![];

        for signer in salter.signers(count, None, Some(path), code, Some(true), None, temp)? {
            keys.push(signer.qb64()?);
        }

        Ok(KeySet { keys, index_offset: offset, transferable })
    }

    #[allow(clippy::too_many_arguments)]
    fn generate_from_salt(
        salt: &[u8],
        code: Option<&str>,
        count: Option<usize>,
        offset: usize,
        transferable: Option<bool>,
        path: &str,
        tier: Option<&str>,
        temp: Option<bool>,
    ) -> Result<Self> {
        let transferable = transferable.unwrap_or(false);
        let salter = Salter::new(tier, None, Some(salt), None, None, None)?;
        let mut keys = vec![];

        for signer in
            &salter.signers(count, None, Some(path), code, Some(transferable), None, temp)?
        {
            keys.push(signer.qb64()?);
        }

        Ok(KeySet { keys, index_offset: offset, transferable })
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn transferable(&self) -> bool {
        self.transferable
    }

    fn signers(&self) -> Result<Vec<Signer>> {
        let mut result = vec![];

        for key in &self.keys {
            let signer = Signer::new_with_qb64(key, Some(self.transferable))?;
            result.push(signer);
        }

        Ok(result)
    }

    fn verfers(&self) -> Result<Vec<Verfer>> {
        let mut verfers = vec![];

        for signer in &self.signers()? {
            verfers.push(signer.verfer());
        }

        Ok(verfers)
    }

    pub fn verfers_qb64(&self) -> Result<Vec<String>> {
        let mut verfers_qb64 = vec![];

        for verfer in &self.verfers()? {
            verfers_qb64.push(verfer.qb64()?);
        }

        Ok(verfers_qb64)
    }

    fn digers(&self) -> Result<Vec<Diger>> {
        let mut digers = vec![];

        for verfer in &self.verfers()? {
            digers.push(Diger::new_with_ser(&verfer.qb64b()?, None)?);
        }

        Ok(digers)
    }

    pub fn digers_qb64(&self) -> Result<Vec<String>> {
        let mut digers_qb64 = vec![];

        for diger in &self.digers()? {
            digers_qb64.push(diger.qb64()?);
        }

        Ok(digers_qb64)
    }

    pub fn sign(&self, ser: &[u8]) -> Result<Vec<Siger>> {
        let mut sigers = vec![];

        for (i, signer) in self.signers()?.iter().enumerate() {
            let siger = signer.sign_indexed(ser, false, (self.index_offset + i) as u32, None)?;
            sigers.push(siger);
        }

        Ok(sigers)
    }
}

pub trait KeriStore {
    fn prefix(&self) -> String;

    fn insert_keys(&mut self, pre: &str, keys: &KeySet) -> Result<()>;
    fn insert_sad(&mut self, sad: &str) -> Result<()>;
    fn insert_acdc(&mut self, acdc: &str, issued: bool) -> Result<()>;
    fn insert_key_event(&mut self, pre: &str, event: &str) -> Result<()>;
    fn insert_transaction_event(&mut self, pre: &str, event: &str) -> Result<()>;
    // fn insert_exchange_event(&mut self, event: &str) -> Result<()>;

    fn get_current_keys(&self, pre: &str) -> Result<KeySet>;
    fn get_next_keys(&self, pre: &str) -> Result<KeySet>;

    fn get_sad(&self, said: &str) -> Result<Value>;
    fn get_acdc(&self, said: &str) -> Result<String>;
    // fn get_exchange_event(&self, inner_said: &str) -> Result<String>;
    // fn get_exchange_saids_for_acdc(&self, said: &str) -> Result<Vec<String>>;
    // fn get_blinded_aggregate(&self, digest: &str) -> Result<Value>;
    fn get_key_event(&self, pre: &str, version: u32) -> Result<String>;
    fn get_transaction_event(&self, pre: &str, version: u32) -> Result<String>;
    fn get_latest_establishment_event(&self, pre: &str) -> Result<(String, u128)>;
    fn get_latest_establishment_event_as_of_sn(&self, pre: &str, sn: u32)
        -> Result<(String, u128)>;
    fn get_latest_transaction_event(&self, pre: &str) -> Result<String>;

    fn get_latest_key_event_said(&self, pre: &str) -> Result<String>;
    fn get_latest_establishment_event_said(&self, pre: &str) -> Result<(String, u128)>;
    fn get_latest_establishment_event_said_as_of_sn(
        &self,
        pre: &str,
        sn: u32,
    ) -> Result<(String, u128)>;

    fn get_kel(&self, pre: &str) -> Result<Vec<String>>;
    fn get_tel(&self, pre: &str) -> Result<Vec<String>>;

    fn count_key_events(&self, pre: &str) -> Result<usize>;
    fn count_transaction_events(&self, pre: &str) -> Result<usize>;
    fn count_establishment_events(&self, pre: &str) -> Result<usize>;
}

pub(crate) fn saidify(sad: &str, label: Option<&str>, anonymize: Option<bool>) -> Result<String> {
    let value: serde_json::Value = serde_json::from_str(sad)?;
    let mut sad = Value::from(&value);
    crate::keri::saidify_value(&mut sad, label, anonymize, Some(false))?;
    sad.to_json()
}

pub(crate) fn saidify_value(
    sad: &mut Value,
    label: Option<&str>,
    anonymize: Option<bool>,
    overwrite: Option<bool>,
) -> Result<(Value, bool)> {
    let anonymize = anonymize.unwrap_or(false);
    let label = label.unwrap_or(Ids::d);
    let overwrite = overwrite.unwrap_or(false);

    let mut anonymizations: Vec<bool> = vec![];
    let mut anonymized;

    if sad.to_vec().is_ok() {
        for (index, val) in sad.to_vec()?.iter_mut().enumerate() {
            (sad[index], anonymized) =
                saidify_value(val, Some(label), Some(anonymize), Some(overwrite))?;
            anonymizations.push(anonymized)
        }
    } else if sad.to_map().is_ok() {
        for (key, val) in sad.to_map()?.iter_mut() {
            (sad[key.as_str()], anonymized) =
                saidify_value(val, Some(label), Some(anonymize), Some(overwrite))?;
            anonymizations.push(anonymized)
        }
    }

    // the name matched so we are reusing this mutable variable
    anonymized = false;
    let map_result = sad.to_map();
    if map_result.is_ok() {
        let map = map_result?;
        if map.contains_key(&label.to_string())
            && map[label].to_string().is_ok()
            && (overwrite || map[label].to_string()?.is_empty())
        {
            if anonymize && !anonymizations.iter().any(|v| *v) {
                sad["u"] = dat!(&Salter::new_with_defaults(None)?.qb64()?);
                anonymized = true;
            }
            let saider = Saider::new_with_sad(sad, Some(label), None, None, None)?;
            sad[label] = dat!(&saider.qb64()?);
        }
    }

    Ok((sad.clone(), anonymized))
}
