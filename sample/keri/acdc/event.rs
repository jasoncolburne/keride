use crate::error::Result;
use cesride::{
    common::{versify, Identage, Ids, Serialage, Tierage, Version, CURRENT_VERSION},
    data::{dat, Value},
    Creder, Matter, Saider, Salter,
};

#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn create(
    schema: &str,
    issuer: &str,
    data: &Value,
    recipient: Option<&str>,
    private: Option<bool>,
    salt: Option<&str>,
    status: Option<&str>,
    source: Option<&Value>,
    rules: Option<&Value>,
    partially_disclosable: Option<&Value>,
    version: Option<&Version>,
    kind: Option<&str>,
) -> Result<(Creder, Vec<Value>)> {
    let private = private.unwrap_or(false);
    let version = version.unwrap_or(CURRENT_VERSION);
    let kind = kind.unwrap_or(Serialage::JSON);

    let vs = versify(Some(Identage::ACDC), Some(version), Some(kind), Some(0))?;

    let mut vc = dat!({
        "v": &vs,
        "d": ""
    });

    let mut subject = dat!({
        "d": ""
    });

    if private {
        vc["u"] = if let Some(salt) = salt {
            dat!(salt)
        } else {
            dat!(&Salter::new_with_defaults(Some(Tierage::low))?.qb64()?)
        };

        subject["u"] = if let Some(salt) = salt {
            dat!(salt)
        } else {
            dat!(&Salter::new_with_defaults(Some(Tierage::low))?.qb64()?)
        };
    }

    if let Some(recipient) = recipient {
        subject["i"] = dat!(recipient);
    }

    let data_map = data.to_map()?;
    subject["dt"] = if data_map.contains_key("dt") {
        data_map["dt"].clone()
    } else {
        dat!(&chrono::Utc::now().format("%+").to_string())
    };

    for (label, value) in data_map {
        subject[label.as_str()] = value
    }

    vc[Ids::i] = dat!(issuer);

    if let Some(status) = status {
        vc["ri"] = dat!(status);
    }

    vc["s"] = dat!(schema);
    vc["a"] = dat!({});

    let mut sads = vec![];

    if let Some(source) = source {
        let (edges, _) = super::compact_sad(&mut source.clone(), &mut sads)?;
        vc["e"] = edges["d"].clone();
        sads.push(edges);
    }

    if let Some(rules) = rules {
        let (rules, _) = super::compact_sad(&mut rules.clone(), &mut sads)?;
        vc["r"] = rules["d"].clone();
        sads.push(rules);
    }

    if let Some(partially_disclosable) = partially_disclosable {
        let map = partially_disclosable.to_map()?;

        for (key, value) in &map {
            let sad = dat!({
                "d": "",
                "u": &Salter::new_with_defaults(Some(Tierage::low))?.qb64()?,
                "value": value.clone()
            });

            let (_, sad) = Saider::saidify(&sad, None, Some(kind), Some(Ids::d), None)?;
            subject[key.as_str()] = sad;
        }
    }

    let (sad, _) = super::compact_sad(&mut subject.clone(), &mut sads)?;
    vc["a"] = sad["d"].clone();
    sads.push(sad);

    let (_, vc) = Saider::saidify(&vc, None, Some(kind), Some(Ids::d), None)?;
    let creder = Creder::new_with_ked(&vc, None, None)?;

    Ok((creder, sads))
}
