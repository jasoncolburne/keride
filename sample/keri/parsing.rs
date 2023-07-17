use crate::error::{err, Error, Result};

use cesride::{
    common::{Identage, Ilkage},
    Creder, Sadder, Serder,
};
use parside::{message::GroupItem, CesrGroup, MessageList};

use super::{acdc, kmi, KeriStore};

use std::collections::HashSet;

fn seen_said(store: &impl KeriStore, said: &str) -> bool {
    store.get_sad(said).is_ok()
}

pub fn ingest_messages(
    store: &mut impl KeriStore,
    messages: &str,
    deep: Option<bool>,
    verify: Option<bool>,
    issuing: bool,
) -> Result<()> {
    let mut verifying = HashSet::new();

    let (_, message_list) = MessageList::from_stream_bytes(messages.as_bytes())?;
    let mut messages = message_list.messages.iter();

    loop {
        let sadder = messages.next();
        if let Some(sadder) = sadder {
            let payload = sadder.payload()?;
            let raw_string = payload.value.to_string();
            let raw_message = raw_string.as_bytes();
            let result = cesride::common::sniff(raw_message)?;

            // println!("{:?}", verifying);

            if result.ident == Identage::KERI {
                let serder = Serder::new_with_raw(raw_message)?;
                let said = serder.said()?;

                let message = messages.next();
                if let Some(message) = message {
                    let group = message.cesr_group()?;
                    match serder.ked()["t"].to_string()?.as_str() {
                        Ilkage::icp | Ilkage::rot | Ilkage::ixn => {
                            match group {
                                CesrGroup::AttachedMaterialQuadletsVariant { value } => {
                                    let existing =
                                        if verify.unwrap_or(true) && !verifying.contains(&said) {
                                            verifying.insert(said);
                                            kmi::verification::verify_key_event(
                                                store,
                                                &serder,
                                                value,
                                                deep,
                                                Some(&mut verifying),
                                                0,
                                            )?
                                        } else {
                                            seen_said(store, &said)
                                        };

                                    if !existing {
                                        let event = String::from_utf8(serder.raw())?;
                                        store.insert_key_event(
                                            &serder.pre()?,
                                            &(event + &group.qb64()?),
                                        )?;
                                        // println!("ingested key event {}", serder.said()?);
                                    }
                                }
                                _ => return err!(Error::Decoding), // we only accept pipelined input at present
                            }
                        }
                        Ilkage::vcp | Ilkage::iss | Ilkage::rev => match group {
                            CesrGroup::SealSourceCouplesVariant { value } => {
                                let existing =
                                    if verify.unwrap_or(true) && !verifying.contains(&said) {
                                        verifying.insert(said);
                                        acdc::tel::verification::verify_transaction_event(
                                            store,
                                            &serder,
                                            value,
                                            deep,
                                            Some(&mut verifying),
                                            0,
                                        )?
                                    } else {
                                        seen_said(store, &said)
                                    };

                                if !existing {
                                    let event = String::from_utf8(serder.raw())?;
                                    store.insert_transaction_event(
                                        &serder.pre()?,
                                        &(event + &group.qb64()?),
                                    )?;
                                    // println!("ingested transaction event {}", serder.said()?);
                                }
                            }
                            _ => return err!(Error::Decoding),
                        },
                        // Ilkage::qry => match group {
                        //     CesrGroup::SealSourceTriplesVariant { value: _ } => {
                        //         // TODO: verify anchor
                        //         let event = String::from_utf8(serder.raw())?;
                        //         store.insert_exchange_event(&(event + &group.qb64()?))?;
                        //         match serder.ked()["r"].to_string()?.as_str() {
                        //             "process/sad/data" => {
                        //                 store.insert_sad(&serder.ked()["a"].to_json()?)?;
                        //             }
                        //             "process/blinded/data" => {
                        //                 store.insert_blinded_aggregate(&serder.ked()["a"])?;
                        //             }
                        //             _ => return err!(Error::Decoding),
                        //         }
                        //     }
                        //     _ => return err!(Error::Decoding),
                        // },
                        // Ilkage::bar => match group {
                        //     CesrGroup::SealSourceTriplesVariant { value: _ } => {
                        //         match serder.ked()["r"].to_string()?.as_str() {
                        //             "process/sealed/data" => {
                        //                 for sad in &serder.ked()["a"].to_vec()? {
                        //                     // TODO: verify we are allowed to save this data
                        //                     store.insert_sad(&sad.to_json()?)?;
                        //                 }
                        //             }
                        //             _ => return err!(Error::Decoding),
                        //         }
                        //     }
                        //     _ => return err!(Error::Decoding),
                        // },
                        _ => return err!(Error::Decoding),
                    }
                } else {
                    return err!(Error::Decoding);
                }
            } else if result.ident == Identage::ACDC {
                let creder = Creder::new_with_raw(raw_message)?;
                let (cred, sads) = super::acdc::compact_acdc(&creder)?;
                // let cred = Creder::new_with_ked(&acdc, Some(&creder.code()), Some(&creder.kind()))?;

                let said = cred.said()?;

                let message = messages.next();
                if let Some(message) = message {
                    let group = message.cesr_group()?;
                    match group {
                        CesrGroup::SealSourceCouplesVariant { value } => {
                            let existing = if verify.unwrap_or(true) && !verifying.contains(&said) {
                                verifying.insert(said.clone());
                                acdc::verification::verify_acdc(store, &creder, value)?
                            } else {
                                seen_said(store, &said)
                            };

                            if !existing {
                                store.insert_acdc(
                                    &(cred.crd().to_json()? + &group.qb64()?),
                                    issuing,
                                )?;
                                for sad in &sads {
                                    store.insert_sad(&sad.to_json()?)?;
                                }
                                // println!("ingested acdc {}: {}", said, cred.crd().to_json()?);
                            }
                        }
                        _ => return err!(Error::Decoding), // we only accept pipelined input at present
                    };
                } else {
                    return err!(Error::Decoding);
                }
            } else {
                return err!(Error::Decoding);
            }
        } else {
            break;
        }
    }

    Ok(())
}
