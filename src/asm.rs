use std::{borrow::Cow, collections::BTreeMap, fs::File, io::{self, BufRead, BufReader}, mem, path::PathBuf, sync::LazyLock};

use anyhow::{bail, ensure, Context};
use bytes::Bytes;
use clap::Parser;
use indexmap::IndexMap;
use regex::Regex;
use base64::prelude::*;

use crate::stcm2::{Action, Parameter, Stcm2};

#[derive(Parser)]
pub struct Args {
    file: PathBuf
}

static INITIAL_ADDRESS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[0-9A-F]{6} ").unwrap());
static LABEL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^((?:[!-\[\]-~]|\\x[0-9a-f]{2})+): ").unwrap());

pub fn main(args: Args) -> anyhow::Result<()> {
    let mut lines = BufReader::new(File::open(args.file)?).lines().collect::<io::Result<Vec<_>>>()?;

    for line in lines.iter_mut() {
        if let Cow::Owned(l) = INITIAL_ADDRESS.replace(line, "") {
            *line = l;
        }
    }

    ensure!(lines.first().is_some_and(|tag| tag.is_ascii() && tag.len() >= 7 && tag.starts_with(".tag \"") && tag.ends_with("\"")),
        "improper tag");
    
    let tag = Bytes::from(mem::take(&mut lines[0]).into_bytes());
    let tag = tag.slice(6..tag.len()-1);

    ensure!(lines.get(1).is_some_and(|gd| gd.is_ascii() && gd.starts_with(".global_data ")),
        "improper global data");
    
    let global_data = Bytes::from(BASE64_STANDARD_NO_PAD.decode(&lines[1][13..])?);

    ensure!(lines.get(2).map(|s| &s[..]) == Some(".code_start"), "improper code start");

    let code = &lines[3..];

    let mut actions = Vec::new();

    // a table of references that are yet to be resolved
    // the index is used to calculate the sentinel value which is used for global calls and pointers
    let mut pending_references = IndexMap::new();

    for instr in code {
        let count = u32::try_from(actions.len())?;

        let mut instr = &instr[..];

        let mut label = LABEL.captures(instr).map(|label| {
            instr = instr.strip_prefix(label.get(0).unwrap().as_str()).unwrap();
            label.get(1).unwrap().as_str()
        });

        if let Some(lbl) = label {
            pending_references.insert(lbl, Some(count));
            if lbl.starts_with("local_") {
                label = None;
            }
        }

        if instr == "return" {
            actions.push(Action {
                export: label.map(|s| Bytes::from(s.to_owned().into_bytes())),
                call: false,
                opcode: 0,
                params: Vec::new(),
                data: Bytes::new()
            });
            continue;
        }

        let mut split = instr.split(" ! ").fuse();
        let text = split.next().context("huh")?;
        let data = split.next();
        ensure!(split.next().is_none(), "huh2");

        let mut split = text.split(", ").fuse();
        let op = split.next().context("huh3")?;

        let (call, opcode) = if let Some(op) = op.strip_prefix("raw ") {
            let opcode = u32::from_str_radix(op, 16)?;
            (false, opcode)
        } else if let Some(op) = op.strip_prefix("call ") {
            let ent = pending_references.entry(op);
            let idx = ent.index();
            ent.or_default();
            let opcode = !u32::try_from(idx)?;
            (true, opcode)
        } else {
            bail!("invalid op {op}");
        };

        let params = split.map(|param| Ok(if let Some(param) = param.strip_prefix('[') {
            let param = param.strip_suffix(']').context("no matching bracket??")?;
            if let Some(ptr) = param.strip_prefix("data+") {
                Parameter::LocalPointer(ptr.parse()?)
            } else {
                let ent = pending_references.entry(param);
                let idx = ent.index();
                ent.or_default();
                let ptr = !u32::try_from(idx)?;
                Parameter::GlobalPointer(ptr)
            }
        } else {
            Parameter::Value(u32::from_str_radix(param, 16)?)
        })).collect::<anyhow::Result<Vec<Parameter>>>()?;

        let data = Bytes::from(data.iter().flat_map(|d| d.split(", ")).try_fold(Vec::new(), |mut buffer, mut incoming| {
            if incoming.starts_with(['"', '@']) {
                let canonical = if let Some(s) = incoming.strip_prefix('@') {
                    incoming = s;
                    false
                } else {
                    true
                };
                incoming = incoming
                    .strip_prefix('"').context("no starting quote")?
                    .strip_suffix('"').context("no ending quote")?;
                todo!()
            } else {
                BASE64_STANDARD_NO_PAD.decode_vec(incoming, &mut buffer)?;
            }
            Ok::<_, anyhow::Error>(buffer)
        })?);

        actions.push(Action {
            export: label.map(|s| Bytes::from(s.to_owned().into_bytes())),
            call,
            opcode,
            params,
            data
        });
    }

    // resolve all pending references in the Vec context
    for action in actions.iter_mut() {
        if action.call {
            let idx = usize::try_from(!action.opcode)?;
            action.opcode = pending_references.get_index(idx).context("wow this shouldn't happen1")?.1.context("never encountered this label1")?;
        }
        for param in action.params.iter_mut() {
            if let Parameter::GlobalPointer(ptr) = param {
                let idx = usize::try_from(!*ptr)?;
                println!("{:?}", pending_references.get_index(idx));
                *ptr = pending_references.get_index(idx).context("wow this shouldn't happen2")?.1.context("never encountered this label2")?;
            }
        }
    }

    // temporary table to handle renaming pointers
    let mut counter = 0;
    let renames = actions.iter().map(|act| {
        let pos = u32::try_from(counter)?;
        counter += 16 + 12*act.params.len() + act.data.len();
        Ok(pos)
    }).collect::<anyhow::Result<Vec<_>>>()?;

    // rename pointers relative to code_start
    let actions = actions.into_iter().enumerate().map(|(i, mut act)| {
        let renamed_i = renames[i];
        if act.call {
            act.opcode = renames[i];
        }
        for param in act.params.iter_mut() {
            if let Parameter::GlobalPointer(ptr) = param {
                *ptr = renames[usize::try_from(*ptr)?];
            }
        }

        Ok((renamed_i, act))
    }).collect::<anyhow::Result<BTreeMap<_, _>>>()?;

    // TODO
    let stcm2 = Stcm2 {
        tag,
        global_data,
        actions
    };

    println!("{:#?}", stcm2);

    Ok(())
}