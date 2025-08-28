use std::{borrow::Cow, fs::{self, File}, io::{self, BufRead, BufReader}, mem, path::PathBuf, sync::LazyLock};

use anyhow::{bail, ensure, Context};
use bytes::{BufMut, Bytes};
use clap::Parser;
use indexmap::IndexMap;
use regex::{Captures, Regex};
use base64::prelude::*;

use crate::stcm2::{Action, Parameter, CODE_START_MAGIC, EXPORT_DATA_MAGIC, GLOBAL_DATA_MAGIC, GLOBAL_DATA_OFFSET, STCM2_MAGIC, STCM2_TAG_LENGTH, COLLECTION_LINK_MAGIC};

#[derive(Parser)]
pub struct Args {
    input: PathBuf,
    output: PathBuf
}

static INITIAL_ADDRESS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[0-9A-F]{6} ").unwrap());
static LABEL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^((?:[!-\[\]-~]|\\x[0-9a-f]{2})+): ").unwrap());

fn decode_label(label: &str) -> Cow<'_, [u8]> {
    use regex::bytes::*;

    // note: this is a bytes regex
    static PLACEHOLDER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\\x([0-9a-f]{2})").unwrap());
    PLACEHOLDER.replace_all(label.as_bytes(), |capt: &Captures<'_>| {
        [u8::from_str_radix(
            unsafe { str::from_utf8_unchecked(capt.get(1).unwrap().as_bytes()) },
            16
        ).unwrap()]
    })
}

fn cow_str_to_bytes(s: Cow<'_, str>) -> Cow<'_, [u8]> {
    match s {
        Cow::Borrowed(s) => Cow::Borrowed(s.as_bytes()),
        Cow::Owned(s) => Cow::Owned(s.into_bytes())
    }
}

fn encode_string(inner: &str, canonical: bool, buffer: &mut Vec<u8>) -> anyhow::Result<()> {
    fn encode_wellformed(wf: &str) -> Cow<'_, str> {
        // note: this is a str regex
        static PLACEHOLDER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"\\(?:x([0-9a-f]{2})|(["\\]))"#).unwrap());
        PLACEHOLDER.replace_all(wf, |capt: &Captures<'_>| {
            if let Some(g) = capt.get(1) {
                // evil miniscule heap allocation LOL
                Cow::Owned(char::from(u8::from_str_radix(
                    g.as_str(),
                    16
                ).unwrap()).to_string())
            } else if let Some(g) = capt.get(2) {
                Cow::Borrowed(&wf[g.range()])
            } else {
                unreachable!()
            }
        })
    }

    static MALFORMED: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\\X([0-9a-f]{2})").unwrap());

    let mut pieces = Vec::new();
    let mut idx = 0;
    while idx < inner.len() {
        match MALFORMED.captures_at(inner, idx) {
            None => {
                pieces.push(cow_str_to_bytes(encode_wellformed(&inner[idx..])));
                break;
            },
            Some(malformed) => {
                let whole = malformed.get(0).unwrap();
                if idx != whole.start() {
                    pieces.push(cow_str_to_bytes(encode_wellformed(&inner[idx..whole.start()])));
                }
                pieces.push(Cow::Owned(vec![u8::from_str_radix(malformed.get(1).unwrap().as_str(), 16).unwrap()]));
                idx = whole.end();
            }
        }
    }
    
    let len = pieces.iter().map(|b| b.len()).sum::<usize>();

    let nzero = if canonical {
        4 - len % 4
    } else {
        ensure!(len % 4 == 0);
        0
    };
    let len = u32::try_from(len + nzero)?;
    let qlen = len / 4;
    
    buffer.put_u32_le(0);
    buffer.put_u32_le(qlen);
    buffer.put_u32_le(1);
    buffer.put_u32_le(len);
    for piece in pieces {
        buffer.put_slice(&piece);
    }
    buffer.put_bytes(0, nzero);
    Ok(())
}

pub fn main(args: Args) -> anyhow::Result<()> {
    let mut lines = BufReader::new(File::open(args.input)?).lines().collect::<io::Result<Vec<_>>>()?;

    for line in &mut lines {
        if let Cow::Owned(l) = INITIAL_ADDRESS.replace(line, "") {
            *line = l;
        }
    }

    ensure!(lines.first().is_some_and(|tag| tag.is_ascii() && tag.len() >= 7 && tag.starts_with(".tag \"") && tag.ends_with('"')),
        "improper tag");
    
    let tag = Bytes::from(mem::take(&mut lines[0]).into_bytes());
    let tag = tag.slice(6..tag.len()-1);

    let filler = if tag.starts_with(b"L") { 0x40000000 } else { 0xff000000 };
    println!("using filler 0x{filler:08x}");

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
        }).map(decode_label);

        if let Some(lbl) = label.clone() {
            if lbl.starts_with(b"local_") {
                label = None;
            }
            pending_references.insert(lbl, Some(count));
        }

        if instr == "return" {
            actions.push(Action {
                export: label.map(|s| Bytes::from(s.into_owned())),
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
            let op = decode_label(op);
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
                let ent = pending_references.entry(decode_label(param));
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
                encode_string(incoming, canonical, &mut buffer)?;
            } else {
                BASE64_STANDARD_NO_PAD.decode_vec(incoming, &mut buffer)?;
            }
            Ok::<_, anyhow::Error>(buffer)
        })?);

        actions.push(Action {
            export: label.map(|s| Bytes::from(s.into_owned())),
            call,
            opcode,
            params,
            data
        });
    }

    // resolve all pending references in the Vec context
    for action in &mut actions {
        if action.call {
            let idx = usize::try_from(!action.opcode)?;
            action.opcode = pending_references.get_index(idx).context("wow this shouldn't happen1")?.1.context("never encountered this label1")?;
        }
        for param in &mut action.params {
            if let Parameter::GlobalPointer(ptr) = param {
                let idx = usize::try_from(!*ptr)?;
                *ptr = pending_references.get_index(idx).context("wow this shouldn't happen2")?.1.context("never encountered this label2")?;
            }
        }
    }

    // temporary table to handle renaming pointers
    let mut counter = 0;
    let renames = actions.iter().map(|act| {
        let pos = u32::try_from(counter)?;
        counter += act.len();
        Ok(pos)
    }).collect::<anyhow::Result<Vec<_>>>()?;

    // rename pointers relative to code_start
    let actions = actions.into_iter().enumerate().map(|(i, mut act)| {
        let renamed_i = renames[i];
        if act.call {
            act.opcode = renames[usize::try_from(act.opcode)?];
        }
        for param in &mut act.params {
            if let Parameter::GlobalPointer(ptr) = param {
                *ptr = renames[usize::try_from(*ptr)?];
            }
        }

        Ok((renamed_i, act))
    }).collect::<anyhow::Result<Vec<_>>>()?;

    let mut out = Vec::new();

    out.put_slice(STCM2_MAGIC);
    out.put_slice(&tag);
    out.put_bytes(0, STCM2_TAG_LENGTH - tag.len());
    let meta_idx = out.len();
    out.put_bytes(0, 4*12); // todo: this is incorrect (figure out unk values)
    out.put_slice(GLOBAL_DATA_MAGIC);
    ensure!(out.len() == GLOBAL_DATA_OFFSET);
    out.put_slice(&global_data);
    out.put_slice(CODE_START_MAGIC);

    let mut exports = Vec::new();

    let code_base = out.len();
    for (pos, mut act) in actions {
        ensure!(out.len() == code_base + usize::try_from(pos)?);

        if let Some(export) = act.export.take() {
            exports.push((export, out.len()));
        }

        out.put_u32_le(act.call.into());
        out.put_u32_le(if act.call {
            u32::try_from(code_base + usize::try_from(act.opcode)?)?
        } else {
            act.opcode
        });
        out.put_u32_le(u32::try_from(act.params.len())?);
        out.put_u32_le(u32::try_from(act.len())?);

        let data_base = out.len() + 12 * act.params.len();
        for param in act.params {
            match param {
                Parameter::Value(val) => {
                    out.put_u32_le(val);
                    out.put_u32_le(filler);
                    out.put_u32_le(filler);
                },
                Parameter::LocalPointer(ptr) => {
                    out.put_u32_le(u32::try_from(data_base + usize::try_from(ptr)?)?);
                    out.put_u32_le(filler);
                    out.put_u32_le(filler);
                },
                Parameter::GlobalPointer(ptr) => {
                    out.put_u32_le(0xffffff41);
                    out.put_u32_le(u32::try_from(code_base + usize::try_from(ptr)?)?);
                    out.put_u32_le(filler);
                }
            }
        }

        out.put_slice(&act.data);
    }

    out.put_slice(EXPORT_DATA_MAGIC);
    let export_addr = out.len();
    {
        let mut export_meta = &mut out[meta_idx..];
        export_meta.put_u32_le(u32::try_from(export_addr)?);
        export_meta.put_u32_le(u32::try_from(exports.len())?);
    }
    for (name, addr) in exports {
        out.put_u32_le(0);
        out.put_slice(&name);
        out.put_bytes(0, 32 - name.len());
        out.put_u32_le(u32::try_from(addr)?);
    }
    
    out.put_slice(COLLECTION_LINK_MAGIC);
    let collection_link_len = 2;
    let collection_link_addr = out.len();
    {
        let mut collection_meta = &mut out[meta_idx+8..];
        collection_meta.put_u32_le(collection_link_len);
        collection_meta.put_u32_le(collection_link_addr.try_into()?);
    }
    out.put_u32_le(0);
    let write_file_len_here = out.len();
    out.put_bytes(0, 60);
    {
        let len = out.len();
        let mut write_file_len = &mut out[write_file_len_here..];
        write_file_len.put_u32_le(len.try_into()?);
    }

    fs::write(args.output, out)?;

    Ok(())
}