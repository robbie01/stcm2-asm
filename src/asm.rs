use std::{borrow::Cow, fs::{self, File}, io::{self, BufRead, BufReader}, mem, path::PathBuf, ptr, sync::LazyLock};

use anyhow::{bail, ensure, Context as _};
use bimap::BiMap;
use bstr::BStr;
use bytes::{BufMut, Bytes};
use clap::Parser;
use indexmap::IndexMap;
use regex::{Captures, Regex};
use base64::prelude::*;

use crate::stcm2::{Action, Parameter, CODE_START_MAGIC, EXPORT_DATA_MAGIC, GLOBAL_DATA_MAGIC, GLOBAL_DATA_OFFSET, STCM2_MAGIC, STCM2_TAG_LENGTH, COLLECTION_LINK_MAGIC};

#[derive(Parser)]
pub struct Args {
    #[arg(from_global)]
    encoding: super::Encoding,
    input: PathBuf,
    output: PathBuf
}

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

fn cow_str_to_bytes<'a>(encoding: &'static encoding_rs::Encoding, s: Cow<'a, str>) -> Cow<'a, [u8]> {
    match s {
        Cow::Borrowed(s) => {
            let (s, _, replaced) = encoding.encode(s);
            if replaced { println!("warning: encountered unmappable character"); }
            s
        },
        Cow::Owned(s) => {
            let (enc, _, replaced) = encoding.encode(&s);
            if replaced { println!("warning: encountered unmappable character"); }
            match enc {
                Cow::Borrowed(enc) if ptr::eq(enc, s.as_bytes()) => Cow::Owned(s.into_bytes()),
                _ => Cow::Owned(enc.into_owned())
            }
        }
    }
}

fn encode_bytestring(type_: u32, inner: &[u8], buffer: &mut Vec<u8>) -> anyhow::Result<()> {
    ensure!(inner.len() % 4 == 0, "must be divisible by 4");
    buffer.put_u32_le(type_);
    buffer.put_u32_le((inner.len() / 4).try_into()?);
    buffer.put_u32_le(1);
    buffer.put_u32_le(inner.len().try_into()?);
    buffer.put_slice(inner);
    Ok(())
}

fn encode_string(encoding: &'static encoding_rs::Encoding, inner: &str, buffer: &mut Vec<u8>) -> anyhow::Result<()> {
    fn unsub_wellformed(wf: &str) -> Cow<'_, str> {
        // note: this is a str regex
        static PLACEHOLDER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"\\(?:x([0-9a-f]{2})|(["\\]))"#).unwrap());
        PLACEHOLDER.replace_all(wf, |capt: &Captures<'_>| {
            match (capt.get(1), capt.get(2)) {
                (Some(g), None) => {
                    // evil miniscule heap allocation LOL
                    Cow::Owned(char::from(u8::from_str_radix(
                        g.as_str(),
                        16
                    ).unwrap()).to_string())
                },
                (None, Some(g)) => {
                    Cow::Borrowed(&wf[g.range()])
                },
                _ => unreachable!()
            }
        })
    }

    static MALFORMED: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\\X([0-9a-f]{2})").unwrap());

    let mut pieces = Vec::new();
    let mut idx = 0;
    while idx < inner.len() {
        match MALFORMED.captures_at(inner, idx) {
            None => {
                pieces.push(cow_str_to_bytes(encoding, unsub_wellformed(&inner[idx..])));
                break;
            },
            Some(malformed) => {
                let whole = malformed.get(0).unwrap();
                if idx != whole.start() {
                    pieces.push(cow_str_to_bytes(encoding, unsub_wellformed(&inner[idx..whole.start()])));
                }
                pieces.push(Cow::Owned(vec![u8::from_str_radix(malformed.get(1).unwrap().as_str(), 16).unwrap()]));
                idx = whole.end();
            }
        }
    }
    
    let len = pieces.iter().map(|b| b.len()).sum::<usize>();

    let nzero = 4 - len % 4;
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

fn split(orig: &str) -> anyhow::Result<(Vec<&str>, Option<&str>)> {
    let mut instr = orig;
    let mut parts = Vec::new();
    loop {
        instr = instr.trim_ascii_start();

        if let Some(junk) = instr.strip_prefix("! ") {
            break Ok((parts, Some(junk)))
        } else if instr.is_empty() {
            break Ok((parts, None))
        }

        if instr.starts_with('"') {
            let mut skip = 0u32;
            let mut end = None;
            for (idx, ch) in instr.char_indices().skip(1) {
                if skip > 0 {
                    skip -= 1;
                    continue;
                }

                if ch == '"' {
                    end = Some(idx + ch.len_utf8());
                    break;
                }

                if ch == '\\' {
                    if let Some(peek) = instr[idx + ch.len_utf8()..].chars().next() {
                        if peek == '"' || peek == '\\' {
                            skip = 1;
                        } else if peek == 'x' {
                            skip = 3;
                        } else {
                            bail!("unsupported escape: original line {orig}");
                        }
                    }
                }
            }
            let end = end.with_context(|| format!("bad quotes: original line {orig}"))?;
            parts.push(&instr[..end]);
            let tail = &instr[end..];
            instr = tail.strip_prefix(", ").unwrap_or(tail);
        } else if let Some((head, tail)) = instr.split_once(',') {
            parts.push(head);
            instr = tail;
        } else if let Some(j) = instr.find(" ! ") {
            parts.push(&instr[..j]);
            instr = &instr[j..];
        } else {
            parts.push(instr);
            instr = "";
        }
    }
}

pub fn main(args: Args, mnemonics: BiMap<&str, u32>) -> anyhow::Result<()> {
    static INITIAL_ADDRESS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(?:[0-9A-F]{6})? +").unwrap());
    static LABEL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^((?:[!-\[\]-~]|\\x[0-9a-f]{2})+): ").unwrap());

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
        if instr.is_empty() { continue }

        let count = u32::try_from(actions.len())?;

        let mut instr = &instr[..];

        let mut label = LABEL.captures(instr).map(|label| {
            instr = instr.strip_prefix(label.get(0).unwrap().as_str()).unwrap();
            label.get(1).unwrap().as_str()
        }).map(decode_label);

        if let Some(lbl) = label.clone() {
            if lbl.starts_with(b"local_") || lbl.starts_with(b"fn_") {
                label = None;
            }
            pending_references.insert(lbl, Some(count));
        }

        let (split, junk) = split(instr)?;
        let op = split[0];
        let junk = junk.unwrap_or_default();

        let (call, opcode) = if let Some(op) = op.strip_prefix("raw ") {
            let opcode = u32::from_str_radix(op, 16)?;
            (false, opcode)
        } else if let Some(&opcode) = mnemonics.get_by_left(op) {
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

        let mut data = Vec::new();
        BASE64_STANDARD_NO_PAD.decode_vec(junk, &mut data)?;

        let params = split[1..].iter().map(|&param| Ok(
            if let Some(s) = param.strip_prefix('"') {
                let s = s.strip_suffix('"').with_context(|| format!("no ending quote for {instr}"))?;
                let ptr = u32::try_from(data.len())?;
                encode_string(args.encoding.get(), s, &mut data)?;
                Parameter::DataPointer(ptr)
            } else if let Some(lit) = param.strip_prefix(['=', '@']) {
                let (type_, lit) = if let Some(lit) = lit.strip_prefix('=') {
                    (1, lit)
                } else {
                    (0, lit)
                };
                let lit = if let Some(lit) = lit.strip_suffix('h') {
                    u32::from_str_radix(lit, 16)?
                } else {
                    lit.parse()?
                };
                let ptr = u32::try_from(data.len())?;
                encode_bytestring(type_, &lit.to_le_bytes(), &mut data)?;
                Parameter::DataPointer(ptr)
            } else if let Some(param) = param.strip_prefix('[') {
                let param = param.strip_suffix(']').context("no matching bracket??")?;
                if let Some(ptr) = param.strip_prefix("global_data+") {
                    Parameter::GlobalDataPointer(ptr.parse()?)
                } else {
                    let ent = pending_references.entry(decode_label(param));
                    let idx = ent.index();
                    ent.or_default();
                    let ptr = !u32::try_from(idx)?;
                    Parameter::ActionRef(ptr)
                }
            } else {
                Parameter::Value(u32::from_str_radix(param, 16)?)
            }
        )).collect::<anyhow::Result<Vec<Parameter>>>()?;

        actions.push(Action {
            export: label.map(|s| Bytes::from(s.into_owned())),
            call,
            opcode,
            params,
            data: data.into()
        });
    }

    // resolve all pending references in the Vec context
    for action in &mut actions {
        if action.call {
            let idx = usize::try_from(!action.opcode)?;
            action.opcode = pending_references.get_index(idx).context("wow this shouldn't happen1")?.1.context("never encountered this label1")?;
        }
        for param in &mut action.params {
            if let Parameter::ActionRef(ptr) = param {
                let idx = usize::try_from(!*ptr)?;
                let (name, addr) = pending_references.get_index(idx).context("wow this shouldn't happen2")?;
                *ptr = addr.with_context(|| format!("never encountered this label {}", BStr::new(name)))?;
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
            if let Parameter::ActionRef(ptr) = param {
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
                Parameter::GlobalDataPointer(ptr) => {
                    out.put_u32_le(u32::try_from(GLOBAL_DATA_OFFSET)? + ptr);
                    out.put_u32_le(filler);
                    out.put_u32_le(filler);
                },
                Parameter::DataPointer(ptr) => {
                    out.put_u32_le(u32::try_from(data_base + usize::try_from(ptr)?)?);
                    out.put_u32_le(filler);
                    out.put_u32_le(filler);
                },
                Parameter::ActionRef(ptr) => {
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