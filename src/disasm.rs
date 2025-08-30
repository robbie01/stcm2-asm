use std::{borrow::Cow, cmp::Ordering, collections::{BTreeMap, HashSet}, fmt::Write as _, fs, mem, path::PathBuf, str, sync::LazyLock};
use anyhow::{bail, ensure, Context as _};
use bytes::{Buf as _, Bytes};
use clap::Parser;
use base64::{display::Base64Display, prelude::*};
use encoding_rs::DecoderResult;
use regex::bytes::{Captures, Regex};

use crate::stcm2::*;

#[derive(Parser)]
pub struct Args {
    #[arg(short = 'a', help = "print addresses in disassembly")]
    address: bool,
    #[arg(from_global)]
    encoding: super::Encoding,
    file: PathBuf
}

fn decode_string(addr: u32, mut str: Bytes) -> anyhow::Result<(Bytes, Bytes, bool)> {
    str.advance(addr as usize);

    ensure!(str.len() > 16, "not enough room for magic");

    ensure!(str.get_u32_le() == 0, "string magic isn't 0");
    let qlen = str.get_u32_le();
    ensure!(str.get_u32_le() == 1, "string magic isn't 1");
    let len = str.get_u32_le();
    ensure!(len == qlen*4, "len and qlen are inconsistent: len = {len}, qlen = {qlen}");
    let len = len.try_into()?;

    ensure!(str.len() >= len, "not enough room for string data");

    let tail = str.split_off(len);

    // hack to output u32s (i should really change the API here)
    // do you like my heuristic? :) it seems like the game only uses ints that aren't 6-digit hex
    if str[..].try_into().is_ok_and(|u| !matches!(u32::from_le_bytes(u), 0x100000..0x1000000)) {
        return Ok((str, tail, false))
    }

    // clip zeros off end
    let nzero = str.iter().rev().take_while(|&&n| n == 0).count();
    let canonical = matches!(nzero, 1..=4);
    if canonical {
        str.truncate(str.len() - nzero);
    }

    Ok((str, tail, canonical))
}

fn autolabel(prefix: &str, addr: u32) -> Bytes {
    let label = format!("{prefix}_{addr:X}");
    label.into_bytes().into()
}

fn decode_with_hex_replacement<'a>(encoding: &'static encoding_rs::Encoding, mut buf: &'a [u8]) -> Cow<'a, str> {
    const RESERVE: usize = char::MAX.len_utf8();

    if let Some(buf) = encoding.decode_without_bom_handling_and_without_replacement(buf) {
        return buf;
    }

    let mut dec = encoding.new_decoder_without_bom_handling();
    let mut s = String::with_capacity(buf.len());

    loop {
        let (res, n) = dec.decode_to_string_without_replacement(buf, &mut s, true);
        match res {
            DecoderResult::InputEmpty => break,
            DecoderResult::OutputFull => s.reserve(RESERVE),
            DecoderResult::Malformed(nm, p) => {
                assert_eq!(p, 0);

                let malformed = &buf[n - usize::from(nm)..n];
                for b in malformed {
                    write!(s, "\u{1f5ff}X{b:02x}").unwrap();
                }
            }
        }
        buf = &buf[n..];
    }

    Cow::Owned(s)
}

fn cow_bytes_to_str(bytes: Cow<'_, [u8]>) -> Option<Cow<'_, str>> {
    match bytes {
        Cow::Borrowed(bytes) => str::from_utf8(bytes).map(Cow::Borrowed).ok(),
        Cow::Owned(bytes) => String::from_utf8(bytes).map(Cow::Owned).ok()
    }
}

static ILLEGAL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?-u:[^!-\[\]-~])").unwrap());

// Always interpret labels as ASCII
fn label_to_string(label: &[u8]) -> Cow<'_, str> {
    cow_bytes_to_str(ILLEGAL.replace_all(label, |c: &Captures<'_>| {
        let substr = c.get(0).unwrap().as_bytes();
        assert_eq!(substr.len(), 1);
        // evil miniscule heap allocation LOL
        format!("\\x{:02x}", substr[0])
    })).unwrap()
}

// Heuristically determine function boundaries by splitting on returns,
// and combining based on labels and local jumps.
// This could probably be more efficient using u32 ranges to represent chunks
fn chunk_actions(acts: &BTreeMap<u32, Action>) -> Vec<Vec<(u32, &Action)>> {
    let mut chunks = Vec::new();
    let mut current_labels = HashSet::new();
    let mut current_chunk = Vec::new();

    for (&addr, act) in acts {
        current_labels.insert(addr);
        for param in &act.params {
            if let Parameter::ActionRef(ptr) = *param {
                current_labels.insert(ptr);
            }
        }
        current_chunk.push((addr, act));
        if !act.call && act.opcode == 0 {
            chunks.push((
                mem::take(&mut current_labels),
                mem::take(&mut current_chunk)
            ));
        }
    }

    if !current_chunk.is_empty() {
        chunks.push((current_labels, current_chunk));
    }

    let mut cur = 0;
    while cur + 1 < chunks.len() {
        // find the last intersecting chunk, then take the union of that whole range
        // iterate until no more matches (handles an edge case)
        loop {
            let mut found = false;

            for (i, (h, _)) in chunks.iter().enumerate().skip(cur+1).rev() {
                if !chunks[cur].0.is_disjoint(h) {
                    for _ in cur+1..=i {
                        let (h, v) = chunks.remove(cur+1);
                        chunks[cur].0.extend(h);
                        chunks[cur].1.extend(v);
                    }
                    found = true;
                    break;
                }
            }

            if !found { break }
        }

        cur += 1;
    }

    chunks.into_iter().map(|z| z.1).collect()
}

pub fn main(args: Args) -> anyhow::Result<()> {
    let file = fs::read(args.file)?.into();

    let mut stcm2 = from_bytes(file)?;

    // build symbol table and autolabels
    let mut autolabels = BTreeMap::new();
    for act in stcm2.actions.values() {
        if let Action { call: true, opcode, .. } = *act
            && stcm2.actions.get(&opcode).context("bruh0")?.export.is_none()
        {
            let ent: &mut Bytes = autolabels.entry(opcode).or_default();
            if !ent.starts_with(b"fn") {
                *ent = autolabel("fn", opcode);
            }
        }
        for &param in &act.params {
            if let Parameter::ActionRef(addr) = param
                && stcm2.actions.get(&addr).context("bruh9")?.export.is_none()
            {
                let ent = autolabels.entry(addr).or_default();
                if ent.is_empty() {
                    *ent = autolabel("local", addr);
                }
            }
        }
    }
    if let (Some((&begin, _)), Some((&end, _))) = (autolabels.first_key_value(), autolabels.last_key_value()) {
        let mut acts = stcm2.actions.range_mut(begin..=end);
        for (addr, label) in autolabels {
            let act = loop {
                let (&k, v) = acts.next().context("this should never happen 1")?;
                match k.cmp(&addr) {
                    Ordering::Less => (),
                    Ordering::Equal => break v,
                    Ordering::Greater => bail!("this should never happen 2")
                }
            };
            ensure!(act.export.is_none());
            act.export = Some(label);
        }
    }

    let tag = str::from_utf8(&stcm2.tag).context("nooooo")?.trim_end_matches('\0');
    println!(".tag \"{tag}\"");
    println!(".global_data {}", Base64Display::new(&stcm2.global_data, &BASE64_STANDARD_NO_PAD));
    println!(".code_start");

    for chunk in chunk_actions(&stcm2.actions) {
        println!();
        for (addr, act) in chunk {
            if args.address {
                print!("{addr:06X} ");
            }

            if let Some(label) = act.label() {
                let label = label_to_string(label);
                print!("{label:>14}: ");
            } else {
                print!("                ")
            }

            let Action { call, opcode, ref params, ref data, .. } = *act;
            
            if call {
                print!("call {}", label_to_string(stcm2.actions.get(&opcode).context("bruh")?.label().context("bruh2")?));
            } else if opcode == 0 && params.is_empty() {
                print!("return");
            } else {
                print!("raw {opcode:X}");
            }

            for &param in params {
                match param {
                    Parameter::Value(v) => print!(", {v:X}"),
                    Parameter::ActionRef(addr) => print!(", [{}]", label_to_string(stcm2.actions.get(&addr).context("bruh5")?.label().context("bruh6")?)),
                    Parameter::DataPointer(addr) => print!(", [data+{addr}]"),
                    Parameter::GlobalDataPointer(addr) => print!(", [global_data+{addr}]")
                }
            }

            let mut data = data.clone();
            let mut pos = 0;

            let mut sep = " !";

            while pos < data.len() {
                if let Ok((s, tail, canonical)) = decode_string(pos.try_into()?, data.clone()) {
                    if pos != 0 {
                        print!("{sep} {}", Base64Display::new(&data[..pos], &BASE64_STANDARD_NO_PAD));
                        sep = ",";
                    }

                    if !canonical && s.len() == 4 {
                        let n = u32::from_le_bytes(s[..].try_into().unwrap());
                        if n < 0xFF000000 {
                            print!("{sep} ={n}")
                        } else {
                            print!("{sep} ={n:X}h");
                        }
                    } else {
                        let s = decode_with_hex_replacement(args.encoding.get(), &s);
                        if canonical {
                            print!("{sep} \"");
                        } else {
                            print!("{sep} @\"");
                        }
                        for ch in s.chars() {
                            if ch.is_control() {
                                print!(r"\x{:02x}", u32::from(ch));
                            } else if ch == '\u{1f5ff}' {
                                print!(r"\");
                            } else if ch == '"' || ch == '\\' {
                                print!(r"\{ch}");
                            } else {
                                print!("{ch}");
                            }
                        }
                        print!("\"");
                    }
                    sep = ",";
                    data = tail;
                    pos = 0;
                    continue;
                }

                pos += 1;
            }

            if !data.is_empty() {
                print!("{sep} {}", Base64Display::new(&data, &BASE64_STANDARD_NO_PAD));
            }
            println!();
        }
    }

    Ok(())
}
