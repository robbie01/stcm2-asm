use std::{borrow::Cow, cmp::Ordering, collections::{btree_map, BTreeMap}, fmt::Write as _, fs::File, io::{self, Write as _}, path::PathBuf, str, sync::LazyLock};
use anyhow::{bail, ensure, Context as _};
use bytes::{Buf as _, BufMut as _, Bytes, BytesMut};
use clap::{Parser, ValueEnum};
use base64::{display::Base64Display, prelude::*};
use encoding_rs::DecoderResult;
use regex::bytes::{Captures, Regex};

use crate::stcm2::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Encoding {
    #[value(name = "utf-8")]
    Utf8,
    #[value(name = "sjis")]
    ShiftJis
}

impl Encoding {
    fn get(self) -> &'static encoding_rs::Encoding {
        match self {
            Encoding::Utf8 => encoding_rs::UTF_8,
            Encoding::ShiftJis => encoding_rs::SHIFT_JIS
        }
    }
}

#[derive(Parser)]
pub struct Args {
    #[arg(short = 'a', help = "print addresses in disassembly")]
    address: bool,
    #[arg(short = 'e', help = "text encoding", value_enum, default_value_t = Encoding::Utf8)]
    encoding: Encoding,
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

    // clip zeros off end
    let nzero = str.iter().rev().take_while(|&&n| n == 0).count();
    let canonical = matches!(nzero, 1..=4);
    if canonical {
        str.truncate(str.len() - nzero);
    }

    Ok((str, tail, canonical))
}

fn autolabel(addr: u32) -> anyhow::Result<Bytes> {
    let label = format!("local_{addr:X}");
    Ok(Bytes::from(label.into_bytes()))
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
        let mut buf = [0; 4];
        write!(&mut buf[..], r"\x{:02x}", substr[0]).unwrap();
        buf
    })).unwrap()
}

pub fn main(args: Args) -> anyhow::Result<()> {
    let file = {
        let mut b = BytesMut::new().writer();
        io::copy(&mut File::open(args.file)?, &mut b)?;
        b.into_inner().freeze()
    };

    let mut stcm2 = from_bytes(file)?;

    // build symbol table and autolabels
    let mut labels = BTreeMap::new();
    for act in stcm2.actions.values() {
        if let Action { call: true, opcode, .. } = *act
            && stcm2.actions.get(&opcode).context("bruh0")?.export.is_none()
            && let btree_map::Entry::Vacant(entry) = labels.entry(opcode)
        {
            entry.insert(autolabel(opcode)?);
        }
        for &param in act.params.iter() {
            if let Parameter::GlobalPointer(addr) = param
                && stcm2.actions.get(&addr).context("bruh9")?.export.is_none()
                && let btree_map::Entry::Vacant(entry) = labels.entry(addr)
            {
                entry.insert(autolabel(addr)?);
            }
        }
    }
    if let Some(((&begin, _), (&end, _))) = labels.first_key_value().zip(labels.last_key_value()) {
        let mut acts = stcm2.actions.range_mut(begin..=end);
        for (addr, label) in labels {
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
    println!(".tag \"{}\"", tag);
    println!(".global_data {}", Base64Display::new(&stcm2.global_data, &BASE64_STANDARD_NO_PAD));
    println!(".code_start");
    for (&addr, act) in stcm2.actions.iter() {
        if args.address {
            print!("{addr:06X} ");
        }

        if let Some(label) = act.label() {
            let label = label_to_string(label);
            print!("{label}: ");
        }

        let Action { call, opcode, ref params, ref data, .. } = *act;
        
        if call {
            print!("call {}", label_to_string(stcm2.actions.get(&opcode).context("bruh")?.label().context("bruh2")?));
        } else if opcode == 0 && params.is_empty() && data.is_empty() {
            print!("return")
        } else {
            print!("raw {opcode:X}");
        }

        for &param in params.iter() {
            match param {
                Parameter::Value(v) => print!(", {v:X}"),
                Parameter::GlobalPointer(addr) => print!(", [{}]", label_to_string(stcm2.actions.get(&addr).context("bruh5")?.label().context("bruh6")?)),
                Parameter::LocalPointer(addr) => print!(", [data+{addr}]")
            }
        }

        let mut data = data.clone();
        let mut pos = 0;

        let mut sep = " !";

        while pos < data.len() {
            if let Ok((s, tail, canonical)) = decode_string(pos as u32, data.clone()) {
                let s = decode_with_hex_replacement(args.encoding.get(), &s);
                if pos != 0 {
                    print!("{sep} {}", Base64Display::new(&data[..pos], &BASE64_STANDARD_NO_PAD));
                    sep = ",";
                }
                if canonical {
                    print!("{sep} \"");
                } else {
                    print!("{sep} @\"");
                }
                sep = ",";
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

    Ok(())
}
