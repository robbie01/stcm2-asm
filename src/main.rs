#![forbid(unsafe_code)]

use std::{fs, iter, path::PathBuf};

use anyhow::{ensure, Context};
use clap::{Parser, Subcommand, ValueEnum};
use saphyr::{LoadableYamlNode, Yaml};

mod disasm;
mod asm;
mod stcm2;

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

#[derive(Subcommand)]
enum Command {
    Disasm(disasm::Args),
    Asm(asm::Args)
}

#[derive(Parser)]
struct Args {
    #[arg(global = true, short = 'c', help = "config.yaml file")]
    config: Option<PathBuf>,
    #[arg(global = true, short = 'e', help = "text encoding", value_enum, default_value_t = Encoding::Utf8)]
    encoding: Encoding,
    #[command(subcommand)]
    cmd: Command
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let conf = if let Some(conf) = args.config {
        let conf = fs::read_to_string(conf)?;
        let mut docs = Yaml::load_from_str(&conf)?;
        ensure!(docs.len() == 1);
        docs.pop()
    } else {
        None
    };

    let mnemonics = if let Some(ref conf) = conf && let Some(mnemonics) = conf.as_mapping_get("mnemonics") {
        mnemonics
            .as_mapping().context("mnemonics is not a mapping")?.iter()
            .map(|(k, v)| {
                let name = k.as_str().with_context(|| format!("mnemonic {k:?} is not a str"))?;
                let opcode = v.as_integer().with_context(|| format!("opcode {v:?} is not an int"))?;
                let opcode = opcode.try_into().with_context(|| format!("opcode {opcode:X} out of range"))?;
                Ok((name, opcode))
            })
            .collect::<anyhow::Result<_>>()?
    } else {
        iter::once(("return", 0u32)).collect()
    };

    match args.cmd {
        Command::Disasm(args) => disasm::main(args, mnemonics),
        Command::Asm(args) => asm::main(args, mnemonics)
    }
}
