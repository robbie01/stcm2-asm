use clap::{Parser, Subcommand, ValueEnum};

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
    #[arg(global = true, short = 'e', help = "text encoding", value_enum, default_value_t = Encoding::Utf8)]
    encoding: Encoding,
    #[command(subcommand)]
    cmd: Command
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    match args.cmd {
        Command::Disasm(args) => disasm::main(args),
        Command::Asm(args) => asm::main(args)
    }
}
