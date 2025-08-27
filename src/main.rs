use clap::{Parser, Subcommand};

mod disasm;
mod asm;
mod stcm2;

#[derive(Subcommand)]
enum Command {
    Disasm(disasm::Args),
    Asm(asm::Args)
}

#[derive(Parser)]
struct Args {
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
