use std::collections::BTreeMap;

use anyhow::{anyhow, bail, ensure, Context as _};
use bytes::{Buf as _, Bytes};

pub const STCM2_MAGIC: &[u8] = b"STCM2";
pub const STCM2_TAG_LENGTH: usize = 32 - STCM2_MAGIC.len();
pub const GLOBAL_DATA_MAGIC: &[u8] = b"GLOBAL_DATA\0";
pub const GLOBAL_DATA_OFFSET: usize = STCM2_MAGIC.len() + STCM2_TAG_LENGTH + 12*4 + GLOBAL_DATA_MAGIC.len();
pub const CODE_START_MAGIC: &[u8] = b"CODE_START_\0";
pub const EXPORT_DATA_MAGIC: &[u8] = b"EXPORT_DATA\0";
pub const COLLECTION_LINK_MAGIC: &[u8] = b"COLLECTION_LINK\0";

#[derive(Clone, Copy, Debug)]
pub enum Parameter {
    ActionRef(u32),
    DataPointer(u32),
    Value(u32),
    GlobalDataPointer(u32)
}

impl Parameter {
    pub fn parse(value: [u32; 3], data_addr: u32, data_len: u32, global_data_len: u32) -> anyhow::Result<Self> {
        const GDO: u32 = GLOBAL_DATA_OFFSET as u32;
        match value {
            [0xffffff41, addr, 0x40000000 | 0xff000000] => Ok(Self::ActionRef(addr)),
            [addr, 0x40000000 | 0xff000000, 0x40000000 | 0xff000000]
                if addr >= data_addr && addr < data_addr+data_len => Ok(Self::DataPointer(addr-data_addr)),
            [addr, 0x40000000 | 0xff000000, 0x40000000 | 0xff000000]
                if addr >= GDO && addr < GDO+global_data_len => Ok(Self::GlobalDataPointer(addr-GDO)),
            [value, 0x40000000 | 0xff000000, 0x40000000 | 0xff000000] => Ok(Self::Value(value)),
            _ => Err(anyhow!("bad parameter: {value:08X?}"))
        }
    }
}

#[derive(Clone, Debug)]
pub struct Action {
    pub export: Option<Bytes>,
    pub call: bool,
    pub opcode: u32,
    pub params: Vec<Parameter>,
    pub data: Bytes
}

impl Action {
    //const OP_ADD: u32 = 0xffffff00;
    //const OP_SUB: u32 = 0xffffff01;
    //const OP_MUL: u32 = 0xffffff02;
    //const OP_DIV: u32 = 0xffffff03;
    //const OP_MOD: u32 = 0xffffff04;
    //const OP_SHL: u32 = 0xffffff05;
    //const OP_SHR: u32 = 0xffffff06;
    //const OP_AND: u32 = 0xffffff07;
    //const OP_XOR: u32 = 0xffffff08;
    //const OP_OR: u32 = 0xffffff09;

    pub fn label(&self, junk: bool) -> Option<&[u8]> {
        let mut b = &self.export.as_ref()?[..];
        if junk {
            while let [rst @ .., 0] = b {
                b = rst;
            }
            Some(b)
        } else {
            let pos = b.iter().position(|&z| z == 0).unwrap_or(b.len());
            Some(&b[..pos])
        }
    }

    pub fn len(&self) -> usize {
        16 + 12*self.params.len() + self.data.len()
    }
}

#[derive(Clone, Debug)]
pub struct Stcm2 {
    pub tag: Bytes,
    pub global_data: Bytes,
    pub actions: BTreeMap<u32, Action>
}

pub fn from_bytes(mut file: Bytes) -> anyhow::Result<Stcm2> {
    let start_addr = file.as_ptr();
    let get_pos = |file: &Bytes| file.as_ptr() as usize - start_addr as usize;

    ensure!(file.starts_with(STCM2_MAGIC));
    file.advance(STCM2_MAGIC.len());
    let tag = file.split_to(STCM2_TAG_LENGTH);
    let export_addr = file.get_u32_le();
    let export_len = file.get_u32_le();
    let _unk1 = file.get_u32_le();
    let _collection_addr = file.get_u32_le();
    let _unk = file.split_to(32);
    ensure!(file.starts_with(GLOBAL_DATA_MAGIC));
    file.advance(GLOBAL_DATA_MAGIC.len());
    ensure!(get_pos(&file) == GLOBAL_DATA_OFFSET);
    let mut global_len = 0;
    while !file[global_len..].starts_with(CODE_START_MAGIC) {
        global_len += 4;
    }
    let global_data = file.split_to(global_len);
    ensure!(file.starts_with(CODE_START_MAGIC));
    file.advance(CODE_START_MAGIC.len());

    let mut actions = BTreeMap::new();

    while get_pos(&file) < usize::try_from(export_addr)? - EXPORT_DATA_MAGIC.len() {
	    let addr = get_pos(&file).try_into()?;
		
        let global_call = file.get_u32_le();
        let opcode = file.get_u32_le();
        let nparams = file.get_u32_le();
        let length = file.get_u32_le();

        let call = match global_call {
            0 => false,
            1 => true,
            v => bail!("global_call = {v:08X}")
        };
        let mut params = Vec::with_capacity(nparams.try_into()?);
        for _ in 0..nparams {
            let buffer = [file.get_u32_le(), file.get_u32_le(), file.get_u32_le()];
            params.push(Parameter::parse(buffer, addr + 16 + 12*nparams, length - 16 - 12*nparams, global_len.try_into()?)?);
        }

        let ndata = length - 16 - 12*nparams;
        let data = file.split_to(ndata.try_into()?);

        let res = actions.insert(addr, Action { export: None, call, opcode, params, data });
        ensure!(res.is_none());
    }

    ensure!(file.starts_with(EXPORT_DATA_MAGIC));
    file.advance(EXPORT_DATA_MAGIC.len());

    for _ in 0..export_len {
        ensure!(file.get_u32_le() == 0);
        let export = file.split_to(32);
        let addr = file.get_u32_le();
        let act = actions.get_mut(&addr).context("export does not match known action")?;
        ensure!(act.export.is_none());
        act.export = Some(export);
    }

    Ok(Stcm2 {
        tag,
        global_data,
        actions
    })
}