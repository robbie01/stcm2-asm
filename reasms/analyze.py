import re
import sqlite3
from pathlib import Path

addr = re.compile(r"^([0-9A-F]{6}) ")
def get_address(line):
    m = addr.match(line)
    if m:
        return int(m.group(1), 16)
    else:
        return None

label_pat = re.compile(r"^(?:[0-9A-F]{6})? +([!-~]+): ")
def get_label(line):
    m = label_pat.match(line)
    if m is not None:
        return m.group(1)
    else:
        return None

vox = re.compile(r"=([1-9][0-9]*),")

dir = Path(__file__).parent

xadv = {}
with (dir / "advfont.txt").open() as f:
    pat = re.compile(r"id=([0-9]+|.).*xAdv=([0-9]+)")
    for line in f:
        if not line.startswith('char'):
            continue
        m = pat.search(line)
        if m is None:
            print(line)
        c = m.group(1)
        if len(c) > 1:
            c = chr(int(c))
        x = int(m.group(2))
        xadv[c] = x

def get_width(text: str):
    return sum(xadv[c] for c in text)

def breakup(line: str):
    MAX_WIDTH = 1500

    words = line.strip().split()

    cur = ''
    cur_width = 0
    chunks = []
    while words:
        if cur:
            s = ' '
        else:
            s = ''
        
        w = xadv.get(s, 0) + get_width(words[0])
        if cur_width + w > MAX_WIDTH:
            chunks.append(cur)
            cur = ''
            cur_width = 0
            w -= xadv.get(s, 0)
            s = ''
        
        cur += s + words[0]
        cur_width += w
        words = words[1:]
    
    if cur:
        chunks.append(cur)
    
    return chunks

db = sqlite3.connect(dir / "cpa.db", autocommit=False)

# pat = re.compile(r'^(?:[^\n]*call local_EB4C[^\n]*\n)?(?:[^\n]*call local_13F[^\n]*\n)?(?:[^\n]*call local_367D4[^\n]*\n)?(?:[^\n]*call local_E340, \[[^\n]*\n)+', re.M)

paths = (dir.parent / "asms").glob("*.asm")
for path in paths:
    scriptid = path.stem
    print(f"scriptid = {scriptid}")
    with path.open() as f:
        asm = f.readlines()

    cur = db.execute("""
        SELECT address, speaker, tl_body, tl_variant_body
        FROM dialogue NATURAL JOIN dialogueTl
        WHERE scriptid = ?
    """, (scriptid,))

    idx = 0
    found = False

    address: int
    speaker: str
    translation: str
    variant_tl: str
    for address, speaker, translation, variant_tl in cur:
        found = True
        while idx < len(asm) and get_address(asm[idx]) != address:
            idx += 1

        while idx < len(asm) and all(s not in asm[idx] for s in ['call fn_E340,', 'call fn_3B78C,', 'call fn_3BB24,', 'call fn_54B4C,']):
            idx += 1

        if idx >= len(asm):
            raise Exception(f"no match for ({scriptid}, {address})")
        
        # obvious hack
        # (ー is the katakana long vowel mark)
        translation = translation.replace('—', 'ー').replace('é', 'e').replace('è', 'e').replace('à', 'a')
        if variant_tl is not None:
            variant_tl = variant_tl.replace('—', 'ー').replace('é', 'e').replace('è', 'e').replace('à', 'a')

        translation = breakup(translation)

        if any(s in asm[idx] for s in ['call fn_3B78C,', 'call fn_3BB24,', 'call fn_54B4C,']):
            label = get_label(asm[idx])
            call = next(s for s in ['call fn_3B78C,', 'call fn_3BB24,', 'call fn_54B4C,'] if s in asm[idx])[5:-1]

            variant_tl = breakup(variant_tl) if variant_tl is not None else translation

            # todo: warn if overlong

            if len(translation) < 4:
                translation += [''] * (4 - len(translation))
            if len(variant_tl) < 4:
                variant_tl += [''] * (4 - len(variant_tl))

            if call == 'fn_54B4C':
                translation[3:] = [''.join(translation[3:])]
                variant_tl[3:] = [''.join(variant_tl[3:])]
            else:
                translation[2:] = [''.join(translation[2:])]
                variant_tl[2:] = [''.join(variant_tl[2:])]
            
            translation = ['"' + tl.replace('\\', '\\\\').replace(',', '\\x2c').replace('"', '\\"').replace('\n', '\\x0a').replace('\r', '\\x0d') + '"' for tl in translation]
            variant_tl = ['"' + tl.replace('\\', '\\\\').replace(',', '\\x2c').replace('"', '\\"').replace('\n', '\\x0a').replace('\r', '\\x0d') + '"' for tl in variant_tl]

            voxA, voxB = vox.findall(asm[idx])

            line = f"call {call}, ={voxA}, {", ".join(translation)}, ={voxB}, {", ".join(variant_tl)}\n"
            if label is not None:
                line = f"{label}: {line}"
            
            asm[idx] = line
            
            continue

        assert variant_tl is None
        
        label = None
        while idx < len(asm) and 'call fn_E340,' in asm[idx]:
            l = get_label(asm[idx])
            if l is not None:
                if label is not None:
                    raise Exception(f"double label at ({scriptid}, {address})")
                label = l
            del asm[idx]
        
        if len(translation) > 3:
            print("overlong warning")
        for tl in translation:
            tl = tl.replace('\\', '\\\\').replace(',', '\\x2c').replace('"', '\\"').replace('\n', '\\x0a').replace('\r', '\\x0d')
            line = f"call fn_E340, \"{tl}\"\n"
            if label is not None:
                line = f"{label}: {line}"
                label = None
            asm.insert(idx, line)
            idx += 1
        
    
    db.commit()

    if found:
        outpath = dir / path.name
        with outpath.open("w") as f:
            f.writelines(asm)

