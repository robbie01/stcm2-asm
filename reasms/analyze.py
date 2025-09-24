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

def breakup(line: str, scale: float = 1.0):
    if not line:
        return ['']

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
        if scale * (cur_width + w) > MAX_WIDTH:
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

    if scale != 1.0:
        chunks[0] = f'#Scale[{scale}]{chunks[0]}'
    
    return chunks

speakers = {
    "#Name[1][#Name[2]]＝ラリック": "Hairi Lalique",
    "おばあさん": "Grandmother",
    "おばあちゃん": "Granny",
    "アロマ店店主": "Aroma Shop Owner",
    "カンパネラ": "Campanella",
    "ハルモニア": "Harmonia",
    "三人": "Three People",
    "二人": "Two People",
    "住民Ａ": "Resident A",
    "住民Ｂ": "Resident B",
    "刈鐘[カリガネ]": "Karigane",
    "初代Ｍ": "First M",
    "助手": "Assistant",
    "司書": "Librarian",
    "女性記者Ａ": "Female Reporter A",
    "女性１": "Woman 1",
    "女性２": "Woman 2",
    "女性Ａ": "Woman A",
    "子供": "Child",
    "子供Ａ": "Child A",
    "少女": "Girl",
    "少女Ａ": "Girl A",
    "少年": "Boy",
    "店員": "Shop Clerk",
    "廻螺[エラ]＝アマルリック": "Ela Amalric",
    "憂漣[ユーレン]=ミュラー": "Ulen Muller",
    "憂漣[ユーレン]ミュラー": "Ulen Muller",
    "憂漣[ユーレン]＝ミュラー": "Ulen Muller",
    "晩歌[バンカ]": "Banka",
    "歌紫歌": "Kashika Galle",
    "歌紫歌[カシカ]＝ガレ": "Kashika Galle",
    "歌紫歌＆糸遠": "Kashika & Shion",
    "泣虎[ナトラ]＝ピオニー": "Natra Peony",
    "泣虎[ナトラ]＝ピオニー　": "Natra Peony",
    "猿": "Monkey",
    "王": "King",
    "瑠璃[ルリ]": "Ruri",
    "瑪衣[メイ]": "Mei",
    "瑪衣[メイ] ": "Mei",
    "男性": "Man",
    "男性１": "Man 1",
    "男性Ａ": "Man A",
    "男１": "Man 1",
    "番人１": "Guard 1",
    "番人２": "Guard 2",
    "番人Ａ": "Guard A",
    "番人Ｂ": "Guard B",
    "研究者Ａ": "Researcher A",
    "研究者Ｂ": "Researcher B",
    "糸遠[シオン]＝ラリック": "Shion Lalique",
    "紫鳶[シエン]＝クリノクロア": "Shien Clinochlore",
    "紫鳶＆黒禰": "Shien & Klone",
    "綸燈[リンドウ]＝ウェステリア": "Rindo Westeria",
    "衿栖[エリス]＝シュナイダー": "Eris Schneider",
    "門番": "Gatekeeper",
    "霞[カスミ]": "Kasumi",
    "霞[カスミ]　　": "Kasumi",
    "魔法使い": "Wizard",
    "黒禰[クロネ]＝スピネル": "Klone Spinel",
    "？？？": "???",
    "Ｍ": "M"
}

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
    for address, speaker, tl_body, tl_variant_body in cur:
        found = True
        while idx < len(asm) and get_address(asm[idx]) != address:
            idx += 1
        
        assert (speaker is not None) == (f'call fn_EB4C, "{speaker}"' in asm[idx])
        if speaker is not None:
            label = get_label(asm[idx])
            line = f'call fn_EB4C, "{speakers[speaker]}"\n'
            if label is not None:
                line = f'{label}: {line}'
            asm[idx] = line

        while idx < len(asm) and all(s not in asm[idx] for s in ['call fn_E340,', 'call fn_3B78C,', 'call fn_3BB24,', 'call fn_54B4C,']):
            idx += 1

        if idx >= len(asm):
            raise Exception(f"no match for ({scriptid}, {address})")
        
        # obvious hack
        # (ー is the katakana long vowel mark)
        tl_body = tl_body.replace('—', 'ー').replace('é', 'e').replace('è', 'e').replace('à', 'a').replace('…', '...')
        if tl_variant_body is not None:
            tl_variant_body = tl_variant_body.replace('—', 'ー').replace('é', 'e').replace('è', 'e').replace('à', 'a').replace('…', '...')

        scale = 1.0
        while True:
            translation = breakup(tl_body, scale)
            if len(translation) <= 3:
                break
            scale -= 0.1

        if (call := next((s[5:-1] for s in ['call fn_3B78C,', 'call fn_3BB24,', 'call fn_54B4C,'] if s in asm[idx]), None)) is not None:
            label = get_label(asm[idx])

            variant_tl = breakup(tl_variant_body, scale) if tl_variant_body is not None else translation

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

        assert tl_variant_body is None
        
        label = None
        while idx < len(asm) and 'call fn_E340,' in asm[idx]:
            l = get_label(asm[idx])
            if l is not None:
                if label is not None:
                    raise Exception(f"double label at ({scriptid}, {address})")
                label = l
            del asm[idx]
        
        if len(translation) > 3:
            scale = 3 / len(translation)
            translation[0] = f"#Scale[{scale}]{translation[0]}"
        
        for i, tl in enumerate(translation):
            # hack that doesn't take into account some scenes (i.e. letter_male)
            # todo: improve typesetting
            # (note: investigate letter_male scenes)
            # (note note: is letter_male supposed to be letter_mail? lol)

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

