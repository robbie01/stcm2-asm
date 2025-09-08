from pathlib import Path
import sqlite3
import re

dir = Path(__file__).parent

db = sqlite3.connect(dir / "cpa.db", autocommit=False)

db.executescript("""
    CREATE TABLE IF NOT EXISTS dialogue(
        scriptid INTEGER,
        address INTEGER,
        thread TEXT NOT NULL,
        speaker TEXT,
        body TEXT NOT NULL,
        variant_body TEXT,
        PRIMARY KEY (scriptid, address)
    ) WITHOUT ROWID, STRICT;

    CREATE INDEX IF NOT EXISTS dialogueThread ON dialogue(scriptid, thread);

    CREATE TABLE IF NOT EXISTS graph(
        tScriptid INTEGER,
        tThread TEXT,
        hScriptid INTEGER,
        hThread TEXT,
        choice TEXT,
        PRIMARY KEY (tScriptid, tThread, hScriptid, hThread)
    ) WITHOUT ROWID, STRICT;

    CREATE INDEX IF NOT EXISTS graphHead ON graph(hScriptid, hThread);
""")

db.commit()

for script in dir.glob("*.asm"):
    try:
        scriptid = int(script.stem)
    except ValueError:
        continue
    if scriptid > 9099:
        continue

    with open(script) as f:
        s = f.readlines()

    chunks = []
    chunk = []
    for thread in s:
        thread = thread.strip()

        if thread.startswith('.'):
            continue
        
        if thread:
            chunk.append(thread)
        else:
            if chunk:
                chunks.append(chunk)
                chunk = []

    if chunk:
        chunks.append(chunk)
        chunk = []

    label = re.compile('^[0-9A-F]{6} +([!-~]+):')
    call = re.compile('^[0-9A-F]{6} +(?:[!-~]+: )?([^,]+)')
    st = re.compile('"([^"]*)"')
    sure = re.compile('(?:=([0-9]+), )?"(sure[0-9]+)"')
    for chunk in chunks:
        m = label.match(chunk[0])
        if not m:
            continue
        thread = m.group(1)
        if not thread.startswith('sure'):
            continue

        addr = None
        speaker = None
        dialogue = ("", None)
        jumps = []
        line: str
        for line in chunk:
            lineaddr = int(line[:6], 16)
            m = call.match(line)
            if m:
                match m.group(1):
                    case "call fn_EB4C":
                        addr = lineaddr
                        speaker = st.search(line).group(1)
                    case "call fn_E340":
                        if addr is None:
                            addr = lineaddr
                        dialogue = dialogue[0] + st.search(line).group(1).strip(), dialogue[1]
                    case "call fn_3B78C" | "call fn_3BB24":
                        if addr is None:
                            addr = lineaddr
                        line = line.replace(', =0', ', ""')
                        d = [s.strip() for s in st.findall(line)]
                        assert len(d) == 6
                        fst, snd = ''.join(d[:3]), ''.join(d[3:])
                        if fst == snd:
                            dialogue = fst, None
                        else:
                            dialogue = fst, snd
                    case "call fn_54B4C":
                        if addr is None:
                            addr = lineaddr
                        d = [s.strip() for s in st.findall(line)]
                        assert len(d) == 8
                        fst, snd = ''.join(d[:4]), ''.join(d[4:])
                        if fst == snd:
                            dialogue = fst, None
                        else:
                            dialogue = fst, snd
                    case _:
                        if dialogue[0]:
                            db.execute("INSERT INTO dialogue VALUES (?, ?, ?, ?, ?, ?)",
                                       (scriptid, addr, thread, speaker, *dialogue))
                            addr = None
                            speaker = None
                            dialogue = ("", None)

                match m.group(1):
                    case "call fn_15C0" | "call fn_1608":
                        s = sure.search(line)
                        tgt = int(s.group(1) or scriptid)
                        db.execute("INSERT OR IGNORE INTO graph VALUES (?, ?, ?, ?, NULL)",
                                   (scriptid, thread, tgt, s.group(2)))
                    case "call fn_F794" | "call fn_54F3C":
                        s = sure.search(line)
                        db.execute("INSERT INTO graph VALUES (?, ?, ?, ?, ?)",
                                   (scriptid, thread, int(s.group(1)), s.group(2), st.search(line).group(1)))
                    case _:
                        if sure.search(line) is not None:
                            raise Exception(f"found sure in {m.group(1)}")

db.autocommit = True
db.execute("VACUUM")
db.close()