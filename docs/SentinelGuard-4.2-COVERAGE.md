# SentinelGuard 4.2 — static file coverage matrix

The classifications below measure **code inspection depth, not proven malware detection**.

| Files | Depth | Static checks | Unsupported |
|---|---|---|---|
| EXE / DLL / SYS / SCR / CPL | Partial deep | PE header; bounded debug/pe section entropy, import combinations, overlay, filename/location; Authenticode metadata on Windows launch review | Complete resource parsing, packing/unpacking, dynamic execution, memory-only attacks |
| LNK | Partial deep | Shell Link header and CLSID, flags, StringData relative path/arguments, hidden window and encoded network command correlations | Every LinkInfo / ExtraData variation or behavior |
| DOCM / XLSM / PPTM | Shallow structural | OOXML ZIP members, bounded vbaProject.bin strings and auto-run plus execution correlations | OLE/VBA stream decompression, macro emulation |
| DOCX / XLSX / PPTX / ZIP / JAR | Bounded recursive | ZIP metadata, safe nested ZIP, the harmless exact EICAR marker for all member extensions, bounded script text | Encrypted/oversized archives, unsupported codecs, indefinite recursion |
| PDF | Shallow structural | First 512 KiB, PDF magic, OpenAction with JS, Launch actions referencing executables | PDF compressed object streams, XFA and full syntax |
| PS1 / PSM1 / BAT / CMD / VBS / JS / JSE / WSF / SCT / HTA | Contextual static | Bounded command correlations, basic deobfuscation, persistence, downloader and interpreter patterns | Runtime behavior and sophisticated obfuscation |
| HTML / HTM / SVG | Shallow textual | HTML-smuggling and embedded risky script correlations | Browser execution or DOM simulation |
| TXT / JSON / XML / REG | Selective advisory | Ransom note, suspicious config or persistence strings | General document intent or semantics |
| Image formats | Basic metadata | Disguised PE header and short sampled metadata | Steganography and decoder vulnerability analysis |
| 7z / RAR | Very shallow | File header checks and exposed uncompressed text only | Genuine compressed content inspection |
| TAR / GZIP / ISO / IMG | Minimal / unsupported | Naming/context metadata | TAR/GZIP decompression, mounted ISO filesystem |
| Other extensions | Minimal | Path/filename indicators | Specialized parsing |

## Bounds and exceptions

- ZIP recursion: maximum 3 nested levels and 4,096 entries in total; 2 MiB global read budget; per-member limit 128 KiB and nested member 512 KiB; compressed-size ceiling 16 MiB; compression-expansion bound.
- PE: maximum 64 MiB input, 96 sections and 32 KiB read per executable section. Entropy alone never creates a finding.
- PDF: first 512 KiB only. OOXML VBA binary: at most 128 KiB of visible text sampled, no VBA decompression.
- Active monitoring is user-mode, with safe file-count and size limits. There is no kernel minifilter, memory scanner, dynamic sandbox, process-event blocker or reputation signature feed.

## Fixture classifications and evaluation policies

The original Stage 6–12 and Claude-supplied corpora are **development/regression fixtures**. They include many **indicator-present, non-operational** samples (inert or commented commands) and potentially operational commands that are never executed; their existing suspicious-vs-benign fixture labels are not ground-truth malware labels. No scoring rule is adjusted solely to make a matrix reach 100%, and historical fixture tests are retained. Any expectation updated for the 4.2 API is separately explained.

The EICAR and AMTSO files are harmless published antivirus feature tests, never real malware. Large Windows/Program Files/Python/npm read-only benign surveys are **false-positive measurements**, not detector sensitivity estimates. A predeclared Windows benign-file subset is a prospective frozen holdout and must never be used to tune rules. It overlaps a few earlier known Windows executables; it is not fully independent. No labeled real-malware holdout exists in this release; report that explicitly rather than calculating a fabricated sensitivity interval.
