# SentinelGuard 4.2 — static coverage matrix

These are the **actual inspection paths**, not claims of malware efficacy.
"Deep" means bounded parsing of specific structure fields, NOT behavioral analysis.
Every file is read as data; nothing is executed.

| File type | Inspection level | Rules | Limits / missing coverage |
|---|---|---|---|
| EXE, DLL, SYS, SCR, CPL | **Bounded PE metadata** | PE header, section entropy, packer section names; combination of remote-write + allocation + thread-create imports; filename masquerade | Only files <=48 MiB receive section/import parsing. Ordinary high entropy/unsigned is not flagged. No memory/packer emulation; version resources/overlay/authenticity not fully integrated. |
| COM | Shallow static | Exact harmless EICAR test signature and metadata | No 16-bit DOS execution or runtime emulation |
| LNK | **Partial structured Shell Link parsing** | Valid header, StringData target/arguments, encoded PowerShell signals | Does not decode arbitrary target-ID lists, MSI advertised shortcuts, or all shell link ExtraData blocks |
| PowerShell, CMD, BAT, WSF, VBS, JS and related | Context-aware static text | Download+execute combinations, encoded commands, persistence, defense evasion strings | Reads a bounded head/tail; quoted commands and comments can be benign; obfuscation may evade |
| ZIP / nested ZIP / JAR / OOXML | Bounded archive entry inspection | Exact standalone EICAR in entries, double extension, included scripts, macro metadata | 3 nesting levels, 4,096 entries overall, 2 MiB read budget, <=16 MiB compressed entry, 128 KiB ordinary entry read, max ratio for larger entries; skip encrypted/unsupported |
| DOCM, XLSM, PPTM | Shallow macro metadata | ZIP entry `vbaProject.bin` + visible autorun strings | Does not parse/decompress full OLE VBA streams; presence alone is not a malware verdict |
| PDF | Shallow structural heuristics | `/OpenAction` + JavaScript action, `/Launch` action | Reads first 512 KiB; no full PDF object-graph parsing, encryption, incremental update analysis or JavaScript engine |
| TXT, JSON, XML | Context-based static text | Ransomware-style note, suspicious configs, scheduled-task persistence | Size and comment/disabled-state aware; cannot infer active execution from a document |
| JPG, PNG, GIF, etc. | Shallow file-signature check | Valid embedded PE masquerading as document/image | No image exploit/vulnerability scanning, no steganography detection |
| RAR, 7z and encrypted containers | Limited header / metadata | Misnamed-file clue only | No archive decompression; skipped/uninspected content must not be treated as clean |
| In-memory processes, network TLS, browser internals | **Not scanned** | None | SentinelGuard is not a kernel or process-monitor AV |

**Scoring:** Most signals need correlation and a score >=40 before the UI shows a finding; high confidence auto-quarantine remains a separate opt-in at score >=110 and does not imply certainty.

**EICAR:** Standard EICAR detection is a known harmless test-signature check. Its results are excluded from real-world malware-detection claims.

**Monitor:** Windows uses `FindFirstChangeNotificationW` to *wake a reconciliation scan*, not `ReadDirectoryChangesW`. No notification buffer exists to overflow in this architecture; missed notifications are eventually covered by the timed directory enumeration. The monitor is *not* a pre-execution blocker.
