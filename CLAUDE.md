Athar — Windows DFIR Artefact Correlation Engine
Claude Code Prompt
What You Are Building
Athar is a cross-platform, single-binary-equivalent Python tool that ingests four Windows forensic artefacts, correlates them temporally, and produces an analyst-ready timeline with findings, tags, and a self-contained HTML report.
This is not a demo. It is a professional-grade DFIR tool built to the standard of Eric Zimmerman's tooling — but in Python, cross-platform, and open-source.
One tool. Does one thing. Does it exceptionally well.
Identity
Name        : Athar Author      : Bernardo Sousa Version     : 0.1.0 Python      : 3.10+ Platform    : Windows, Linux, macOS License     : MIT Tagline     : Every file leaves a trace. Athar finds it. 
ASCII banner for CLI (print on startup):
    ___            __
 /\   |  |__|  /\  |__)
/~~\  |  |  | /~~\ |  \

Athar v0.1.0 — by Bernardo Sousa  |  Windows DFIR Artefact Correlation
Replace placeholder with actual tool name when defined. For now use Athar.
Project Structure
athar/ ├── __init__.py ├── cli.py                        # Click CLI entry point + ASCII banner ├── config.py                     # Constants, LOLBins list, default Event IDs ├── models/ │   ├── __init__.py │   ├── base.py                   # BaseRecord, CorrelatedEvent dataclasses │   ├── prefetch.py               # PrefetchRecord │   ├── mft.py                    # MFTRecord │   ├── usn.py                    # USNRecord │   └── evtx.py                   # EventLogRecord ├── parsers/ │   ├── __init__.py │   ├── prefetch_parser.py │   ├── mft_parser.py │   ├── usn_parser.py             # Pure binary parser, no external lib │   └── evtx_parser.py ├── correlation/ │   ├── __init__.py │   ├── engine.py                 # Timeline merge + deduplication │   ├── rules.py                  # Correlation rule functions │   └── enrichment.py            # Path normalisation, LOLBin tagging ├── output/ │   ├── __init__.py │   ├── json_exporter.py │   ├── csv_exporter.py │   └── html_reporter.py         # Jinja2 renderer ├── templates/ │   └── report.html.j2 ├── tests/ │   ├── fixtures/                 # Binary fixture files for unit tests │   ├── test_prefetch.py │   ├── test_mft.py │   ├── test_usn.py │   ├── test_evtx.py │   └── test_correlation.py ├── pyproject.toml ├── requirements.txt └── README.md 
Data Models
BaseRecord
from dataclasses import dataclass, field from datetime import datetime from typing import Optional  @dataclass class BaseRecord:     timestamp: datetime              # UTC, timezone-aware     source: str                      # "prefetch" | "mft" | "usn" | "evtx"     event_type: str                  # See event type constants below     path: str                        # Full path, uppercase, backslash-normalised     filename: str                    # os.path.basename(path).upper()     pid: Optional[int] = None     details: dict = field(default_factory=dict)   # Source-specific fields     raw: Optional[dict] = None  # Event type constants (use these everywhere, no raw strings) class EventType:     EXECUTION       = "execution"     FILE_CREATE     = "file_create"     FILE_DELETE     = "file_delete"     FILE_RENAME     = "file_rename"     FILE_MODIFY     = "file_modify"     PROCESS_CREATE  = "process_create"     LOGON           = "logon"     LOGON_FAIL      = "logon_failure"     SERVICE_INSTALL = "service_install"     TASK_CREATE     = "task_create"     LOG_CLEARED     = "log_cleared"     SCRIPT_BLOCK    = "script_block"     USER_CREATE     = "user_create"     GROUP_CHANGE    = "group_change" 
PrefetchRecord
@dataclass class PrefetchRecord(BaseRecord):     executable: str = ""     run_count: int = 0     run_times: list[datetime] = field(default_factory=list)     referenced_files: list[str] = field(default_factory=list)     referenced_volumes: list[str] = field(default_factory=list)     pf_version: int = 0 
MFTRecord
@dataclass class MFTRecord(BaseRecord):     entry_number: int = 0     sequence_number: int = 0     parent_entry: int = 0     si_created: Optional[datetime] = None     si_modified: Optional[datetime] = None     si_mft_modified: Optional[datetime] = None     si_accessed: Optional[datetime] = None     fn_created: Optional[datetime] = None     fn_modified: Optional[datetime] = None     file_size: int = 0     is_directory: bool = False     is_deleted: bool = False     timestomp_suspect: bool = False   # True if SI and FN differ > 2s 
USNRecord
@dataclass class USNRecord(BaseRecord):     usn: int = 0     file_reference: int = 0     parent_reference: int = 0     reason_flags: list[str] = field(default_factory=list)     reason_raw: int = 0 
EventLogRecord
@dataclass class EventLogRecord(BaseRecord):     event_id: int = 0     computer: str = ""     channel: str = ""     provider: str = ""     event_data: dict = field(default_factory=dict) 
CorrelatedEvent
@dataclass class CorrelatedEvent:     window_start: datetime     window_end: datetime     primary_path: str     primary_filename: str     records: list[BaseRecord]     tags: list[str]     confidence: str          # "high" | "medium" | "low"     notes: list[str]         # Human-readable analyst notes     mitre_tags: list[str]    # ATT&CK technique IDs e.g. ["T1059.001", "T1053.005"] 
Parser Specifications
1. Prefetch Parser (parsers/prefetch_parser.py)
Dependencies: Try python-libscca first. If unavailable, implement pure-Python PF format parser.
Supported versions:
* v17 (XP), v23 (Vista/7), v26 (Win8), v30 (Win10+)
* Handle MAM compression (Win10+ uses Xpress Huffman — decompress before parsing)
Per .pf file, extract:
* Executable name (strip -XXXXXXXX.pf hash suffix)
* Format version
* Last run time (v17/v23: single timestamp; v26/v30: up to 8 timestamps)
* Run count
* Referenced file strings (up to 1024)
* Referenced volume info
Output: One PrefetchRecord per execution timestamp (not per file). If a file has 3 run times, emit 3 records with event_type = EventType.EXECUTION.
Error handling: Log warning and skip file on any parse error. Never raise.
2. USN Journal Parser (parsers/usn_parser.py)
No external library. Implement full binary parser from scratch.
USN Record v2 structure (little-endian):
Offset  Size  Field 0       4     RecordLength (DWORD) 4       2     MajorVersion (WORD) — must be 2 6       2     MinorVersion (WORD) 8       8     FileReferenceNumber (DWORDLONG) 16      8     ParentFileReferenceNumber (DWORDLONG) 24      8     Usn (LONGLONG) 32      8     TimeStamp (FILETIME — 100ns intervals since 1601-01-01) 40      4     Reason (DWORD — bitmask) 44      4     SourceInfo (DWORD) 48      4     SecurityId (DWORD) 52      4     FileAttributes (DWORD) 56      2     FileNameLength (WORD) 58      2     FileNameOffset (WORD) 60      var   FileName (UTF-16LE, FileNameLength bytes) 
FILETIME conversion:
import datetime EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)  def filetime_to_datetime(ft: int) -> datetime.datetime:     return EPOCH + datetime.timedelta(microseconds=ft // 10) 
Reason flags bitmask — implement parse_reason_flags(flags: int) -> list[str]:
USN_REASONS = {     0x00000001: "DATA_OVERWRITE",     0x00000002: "DATA_EXTEND",     0x00000004: "DATA_TRUNCATION",     0x00000010: "NAMED_DATA_OVERWRITE",     0x00000020: "NAMED_DATA_EXTEND",     0x00000040: "NAMED_DATA_TRUNCATION",     0x00000100: "FILE_CREATE",     0x00000200: "FILE_DELETE",     0x00000400: "EA_CHANGE",     0x00000800: "SECURITY_CHANGE",     0x00001000: "RENAME_OLD_NAME",     0x00002000: "RENAME_NEW_NAME",     0x00004000: "INDEXABLE_CHANGE",     0x00008000: "BASIC_INFO_CHANGE",     0x00010000: "HARD_LINK_CHANGE",     0x00020000: "COMPRESSION_CHANGE",     0x00040000: "ENCRYPTION_CHANGE",     0x00080000: "OBJECT_ID_CHANGE",     0x00100000: "REPARSE_POINT_CHANGE",     0x00200000: "STREAM_CHANGE",     0x80000000: "CLOSE", } 
Parsing strategy:
* Input file may have leading zeroes (sparse regions) — skip 4096-byte blocks of zeroes
* Iterate: read RecordLength, if 0 skip to next aligned offset, else parse full record
* FileReferenceNumber: high 16 bits = sequence number, low 48 bits = MFT entry number
event_type mapping from reason flags:
* FILE_CREATE → EventType.FILE_CREATE
* FILE_DELETE → EventType.FILE_DELETE
* RENAME_NEW_NAME → EventType.FILE_RENAME
* DATA_EXTEND / DATA_OVERWRITE → EventType.FILE_MODIFY
* Multiple flags on same record → use most significant event type
3. Event Log Parser (parsers/evtx_parser.py)
Dependency: python-evtx
Target Event IDs (define in config.py as DEFAULT_EVENT_IDS, allow CLI override):
DEFAULT_EVENT_IDS = {     # Logon/Auth     4624: ("evtx", EventType.LOGON,          "Logon success"),     4625: ("evtx", EventType.LOGON_FAIL,     "Logon failure"),     4648: ("evtx", EventType.LOGON,          "Explicit credentials logon"),     # Process     4688: ("evtx", EventType.PROCESS_CREATE, "Process creation"),     # Persistence     4697: ("evtx", EventType.SERVICE_INSTALL,"Service installed"),     4698: ("evtx", EventType.TASK_CREATE,    "Scheduled task created"),     4702: ("evtx", EventType.TASK_CREATE,    "Scheduled task modified"),     # Account     4720: ("evtx", EventType.USER_CREATE,    "User account created"),     4726: ("evtx", EventType.USER_CREATE,    "User account deleted"),     4732: ("evtx", EventType.GROUP_CHANGE,   "Member added to group"),     4733: ("evtx", EventType.GROUP_CHANGE,   "Member removed from group"),     # System     7045: ("evtx", EventType.SERVICE_INSTALL,"New service installed"),     1102: ("evtx", EventType.LOG_CLEARED,    "Audit log cleared"),     # PowerShell     4104: ("evtx", EventType.SCRIPT_BLOCK,   "PS ScriptBlock logged"), } 
Path extraction: For events with path-related EventData fields (NewProcessName for 4688, ServiceFileName for 4697, etc.), populate record.path.
Normalisation: All paths to uppercase Windows format on ingest.
4. MFT Parser (parsers/mft_parser.py)
Dependency: Evaluate mft (python-mft) vs analyzeMFT. Choose based on Python 3.10+ compatibility and active maintenance. Include choice rationale in README.
Per record, extract:
* MFT entry number + sequence number
* $FILE_NAME attribute: prefer Win32 name over DOS 8.3
* Parent entry reference (for path resolution)
* $STANDARD_INFORMATION: all 4 MACB timestamps
* $FILE_NAME: all 4 MACB timestamps
* File size (from $DATA attribute, non-resident)
* Is directory (from record flags)
* Is deleted (check record allocation flag)
Path resolution:
* Build entry_map: dict[int, MFTRecord] during parsing
* Resolve full path by walking parent references up to entry 5 (root)
* Cap recursion at 32 levels to avoid loops
* If parent not found, use \\[ORPHAN]\\filename
Timestomp detection:
def check_timestomp(record: MFTRecord) -> bool:     """     Flag if $STANDARD_INFORMATION created differs from $FILE_NAME created by > 2s.     This is the most reliable timestomp indicator.     """     if record.si_created and record.fn_created:         delta = abs((record.si_created - record.fn_created).total_seconds())         return delta > 2.0     return False 
Correlation Engine
Timeline Merge (correlation/engine.py)
def build_timeline(     prefetch: list[PrefetchRecord],     mft: list[MFTRecord],     usn: list[USNRecord],     evtx: list[EventLogRecord],     start: Optional[datetime] = None,     end: Optional[datetime] = None, ) -> list[BaseRecord]:     """Merge, filter by time range, sort ascending by timestamp.""" 
Grouping for Correlation
* Group records into time windows of ±60 seconds around each anchor event
* Anchor events: Prefetch execution records and EventLog 4688 records
* Within each window, check which rules fire
CorrelatedEvent Assembly
* Each fired rule returns a CorrelatedEvent
* Deduplicate: if two rules produce events with >80% overlapping record sets, merge them (combine tags, notes, take highest confidence)
Correlation Rules (correlation/rules.py)
Implement each rule as an independent function: def rule_name(records: list[BaseRecord]) -> list[CorrelatedEvent]
Call all rules from engine.py and aggregate results.
Rules to implement (in priority order):
1. rule_lolbin_execution — HIGH VALUE, IMPLEMENT FIRST
* Any Prefetch/4688 record where filename matches KNOWN_LOLBINS
* Confidence: high
* Tags: ["lolbin_execution"]
* MITRE: T1218 (System Binary Proxy Execution) + specific subtechnique
* Note: "LOLBin executed: {filename} at {timestamp}"
2. rule_execution_of_new_file
* Prefetch record + USN FILE_CREATE for same filename within ±60s
* Confidence: high
* Tags: ["execution", "new_file"]
* MITRE: T1204.002
* Note: "File created and executed within 60s: {path}"
3. rule_timestomp
* MFT record with timestomp_suspect=True + Prefetch execution for same file
* Confidence: high
* Tags: ["timestomping", "execution"]
* MITRE: T1070.006
* Note: "Possible timestomping: SI created={si_created}, FN created={fn_created}"
4. rule_log_cleared
* EventLog 1102 anywhere in dataset
* Look for Prefetch/4688 activity within 10 minutes after
* Confidence: high if activity follows, medium if isolated
* Tags: ["log_cleared", "defence_evasion"]
* MITRE: T1070.001
5. rule_service_install
* Event 7045 or 4697 + MFT/USN file creation for service binary within ±120s
* Confidence: high
* Tags: ["service_install", "persistence"]
* MITRE: T1543.003
6. rule_scheduled_task
* Event 4698/4702
* Confidence: high (standalone — scheduled tasks are always notable)
* Tags: ["scheduled_task", "persistence"]
* MITRE: T1053.005
7. rule_executable_dropped_and_run
* MFT new file (fn_created close to analysis window) + Prefetch execution for same file within ±120s
* Confidence: medium (MFT path resolution may be incomplete)
* Tags: ["dropper", "execution"]
* MITRE: T1204.002
LOLBins list (enrichment.py)
KNOWN_LOLBINS = {     "PSEXEC.EXE", "PSEXESVC.EXE",     "WMIC.EXE", "WSCRIPT.EXE", "CSCRIPT.EXE",     "MSHTA.EXE", "RUNDLL32.EXE", "REGSVR32.EXE",     "CERTUTIL.EXE", "BITSADMIN.EXE",     "MSIEXEC.EXE", "INSTALLUTIL.EXE",     "REGASM.EXE", "REGSVCS.EXE",     "ODBCCONF.EXE", "IEEXEC.EXE",     "MSCONFIG.EXE", "ESENTUTL.EXE",     "EXPAND.EXE", "EXTRAC32.EXE",     "FINDSTR.EXE", "HHTCTL.EXE",     "MAKECAB.EXE", "MAVINJECT.EXE",     "MICROSOFT.WORKFLOW.COMPILER.EXE",     "NET.EXE", "NET1.EXE",     "NLTEST.EXE", "PCALUA.EXE",     "REPLACE.EXE", "RPCPING.EXE",     "RUNSCRIPTHELPER.EXE", "SC.EXE",     "SCRIPTRUNNER.EXE", "SYNCAPPVPUBLISHINGSERVER.EXE",     "TTTRACER.EXE", "VBC.EXE",     "VERCLSID.EXE", "WUAUCLT.EXE",     "XWIZARD.EXE", "APPSYNCPUBLISHINGSERVER.EXE",     "BASH.EXE", "BGINFO.EXE",     "CMSTP.EXE", "CONTROL.EXE",     "CSI.EXE", "DNSCMD.EXE",     "FORFILES.EXE", "FTP.EXE",     "GPSCRIPT.EXE", "INFDEFAULTINSTALL.EXE",     "IPCONFIG.EXE", "POWERSHELL.EXE",     "POWERSHELL_ISE.EXE", "PWSH.EXE",     "REG.EXE", "REGSRV32.EXE", } # Reference: https://lolbas-project.github.io 
Output
JSON Exporter (output/json_exporter.py)
* Serialise list of CorrelatedEvent to JSON
* Include metadata header:
{   "meta": {     "tool": "Athar",     "version": "0.1.0",     "author": "Bernardo Sousa",     "analysis_timestamp": "...",     "hostname": "...",     "artefacts_processed": {...},     "time_range": {"start": "...", "end": "..."}   },   "correlated_events": [...],   "raw_timeline": [...] } 
CSV Exporter (output/csv_exporter.py)
Flat timeline. Columns: timestamp, source, event_type, path, filename, pid, tags, confidence, mitre_tags, notes
Sorted ascending by timestamp. Compatible with Timeline Explorer (EZ Tools) column format where possible.
HTML Reporter (output/html_reporter.py + templates/report.html.j2)
Single self-contained file. All CSS and JS inline. No CDN dependencies. Must open correctly offline.
Design direction — Industrial Terminal:
* Background: #0d0d0d
* Surface: #141414
* Border/grid: #1e1e1e
* Accent primary: #00ff9d (terminal green)
* Accent danger: #ff3c3c
* Accent warning: #ffaa00
* Accent muted: #5a5a5a
* Font: JetBrains Mono (embed via base64 or use monospace fallback)
* Everything is monospaced — this is a forensic tool, not a marketing page
Report sections:
1. Header bar
   * Tool name + version left
   * Hostname | Analysis timestamp | Artefacts processed right
   * Thin accent-green border bottom
2. Executive Summary (card row)
   * Total events | High confidence findings | LOLBin executions | Time range
   * Each card: large number, label below, coloured by severity
3. High Confidence Findings
   * Each finding: timestamp, confidence badge, tags as pills, primary path, MITRE tags, analyst notes
   * Sorted by timestamp
   * Expandable row to show contributing records
4. LOLBin Executions Table
   * Columns: First Seen | Last Seen | Binary | Run Count | MITRE | Source
   * Sortable by clicking column header (vanilla JS)
5. Full Timeline
   * Columns: Timestamp | Source | Event Type | Path | Tags | PID
   * Filter bar: free-text search + source checkboxes + event type filter
   * Colour-code rows by source (green=prefetch, blue=evtx, yellow=usn, cyan=mft)
   * Virtual scroll for large datasets (render only visible rows)
6. Artefact Statistics
   * Mini table: source → record count → time range
No third-party JS frameworks. Vanilla JS only. Keep the JS under 200 lines.
CLI (cli.py)
athar [OPTIONS]  Input:   --prefetch PATH      Directory of .pf files   --mft PATH           Path to $MFT binary   --usn PATH           Path to $UsnJrnl:$J   --evtx PATH          Directory of .evtx files  Output:   --output PATH        Output directory [default: ./athar_output]   --format [json|csv|html|all]  [default: all]  Filters:   --start DATETIME     ISO 8601 start filter   --end DATETIME       ISO 8601 end filter   --hostname TEXT      Label for report [default: unknown]  Verbosity:   --verbose / --quiet   --log-level [DEBUG|INFO|WARNING|ERROR]  Meta:   --version   --help 
Progress output (use rich or plain stderr):
[✓] Parsing Prefetch  → 312 records [✓] Parsing USN       → 48,221 records [✓] Parsing EVTX      → 1,204 records [!] MFT not provided  → skipped [→] Correlating       → 14 events (6 high confidence) [✓] Writing JSON      → ./output/athar_20240315_143022.json [✓] Writing CSV       → ./output/athar_20240315_143022.csv [✓] Writing HTML      → ./output/athar_20240315_143022.html 
Implementation Order
Work strictly in this sequence. Do not scaffold empty files. Every file must contain working, tested code before moving to the next.
Step 1  pyproject.toml + requirements.txt Step 2  models/base.py — BaseRecord, CorrelatedEvent, EventType Step 3  models/prefetch.py, mft.py, usn.py, evtx.py Step 4  parsers/usn_parser.py + tests/test_usn.py (with synthetic fixture) Step 5  parsers/evtx_parser.py + tests/test_evtx.py Step 6  parsers/prefetch_parser.py + tests/test_prefetch.py Step 7  parsers/mft_parser.py + tests/test_mft.py Step 8  enrichment.py (KNOWN_LOLBINS, path normalisation) Step 9  correlation/rules.py — rules 1 and 4 first (lolbin, log_cleared) Step 10 correlation/engine.py — timeline merge + rule orchestration Step 11 output/json_exporter.py + csv_exporter.py Step 12 templates/report.html.j2 + output/html_reporter.py Step 13 cli.py — wire everything together Step 14 README.md — architecture, usage, sample output 
Code Quality Non-Negotiables
* Type hints on every function signature
* Docstrings on every module, class, and public method
* logging everywhere — no print() outside cli.py
* All timestamps: datetime objects, UTC, timezone-aware, converted at parse time
* All paths: uppercase, backslash-normalised, converted at parse time
* Corrupt/truncated artefact files: log warning, skip record, continue — never crash
* No hardcoded paths
* pyproject.toml with correct metadata, entry point, and optional dependencies
Dependencies
[project] dependencies = [     "click>=8.1",     "python-evtx>=0.8.0",     "Jinja2>=3.1",     "python-dateutil>=2.9",     "colorama>=0.4",     "rich>=13.0", ]  [project.optional-dependencies] libscca = ["python-libscca>=20240216"] dev = ["pytest>=8.0", "pytest-cov"] 
README Sections (write last, write properly)
1. What it is (2 sentences)
2. Artefacts supported
3. Installation
4. Usage with examples
5. Output formats
6. Architecture diagram (ASCII or Mermaid)
7. Correlation rules explained
8. Sample HTML report screenshot
9. Roadmap
10. Author + licence
Replace all instances of Athar and athar with the actual tool name before running Claude Code.
