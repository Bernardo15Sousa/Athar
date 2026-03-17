"""
athar.correlation.enrichment
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Enrichment functions for artefact records.

Provides:
- KNOWN_LOLBINS: set of known Living-off-the-Land binaries
- LOLBIN_MITRE: mapping of LOLBin filename to primary MITRE ATT&CK technique
- is_lolbin(): check if a filename is a known LOLBin
- get_lolbin_mitre(): get MITRE technique for a LOLBin
- normalise_windows_path(): ensure consistent path representation
- tag_record(): apply enrichment tags to a BaseRecord

References
----------
- LOLBAS Project: https://lolbas-project.github.io
- MITRE ATT&CK T1218: https://attack.mitre.org/techniques/T1218/
"""

from __future__ import annotations

import logging
from typing import Optional

from athar.models.base import BaseRecord, normalise_path

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# LOLBins registry
# ---------------------------------------------------------------------------

# Living-off-the-Land Binaries — executables that can be abused by attackers
# to proxy execution, download files, bypass defences, etc.
# Reference: https://lolbas-project.github.io
KNOWN_LOLBINS: frozenset[str] = frozenset({
    # Scripting hosts
    "WSCRIPT.EXE",
    "CSCRIPT.EXE",
    "MSHTA.EXE",
    # PowerShell variants
    "POWERSHELL.EXE",
    "POWERSHELL_ISE.EXE",
    "PWSH.EXE",
    # System binary proxy execution
    "RUNDLL32.EXE",
    "REGSVR32.EXE",
    "REGASM.EXE",
    "REGSVCS.EXE",
    "INSTALLUTIL.EXE",
    "MSIEXEC.EXE",
    "ODBCCONF.EXE",
    "IEEXEC.EXE",
    "CONTROL.EXE",
    "SYNCAPPVPUBLISHINGSERVER.EXE",
    "APPSYNCPUBLISHINGSERVER.EXE",
    "MICROSOFT.WORKFLOW.COMPILER.EXE",
    "XWIZARD.EXE",
    "VERCLSID.EXE",
    "PCALUA.EXE",
    "SCRIPTRUNNER.EXE",
    "RUNSCRIPTHELPER.EXE",
    "INFDEFAULTINSTALL.EXE",
    # Credential / recon
    "WMIC.EXE",
    "NET.EXE",
    "NET1.EXE",
    "NLTEST.EXE",
    "IPCONFIG.EXE",
    # Download / transfer
    "CERTUTIL.EXE",
    "BITSADMIN.EXE",
    "EXPAND.EXE",
    "EXTRAC32.EXE",
    "MAKECAB.EXE",
    "REPLACE.EXE",
    "ESENTUTL.EXE",
    "RPCPING.EXE",
    "FTP.EXE",
    # Registry / service manipulation
    "REG.EXE",
    "SC.EXE",
    "SCHTASKS.EXE",
    # Lateral movement
    "PSEXEC.EXE",
    "PSEXESVC.EXE",
    # Code execution
    "CSI.EXE",
    "VBC.EXE",
    "CMSTP.EXE",
    "BASH.EXE",
    "BGINFO.EXE",
    "DNSCMD.EXE",
    "FORFILES.EXE",
    "FINDSTR.EXE",
    "GPSCRIPT.EXE",
    "HHTCTL.EXE",
    "MAVINJECT.EXE",
    "MSCONFIG.EXE",
    "TTTRACER.EXE",
    "WUAUCLT.EXE",
    "WMIC.EXE",
})

# Primary MITRE ATT&CK technique per LOLBin
# Not exhaustive — maps to the most common abuse technique
LOLBIN_MITRE: dict[str, str] = {
    "RUNDLL32.EXE":     "T1218.011",
    "REGSVR32.EXE":     "T1218.010",
    "MSHTA.EXE":        "T1218.005",
    "MSIEXEC.EXE":      "T1218.007",
    "INSTALLUTIL.EXE":  "T1218.004",
    "REGASM.EXE":       "T1218.009",
    "REGSVCS.EXE":      "T1218.009",
    "CMSTP.EXE":        "T1218.003",
    "ODBCCONF.EXE":     "T1218.008",
    "WSCRIPT.EXE":      "T1059.005",
    "CSCRIPT.EXE":      "T1059.005",
    "POWERSHELL.EXE":   "T1059.001",
    "PWSH.EXE":         "T1059.001",
    "POWERSHELL_ISE.EXE": "T1059.001",
    "CERTUTIL.EXE":     "T1140",
    "BITSADMIN.EXE":    "T1197",
    "WMIC.EXE":         "T1047",
    "NET.EXE":          "T1069",
    "NET1.EXE":         "T1069",
    "SC.EXE":           "T1543.003",
    "SCHTASKS.EXE":     "T1053.005",
    "REG.EXE":          "T1112",
    "PSEXEC.EXE":       "T1569.002",
    "PSEXESVC.EXE":     "T1569.002",
    "NLTEST.EXE":       "T1482",
    "BASH.EXE":         "T1059.004",
    "MAVINJECT.EXE":    "T1055.001",
    "WUAUCLT.EXE":      "T1218",
    "XWIZARD.EXE":      "T1218",
    "CONTROL.EXE":      "T1218",
    "DNSCMD.EXE":       "T1543",
    "FTP.EXE":          "T1071.002",
    "ESENTUTL.EXE":     "T1003",
    "FINDSTR.EXE":      "T1552.001",
    "FORFILES.EXE":     "T1218",
    "EXPAND.EXE":       "T1218",
    "MAKECAB.EXE":      "T1560.001",
    "EXTRAC32.EXE":     "T1218",
    "REPLACE.EXE":      "T1218",
}


# ---------------------------------------------------------------------------
# LOLBin helpers
# ---------------------------------------------------------------------------

def is_lolbin(filename: str) -> bool:
    """
    Return True if the filename matches a known LOLBin.

    Parameters
    ----------
    filename : str
        Executable filename. Case-insensitive.

    Returns
    -------
    bool

    Examples
    --------
    >>> is_lolbin("powershell.exe")
    True
    >>> is_lolbin("notepad.exe")
    False
    """
    return filename.upper() in KNOWN_LOLBINS


def get_lolbin_mitre(filename: str) -> Optional[str]:
    """
    Return the primary MITRE ATT&CK technique ID for a LOLBin.

    Returns None if the filename is not in the LOLBIN_MITRE mapping.

    Parameters
    ----------
    filename : str
        Executable filename. Case-insensitive.

    Returns
    -------
    str or None
        ATT&CK technique ID (e.g. "T1218.011") or None.
    """
    return LOLBIN_MITRE.get(filename.upper())


# ---------------------------------------------------------------------------
# Enrichment tags
# ---------------------------------------------------------------------------

# Common suspicious path prefixes that warrant extra attention
_SUSPICIOUS_PATHS: tuple[str, ...] = (
    "\\USERS\\",
    "\\TEMP\\",
    "\\TMP\\",
    "\\APPDATA\\",
    "\\PROGRAMDATA\\",
    "\\RECYCLER\\",
    "\\RECYCLE.BIN\\",
    "\\PUBLIC\\",
    "\\WINDOWS\\TEMP\\",
)

# System directories — execution from here is expected (lower suspicion)
_SYSTEM_PATHS: tuple[str, ...] = (
    "\\WINDOWS\\SYSTEM32\\",
    "\\WINDOWS\\SYSWOW64\\",
    "\\WINDOWS\\",
    "\\PROGRAM FILES\\",
    "\\PROGRAM FILES (X86)\\",
)


def get_path_tags(path: str) -> list[str]:
    """
    Return enrichment tags based on path location.

    Parameters
    ----------
    path : str
        Normalised Windows path (uppercase, backslash).

    Returns
    -------
    list[str]
        Tags such as ["suspicious_path"] or ["system_path"].
    """
    tags: list[str] = []
    path_upper = path.upper()

    for suspicious in _SUSPICIOUS_PATHS:
        if suspicious in path_upper:
            tags.append("suspicious_path")
            break

    for system in _SYSTEM_PATHS:
        if system in path_upper:
            tags.append("system_path")
            break

    return tags


def enrich_record(record: BaseRecord) -> list[str]:
    """
    Compute enrichment tags for a single artefact record.

    Parameters
    ----------
    record : BaseRecord
        Any artefact record.

    Returns
    -------
    list[str]
        List of enrichment tag strings. May be empty.
    """
    tags: list[str] = []

    if is_lolbin(record.filename):
        tags.append("lolbin")

    tags.extend(get_path_tags(record.path))

    return tags
