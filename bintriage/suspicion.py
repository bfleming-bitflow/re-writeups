"""Heuristic categorization of imported API names.

Categories are based on well-known Windows and POSIX APIs that reverse engineers
commonly flag during triage. A hit is not proof of malice.
"""

from __future__ import annotations

CATEGORIES: dict[str, frozenset[str]] = {
    "process": frozenset(
        {
            "createprocessa",
            "createprocessw",
            "createprocessasusera",
            "createprocessasuserw",
            "winexec",
            "shellexecutea",
            "shellexecutew",
            "shellexecuteexa",
            "shellexecuteexw",
            "system",
            "posix_spawn",
            "execve",
            "execl",
            "execvp",
        }
    ),
    "injection": frozenset(
        {
            "virtualallocex",
            "virtualprotectex",
            "writeprocessmemory",
            "readprocessmemory",
            "createremotethread",
            "createremotethreadex",
            "ntmapviewofsection",
            "ntunmapviewofsection",
            "queuauserapc",
            "setthreadcontext",
            "resumethread",
            "ptrace",
            "process_vm_writev",
        }
    ),
    "crypto": frozenset(
        {
            "cryptencrypt",
            "cryptdecrypt",
            "cryptimportkey",
            "cryptacquirecontexta",
            "cryptacquirecontextw",
            "bcryptencrypt",
            "bcryptdecrypt",
            "bcryptgeneratesymmetrickey",
        }
    ),
    "network": frozenset(
        {
            "internetopena",
            "internetopenw",
            "internetopenurla",
            "internetopenurlw",
            "internetreadfile",
            "urldownloadtofilea",
            "urldownloadtofilew",
            "wsastartup",
            "connect",
            "send",
            "recv",
            "socket",
            "getaddrinfo",
            "httpopenrequesta",
            "httpopenrequestw",
        }
    ),
    "persistence": frozenset(
        {
            "regsetvaluea",
            "regsetvaluew",
            "regsetvalueexa",
            "regsetvalueexw",
            "regcreatekeya",
            "regcreatekeyw",
            "regcreatekeyexa",
            "regcreatekeyexw",
        }
    ),
    "anti_analysis": frozenset(
        {
            "isdebuggerpresent",
            "checkremotedebuggerpresent",
            "ntqueryinformationprocess",
            "outputdebugstringa",
            "outputdebugstringw",
            "gettickcount",
            "gettickcount64",
            "queryperformancecounter",
        }
    ),
    "file": frozenset(
        {
            "createfilea",
            "createfilew",
            "writefile",
            "deletefilea",
            "deletefilew",
            "movefilea",
            "movefilew",
            "copyfilea",
            "copyfilew",
        }
    ),
}


def categorize(imports: list[str]) -> dict[str, list[str]]:
    """Map import names to suspicion categories (case-insensitive)."""
    hits: dict[str, list[str]] = {name: [] for name in CATEGORIES}
    for original in imports:
        key = original.lower().split("@", 1)[0]
        # PE exports sometimes decorate; strip ordinals already handled by caller
        for category, names in CATEGORIES.items():
            if key in names:
                hits[category].append(original)
    return {category: sorted(set(values)) for category, values in hits.items() if values}
