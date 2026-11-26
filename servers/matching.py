"""Matches a server name from a scan to one server, ignoring capitals.

Order: the exact CMDB name, then CMDB's FQDN, then the short name (before the first dot) when only one CMDB
server has it. A name that matches no CMDB server, or more than one, becomes a server of its own for someone to
assign by hand. Herald never guesses between two CMDB servers.
"""
from collections import defaultdict

from .models import Server, short_key

EXACT, FQDN, SHORT, SCANNED, UNMATCHED, AMBIGUOUS = "exact", "fqdn", "short", "scanned", "unmatched", "ambiguous"
HOW_LABELS = {
    EXACT: "CMDB name", FQDN: "CMDB FQDN", SHORT: "Short name", SCANNED: "Found in an earlier scan, not in CMDB",
    UNMATCHED: "New, not in CMDB", AMBIGUOUS: "Matches more than one CMDB server",
}
NAME_SAMPLE = 3


class Resolver:
    def __init__(self):
        self.cmdb_by_name, self.scanned_by_name = {}, {}
        self.by_fqdn, self.by_short, self.names = defaultdict(list), defaultdict(list), {}
        rows = Server.objects.values_list("pk", "name", "name_key", "short_key", "fqdn_key", "in_cmdb")
        for pk, name, key, short, fqdn, in_cmdb in rows.iterator(chunk_size=5000):
            if not in_cmdb:
                self.scanned_by_name[key] = pk
                continue
            self.cmdb_by_name[key] = pk
            self.names[pk] = name
            self.by_short[short].append(pk)
            if fqdn:
                self.by_fqdn[fqdn].append(pk)

    def resolve(self, key):
        """(server pk or None, how, note)."""
        if key in self.cmdb_by_name:
            return self.cmdb_by_name[key], EXACT, ""
        if len(self.by_fqdn.get(key, ())) == 1:
            return self.by_fqdn[key][0], FQDN, ""
        candidates = self.by_short.get(short_key(key), [])
        if len(candidates) == 1:
            return candidates[0], SHORT, ""
        note = ""
        if len(candidates) > 1:
            names = sorted(self.names[pk] for pk in candidates)
            more = f" and {len(names) - NAME_SAMPLE} more" if len(names) > NAME_SAMPLE else ""
            note = f"Matches {len(names)} CMDB servers: {', '.join(names[:NAME_SAMPLE])}{more}"
        if key in self.scanned_by_name:
            return self.scanned_by_name[key], SCANNED, note
        return None, AMBIGUOUS if note else UNMATCHED, note

    def cmdb_match(self, key):
        """The one CMDB server a scanned server's name now points to, or None."""
        pk, how, _ = self.resolve(key)
        return pk if how in (EXACT, FQDN, SHORT) else None
