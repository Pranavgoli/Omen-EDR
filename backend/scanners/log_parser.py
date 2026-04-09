import re
import os
import tempfile
import string
import tarfile
import gzip
import io
import json
import csv
import xml.dom.minidom
from typing import Dict, List, Any

try:
    from Evtx.Evtx import Evtx
    EVTX_AVAILABLE = True
except ImportError:
    EVTX_AVAILABLE = False

try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class LogParser:
    def __init__(self):
        # Heuristic Regex patterns
        self.ipv4_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        self.email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        self.path_pattern = re.compile(r'(/[a-zA-Z0-9_.-]+)+|[a-zA-Z]:\\(?:[a-zA-Z0-9_.-]+\\)*')
        
        # Extended Heuristics
        self.sid_pattern = re.compile(r'S-1-5-[0-9-]+')
        self.registry_pattern = re.compile(r'HK(?:LM|CU|U|CR|CC)\\[a-zA-Z0-9_.\\]+')
        self.unix_auth_pattern = re.compile(r'sudo:.*|auth.*|sshd\[\d+\]:.*')

        # Timestamp patterns for various formats
        # ISO, Windows, Syslog, Apache
        self.ts_patterns = [
            re.compile(r'\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}(?::?\d{2})?)?'), # ISO / RFC3339
            re.compile(r'[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}'), # Syslog
            re.compile(r'\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}'), # Apache/Common
            re.compile(r'\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}(?:\s+[AP]M)?') # US Windows
        ]

        self.critical_keywords = [
            'failed password', 'access denied', 'unauthorized', 'error',
            'exception', 'timeout', 'warning', 'critical', 'fatal', 
            'segfault', 'command execution', 'malware', 'backdoor',
            'exploit', 'injection', 'overflow', 'privilege escalation'
        ]

    def _extract_strings(self, binary_data: bytes) -> str:
        printable = set(bytes(string.printable, 'ascii'))
        result = []
        current_string = []
        for b in binary_data:
            if b in printable:
                current_string.append(chr(b))
            else:
                if len(current_string) >= 4:
                    result.append("".join(current_string))
                current_string = []
        if len(current_string) >= 4:
            result.append("".join(current_string))
        return "\n".join(result)

    def _parse_evtx(self, file_bytes: bytes) -> str:
        if not EVTX_AVAILABLE:
            return "EVTX parsing error: python-evtx library not installed on backend."
        tmp_fd, tmp_path = tempfile.mkstemp(suffix=".evtx")
        try:
            with open(tmp_fd, 'wb') as f:
                f.write(file_bytes)
            output = []
            with Evtx(tmp_path) as log:
                for record in log.records():
                    output.append(record.xml())
            return "\n".join(output)
        except Exception as e:
            return f"Failed to parse EVTX: {str(e)}\n\nFallback Strings:\n" + self._extract_strings(file_bytes)
        finally:
            os.remove(tmp_path)

    def _parse_pcap(self, file_bytes: bytes) -> str:
        if not SCAPY_AVAILABLE:
            return "PCAP parsing error: scapy library not installed on backend."
        tmp_fd, tmp_path = tempfile.mkstemp(suffix=".pcap")
        try:
            with open(tmp_fd, 'wb') as f:
                f.write(file_bytes)
            packets = scapy.rdpcap(tmp_path)
            output = [f"PCAP Analysis: {len(packets)} packets captured\n"]
            for i, pkt in enumerate(packets[:100]):
                output.append(f"[{i}] {pkt.summary()}")
            if len(packets) > 100:
                output.append(f"\n... and {len(packets) - 100} more packets.")
            return "\n".join(output)
        except Exception as e:
            return f"Failed to parse PCAP: {str(e)}\n\nFallback Strings:\n" + self._extract_strings(file_bytes)
        finally:
            os.remove(tmp_path)

    def _parse_archive(self, file_bytes: bytes) -> str:
        try:
            output = ["Archive Contents Summary:\n"]
            with tarfile.open(fileobj=io.BytesIO(file_bytes), mode="r:gz") as tar:
                members = tar.getmembers()
                for m in members[:50]:
                    output.append(f"{'DIR ' if m.isdir() else 'FILE'} {m.name} ({m.size} bytes)")
                if len(members) > 50:
                    output.append(f"\n... and {len(members) - 50} more entries.")
                for m in members:
                    if m.isfile() and (m.name.endswith('.log') or m.name.endswith('.txt')):
                        f = tar.extractfile(m)
                        if f:
                            peek = f.read(2048).decode('utf-8', errors='replace')
                            output.append(f"\n--- Preview of {m.name} ---\n{peek}...")
                        break
            return "\n".join(output)
        except Exception as e:
            return f"Failed to parse tar.gz: {str(e)}\n\nFallback Strings:\n" + self._extract_strings(file_bytes)

    def _parse_gzip(self, file_bytes: bytes) -> bytes:
        try:
            return gzip.decompress(file_bytes)
        except Exception:
            return file_bytes

    def _format_structured(self, filename: str, content: str) -> str:
        ext = filename.lower().split('.')[-1]
        try:
            if ext == 'json':
                return json.dumps(json.loads(content), indent=2)
            elif ext == 'xml':
                return xml.dom.minidom.parseString(content).toprettyxml(indent="  ")
            elif ext == 'csv':
                output = io.StringIO()
                reader = csv.reader(io.StringIO(content))
                writer = csv.writer(output, delimiter='|')
                for row in list(reader)[:100]:
                    writer.writerow(row)
                return output.getvalue()
        except Exception:
            pass
        return content

    def _extract_events(self, text: str) -> List[Dict]:
        """Parses raw text into discrete forensic events"""
        events = []
        lines = text.splitlines()
        
        current_event = None
        
        for line in lines[:1000]: # Safety limit
            stripped = line.strip()
            if not stripped: continue
            
            # Detect timestamp at the START of the line
            timestamp = "N/A"
            for pattern in self.ts_patterns:
                match = pattern.search(line[:50]) # Check beginning of line
                if match:
                    timestamp = match.group(0)
                    break
            
            # If we find a timestamp, it's a new event
            if timestamp != "N/A" or not current_event:
                if current_event:
                    events.append(current_event)
                
                # Cleanup description
                desc = stripped.replace(timestamp, "").strip()
                if not desc: desc = "Log Entry"
                
                # Severity Mapping
                level = "Low"
                lower_line = stripped.lower()
                if any(k in lower_line for k in ['fatal', 'critical', 'segfault', 'emergency']):
                    level = "Critical"
                elif any(k in lower_line for k in ['error', 'fail', 'exception', 'panic']):
                    level = "High"
                elif any(k in lower_line for k in ['warn', 'timeout', 'alert']):
                    level = "Medium"
                
                # Action Intelligence
                action = "Analyzed"
                if level == "Critical": action = "Immediate Quarantine Suggested"
                elif level == "High": action = "Flagged for Forensic Review"
                elif level == "Medium": action = "Auto-Logged (Heuristic Trigger)"
                
                current_event = {
                    "timestamp": timestamp,
                    "description": desc[:80] + ("..." if len(desc) > 80 else ""),
                    "details": stripped,
                    "level": level,
                    "action": action
                }
            else:
                # Add line to details of current event
                current_event["details"] += "\n" + stripped

        if current_event:
            events.append(current_event)
            
        return events

    def process_file(self, filename: str, content: bytes) -> dict:
        fname_lower = filename.lower()
        log_type = "Unknown"
        decoded_text = ""

        if fname_lower.endswith('.evtx'):
            log_type = "Windows Event Log (Binary)"
            decoded_text = self._parse_evtx(content)
        elif fname_lower.endswith(('.pcap', '.pcapng')):
            log_type = "Network Capture (PCAP)"
            decoded_text = self._parse_pcap(content)
        elif fname_lower.endswith('.tar.gz'):
            log_type = "Compressed Archive (TarGz)"
            decoded_text = self._parse_archive(content)
        elif fname_lower.endswith(('.evt', '.etl')):
            log_type = "Legacy Windows Log (Binary)"
            decoded_text = self._extract_strings(content)
        elif fname_lower.endswith('.gz') and not fname_lower.endswith('.tar.gz'):
            log_type = "Gzip Compressed Log"
            decompressed = self._parse_gzip(content)
            try:
                decoded_text = decompressed.decode('utf-8', errors='replace')
            except Exception:
                decoded_text = self._extract_strings(decompressed)
        else:
            is_binary = b'\x00' in content[:1024]
            if is_binary:
                log_type = "Binary Blob (Strings Carved)"
                decoded_text = self._extract_strings(content)
            else:
                log_type = "Plain Text / Structured Log"
                decoded_text = content.decode('utf-8', errors='replace')
                if fname_lower.endswith(('json', 'xml', 'csv')):
                    log_type = f"Structured Data ({fname_lower.split('.')[-1].upper()})"
                    decoded_text = self._format_structured(fname_lower, decoded_text)

        # 1. Run Heuristics
        ips = list(set(self.ipv4_pattern.findall(decoded_text)))
        emails = list(set(self.email_pattern.findall(decoded_text)))
        paths = list(set(self.path_pattern.findall(decoded_text)))[:50]
        sids = list(set(self.sid_pattern.findall(decoded_text)))[:20]
        registry = list(set(self.registry_pattern.findall(decoded_text)))[:20]
        
        triggered_keywords = {}
        lower_log = decoded_text.lower()
        for kw in self.critical_keywords:
            count = lower_log.count(kw)
            if count > 0:
                triggered_keywords[kw] = count

        # 2. Extract Event Timeline
        events = self._extract_events(decoded_text)

        return {
            "status": "success",
            "log_type": log_type,
            "decoded_text": decoded_text,
            "events": events or [],
            "heuristics": {
                "ips": ips or [],
                "emails": emails or [],
                "paths": paths or [],
                "sids": sids or [],
                "registry": registry or [],
                "critical_keywords": triggered_keywords or {},
                "total_lines": len(decoded_text.splitlines()),
                "file_size_bytes": len(content)
            }
        }
