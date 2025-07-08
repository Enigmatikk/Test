#!/usr/bin/env python3
# YARA Testing Framework
# A lightweight framework for testing YARA rules against files and directories

import os
import sys
import argparse
import json
import time
import yara
import glob
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


class YaraTestFramework:
    """A framework for testing YARA rules against files and directories."""

    def __init__(self, rules_path=None, target_path=None, recursive=True, threads=4, 
                 output_format="text", output_file=None, timeout=30):
        self.rules_path = rules_path
        self.target_path = target_path
        self.recursive = recursive
        self.threads = threads
        self.output_format = output_format
        self.output_file = output_file
        self.timeout = timeout
        self.rules = None
        self.results = []

    def compile_rules(self):
        """Compile YARA rules from file or directory."""
        try:
            if os.path.isdir(self.rules_path):
                # Compile rules from directory
                rule_files = {}
                for file_path in glob.glob(os.path.join(self.rules_path, "*.yar")) + \
                               glob.glob(os.path.join(self.rules_path, "*.yara")):
                    rule_name = os.path.basename(file_path).split('.')[0]
                    with open(file_path, 'r') as f:
                        rule_files[rule_name] = f.read()
                
                if not rule_files:
                    print(f"[!] No YARA rule files found in {self.rules_path}")
                    return False
                
                self.rules = yara.compile(sources=rule_files)
            else:
                # Compile rules from single file
                self.rules = yara.compile(filepath=self.rules_path)
            
            return True
        except Exception as e:
            print(f"[!] Error compiling rules: {e}")
            return False

    def get_files_to_scan(self):
        """Get list of files to scan based on target path."""
        files_to_scan = []
        
        if os.path.isfile(self.target_path):
            files_to_scan.append(self.target_path)
        elif os.path.isdir(self.target_path):
            if self.recursive:
                # Recursively walk through directory
                for root, _, files in os.walk(self.target_path):
                    for file in files:
                        files_to_scan.append(os.path.join(root, file))
            else:
                # Only include files in the top directory
                files_to_scan.extend([os.path.join(self.target_path, f) for f in os.listdir(self.target_path) 
                                    if os.path.isfile(os.path.join(self.target_path, f))])
        else:
            print(f"[!] Target path not found: {self.target_path}")
        
        return files_to_scan

    def scan_file(self, file_path):
        """Scan a single file with compiled YARA rules."""
        try:
            start_time = time.time()
            matches = self.rules.match(file_path, timeout=self.timeout)
            scan_time = time.time() - start_time
            
            return {
                "file": file_path,
                "size": os.path.getsize(file_path),
                "scan_time": scan_time,
                "matches": [
                    {
                        "rule": match.rule,
                        "namespace": match.namespace,
                        "tags": match.tags,
                        "meta": match.meta,
                        "strings": [{"name": s[0], "offset": s[1], "data": s[2].hex()} for s in match.strings]
                    } for match in matches
                ]
            }
        except Exception as e:
            return {
                "file": file_path,
                "error": str(e)
            }

    def scan_files(self):
        """Scan files using thread pool for parallel processing."""
        files_to_scan = self.get_files_to_scan()
        
        if not files_to_scan:
            print("[!] No files to scan")
            return
        
        print(f"[*] Scanning {len(files_to_scan)} files with {self.threads} threads")
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            self.results = list(executor.map(self.scan_file, files_to_scan))
        
        total_time = time.time() - start_time
        print(f"[*] Scan completed in {total_time:.2f} seconds")

    def output_results(self):
        """Output scan results in specified format."""
        if not self.results:
            print("[!] No results to output")
            return
        
        # Count matches
        total_files = len(self.results)
        files_with_matches = sum(1 for r in self.results if "matches" in r and r["matches"])
        total_matches = sum(len(r.get("matches", [])) for r in self.results)
        
        output = None
        
        if self.output_format == "json":
            output = json.dumps({
                "scan_summary": {
                    "timestamp": datetime.now().isoformat(),
                    "rules_path": self.rules_path,
                    "target_path": self.target_path,
                    "total_files": total_files,
                    "files_with_matches": files_with_matches,
                    "total_matches": total_matches
                },
                "results": self.results
            }, indent=2)
        elif self.output_format == "text":
            output = f"""
=== YARA Test Framework Results ===
Timestamp: {datetime.now().isoformat()}
Rules: {self.rules_path}
Target: {self.target_path}
Files Scanned: {total_files}
Files with Matches: {files_with_matches}
Total Matches: {total_matches}

=== Detailed Results ===
"""
            for result in self.results:
                if "error" in result:
                    output += f"\nERROR scanning {result['file']}: {result['error']}\n"
                    continue
                
                if not result.get("matches"):
                    continue
                
                output += f"\nFile: {result['file']} ({result['size']} bytes)\n"
                output += f"Scan time: {result['scan_time']:.4f} seconds\n"
                output += f"Matches: {len(result['matches'])}\n"
                
                for match in result["matches"]:
                    output += f"  - Rule: {match['rule']}\n"
                    if match["tags"]:
                        output += f"    Tags: {', '.join(match['tags'])}\n"
                    if match["meta"]:
                        output += f"    Meta: {match['meta']}\n"
                    if match["strings"]:
                        output += f"    String matches: {len(match['strings'])}\n"
        
        if output:
            if self.output_file:
                with open(self.output_file, "w") as f:
                    f.write(output)
                print(f"[*] Results written to {self.output_file}")
            else:
                print(output)


def main():
    parser = argparse.ArgumentParser(description="YARA Testing Framework")
    parser.add_argument("rules", help="Path to YARA rule file or directory")
    parser.add_argument("target", help="Path to file or directory to scan")
    parser.add_argument("-r", "--recursive", action="store_true", help="Scan directories recursively")
    parser.add_argument("-t", "--threads", type=int, default=4, help="Number of threads for scanning")
    parser.add_argument("-f", "--format", choices=["text", "json"], default="text", help="Output format")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout for rule matching in seconds")
    
    args = parser.parse_args()
    
    framework = YaraTestFramework(
        rules_path=args.rules,
        target_path=args.target,
        recursive=args.recursive,
        threads=args.threads,
        output_format=args.format,
        output_file=args.output,
        timeout=args.timeout
    )
    
    if framework.compile_rules():
        framework.scan_files()
        framework.output_results()
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()