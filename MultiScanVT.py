#!/usr/bin/env python3
"""
VTBatch - VirusTotal Batch File Scanner
A Python tkinter application for uploading multiple files to VirusTotal
and analyzing them for malware threats with rescan capabilities.

Requirements:
    pip install requests tkinter pillow
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import requests
import json
import hashlib
import time
import threading
import webbrowser
import os
import logging
from datetime import datetime
from typing import List, Dict, Optional, Tuple
import queue

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('virustotal_scanner.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class VirusTotalAPI:
    """VirusTotal API wrapper for file scanning and reporting."""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/vtapi/v2"
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'VirusTotal-Python-Scanner/1.0'})
        
    def scan_file(self, file_path: str) -> Dict:
        """Upload and scan a file."""
        url = f"{self.base_url}/file/scan"
        
        try:
            with open(file_path, 'rb') as file:
                files = {'file': (os.path.basename(file_path), file)}
                data = {'apikey': self.api_key}
                
                logger.info(f"Uploading file: {file_path}")
                response = self.session.post(url, files=files, data=data, timeout=300)
                response.raise_for_status()
                
                result = response.json()
                logger.info(f"Upload successful for {file_path}: {result.get('resource', 'Unknown')}")
                return result
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error uploading {file_path}: {e}")
            raise
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error uploading {file_path}: {e}")
            logger.debug(f"Response text: {response.text[:500] if 'response' in locals() else 'No response'}")
            raise Exception(f"Invalid JSON response: {str(e)}")
        except Exception as e:
            logger.error(f"Error uploading {file_path}: {e}")
            raise
    
    def get_report(self, resource: str) -> Dict:
        """Get scan report for a resource."""
        url = f"{self.base_url}/file/report"
        params = {'apikey': self.api_key, 'resource': resource}
        
        try:
            logger.info(f"Fetching report for resource: {resource}")
            response = self.session.get(url, params=params, timeout=30)
            response.raise_for_status()
            
            # Check if response is actually JSON
            content_type = response.headers.get('content-type', '').lower()
            if 'application/json' not in content_type:
                logger.warning(f"Unexpected content type: {content_type}")
                logger.debug(f"Response content: {response.text[:500]}")
                return {'error': f'Unexpected response format: {content_type}'}
            
            # Handle empty responses
            if not response.text.strip():
                logger.warning("Empty response received")
                return {'error': 'Empty response from VirusTotal'}
            
            result = response.json()
            logger.info(f"Report fetched for {resource}: Response code {result.get('response_code', 'Unknown')}")
            return result
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error fetching report for {resource}: {e}")
            raise
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error for {resource}: {e}")
            logger.debug(f"Response text: {response.text[:500]}")
            return {'error': f'Invalid JSON response: {str(e)}'}
        except Exception as e:
            logger.error(f"Error fetching report for {resource}: {e}")
            raise
    
    def rescan_file(self, resource: str) -> Dict:
        """Request a rescan of a file by hash/resource."""
        url = f"{self.base_url}/file/rescan"
        data = {'apikey': self.api_key, 'resource': resource}
        
        try:
            logger.info(f"Requesting rescan for resource: {resource}")
            response = self.session.post(url, data=data, timeout=30)
            response.raise_for_status()
            
            # Check if response is actually JSON
            content_type = response.headers.get('content-type', '').lower()
            if 'application/json' not in content_type:
                logger.warning(f"Unexpected content type: {content_type}")
                return {'error': f'Unexpected response format: {content_type}'}
            
            if not response.text.strip():
                logger.warning("Empty response received")
                return {'error': 'Empty response from VirusTotal'}
            
            result = response.json()
            logger.info(f"Rescan requested for {resource}: {result.get('response_code', 'Unknown')}")
            return result
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error requesting rescan for {resource}: {e}")
            raise
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error for rescan {resource}: {e}")
            logger.debug(f"Response text: {response.text[:500]}")
            return {'error': f'Invalid JSON response: {str(e)}'}
        except Exception as e:
            logger.error(f"Error requesting rescan for {resource}: {e}")
            raise

class FileScanner:
    """File scanner with threat analysis capabilities."""
    
    def __init__(self, api: VirusTotalAPI):
        self.api = api
        
    @staticmethod
    def calculate_file_hash(file_path: str) -> Tuple[str, str, str]:
        """Calculate MD5, SHA1, and SHA256 hashes of a file."""
        hash_md5 = hashlib.md5()
        hash_sha1 = hashlib.sha1()
        hash_sha256 = hashlib.sha256()
        
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
                    hash_sha1.update(chunk)
                    hash_sha256.update(chunk)
                    
            return hash_md5.hexdigest(), hash_sha1.hexdigest(), hash_sha256.hexdigest()
            
        except Exception as e:
            logger.error(f"Error calculating hashes for {file_path}: {e}")
            raise
    
    def analyze_results(self, report: Dict) -> Dict:
        """Analyze VirusTotal results and determine threat level."""
        analysis = {
            'threat_level': 'clean',
            'detections': 0,
            'total_scans': 0,
            'suspicious_vendors': [],
            'malware_types': set(),
            'is_suspicious': False
        }
        
        if report.get('response_code') != 1:
            analysis['threat_level'] = 'unknown'
            return analysis
            
        scans = report.get('scans', {})
        analysis['total_scans'] = len(scans)
        
        for vendor, result in scans.items():
            if result.get('detected'):
                analysis['detections'] += 1
                analysis['suspicious_vendors'].append(vendor)
                
                # Extract malware type from result
                malware_result = result.get('result', '').lower()
                if malware_result:
                    analysis['malware_types'].add(malware_result)
        
        # Determine threat level
        detection_rate = analysis['detections'] / max(analysis['total_scans'], 1)
        
        if analysis['detections'] == 0:
            analysis['threat_level'] = 'clean'
        elif analysis['detections'] == 1:
            analysis['threat_level'] = 'suspicious'
            analysis['is_suspicious'] = True
        elif detection_rate < 0.1:  # Less than 10%
            analysis['threat_level'] = 'low_risk'
            analysis['is_suspicious'] = True
        elif detection_rate < 0.3:  # Less than 30%
            analysis['threat_level'] = 'medium_risk'
            analysis['is_suspicious'] = True
        else:
            analysis['threat_level'] = 'high_risk'
            analysis['is_suspicious'] = True
            
        logger.info(f"Analysis complete: {analysis['detections']}/{analysis['total_scans']} detections, threat level: {analysis['threat_level']}")
        return analysis

class VirusTotalGUI:
    """Main GUI application for VirusTotal batch scanner."""
    
    def __init__(self, root):
        self.root = root
        self.root.title("VTBatch - VirusTotal Scanner v1.1")
        self.root.geometry("1000x700")
        self.root.minsize(800, 600)
        
        # Application state
        self.api = None
        self.files_to_scan = []
        self.scan_results = {}
        self.is_scanning = False
        self.scan_thread = None
        self.message_queue = queue.Queue()
        
        self.setup_gui()
        self.setup_logging()
        
        # Start message processor
        self.process_messages()
        
        logger.info("VTBatch GUI initialized")
    
    def setup_gui(self):
        """Setup the GUI components."""
        # Create main notebook for tabs
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Scanner tab
        self.scanner_frame = ttk.Frame(notebook)
        notebook.add(self.scanner_frame, text="Scanner")
        self.setup_scanner_tab()
        
        # Results tab
        self.results_frame = ttk.Frame(notebook)
        notebook.add(self.results_frame, text="Results")
        self.setup_results_tab()
        
        # Logs tab
        self.logs_frame = ttk.Frame(notebook)
        notebook.add(self.logs_frame, text="Debug Logs")
        self.setup_logs_tab()
    
    def setup_scanner_tab(self):
        """Setup the main scanner interface."""
        # API Key section
        api_frame = ttk.LabelFrame(self.scanner_frame, text="API Configuration", padding="10")
        api_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(api_frame, text="VirusTotal API Key:").pack(anchor=tk.W)
        self.api_key_var = tk.StringVar()
        self.api_key_entry = ttk.Entry(api_frame, textvariable=self.api_key_var, show="*", width=50)
        self.api_key_entry.pack(fill=tk.X, pady=5)
        
        ttk.Button(api_frame, text="Test API Key", command=self.test_api_key).pack(anchor=tk.W)
        
        # File selection section
        files_frame = ttk.LabelFrame(self.scanner_frame, text="File Selection", padding="10")
        files_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        button_frame = ttk.Frame(files_frame)
        button_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(button_frame, text="Select Files", command=self.select_files).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="Clear List", command=self.clear_files).pack(side=tk.LEFT)
        
        # Files listbox with scrollbar
        list_frame = ttk.Frame(files_frame)
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        self.files_listbox = tk.Listbox(list_frame)
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.files_listbox.yview)
        self.files_listbox.configure(yscrollcommand=scrollbar.set)
        
        self.files_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Control buttons
        control_frame = ttk.Frame(self.scanner_frame)
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.scan_button = ttk.Button(control_frame, text="Start Scan", command=self.start_scan)
        self.scan_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.stop_button = ttk.Button(control_frame, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(control_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=(10, 0))
        
        # Status label
        self.status_var = tk.StringVar(value="Ready")
        status_label = ttk.Label(self.scanner_frame, textvariable=self.status_var)
        status_label.pack(fill=tk.X, padx=10, pady=5)
    
    def setup_results_tab(self):
        """Setup the results display tab."""
        # Results treeview
        columns = ('File', 'Status', 'Detections', 'Threat Level', 'Hash')
        self.results_tree = ttk.Treeview(self.results_frame, columns=columns, show='headings', height=15)
        
        # Configure columns
        self.results_tree.heading('File', text='File Name')
        self.results_tree.heading('Status', text='Status')
        self.results_tree.heading('Detections', text='Detections')
        self.results_tree.heading('Threat Level', text='Threat Level')
        self.results_tree.heading('Hash', text='SHA256')
        
        self.results_tree.column('File', width=200)
        self.results_tree.column('Status', width=100)
        self.results_tree.column('Detections', width=100)
        self.results_tree.column('Threat Level', width=120)
        self.results_tree.column('Hash', width=300)
        
        # Add scrollbar to treeview
        tree_scrollbar = ttk.Scrollbar(self.results_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=tree_scrollbar.set)
        
        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0), pady=10)
        tree_scrollbar.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 10), pady=10)
        
        # Double-click to open in browser
        self.results_tree.bind('<Double-1>', self.open_in_virustotal)
        
        # Results action buttons
        results_button_frame = ttk.Frame(self.results_frame)
        results_button_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(results_button_frame, text="Open in VirusTotal", command=self.open_selected_in_vt).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(results_button_frame, text="Rescan Selected", command=self.rescan_selected_file).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(results_button_frame, text="Export Results", command=self.export_results).pack(side=tk.LEFT)
    
    def setup_logs_tab(self):
        """Setup the debug logs tab."""
        # Log display
        self.log_text = scrolledtext.ScrolledText(self.logs_frame, height=20, width=100)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Log controls
        log_control_frame = ttk.Frame(self.logs_frame)
        log_control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(log_control_frame, text="Clear Logs", command=self.clear_logs).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(log_control_frame, text="Save Logs", command=self.save_logs).pack(side=tk.LEFT)
        
        # Auto-scroll checkbox
        self.auto_scroll_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(log_control_frame, text="Auto-scroll", variable=self.auto_scroll_var).pack(side=tk.RIGHT)
    
    def setup_logging(self):
        """Setup logging to display in GUI."""
        class GUILogHandler(logging.Handler):
            def __init__(self, message_queue):
                super().__init__()
                self.message_queue = message_queue
                
            def emit(self, record):
                msg = self.format(record)
                self.message_queue.put(('log', msg))
        
        gui_handler = GUILogHandler(self.message_queue)
        gui_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logger.addHandler(gui_handler)
    
    def process_messages(self):
        """Process messages from background threads."""
        try:
            while True:
                msg_type, msg_data = self.message_queue.get_nowait()
                
                if msg_type == 'log':
                    self.log_text.insert(tk.END, msg_data + '\n')
                    if self.auto_scroll_var.get():
                        self.log_text.see(tk.END)
                elif msg_type == 'status':
                    self.status_var.set(msg_data)
                elif msg_type == 'progress':
                    self.progress_var.set(msg_data)
                elif msg_type == 'result':
                    self.update_results_display(msg_data)
                elif msg_type == 'scan_complete':
                    self.scan_completed()
                elif msg_type == 'threat_warning':
                    self.show_threat_warning(msg_data)
                elif msg_type == 'rescan_complete':
                    self.rescan_completed(msg_data)
                elif msg_type == 'error':
                    messagebox.showerror("Error", msg_data)
                    
        except queue.Empty:
            pass
        
        # Schedule next check
        self.root.after(100, self.process_messages)
    
    def test_api_key(self):
        """Test the API key validity."""
        api_key = self.api_key_var.get().strip()
        if not api_key:
            messagebox.showerror("Error", "Please enter an API key")
            return
            
        try:
            # Test with a known hash (EICAR test file)
            test_api = VirusTotalAPI(api_key)
            result = test_api.get_report("44d88612fea8a8f36de82e1278abb02f")  # EICAR MD5
            
            if 'error' in result:
                messagebox.showerror("API Error", f"API Error: {result['error']}")
            else:
                messagebox.showinfo("Success", "API key is valid!")
                self.api = test_api
                logger.info("API key validated successfully")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to validate API key: {e}")
            logger.error(f"API key validation failed: {e}")
    
    def select_files(self):
        """Open file dialog to select files for scanning."""
        file_paths = filedialog.askopenfilenames(
            title="Select files to scan",
            filetypes=[("All files", "*.*")]
        )
        
        for file_path in file_paths:
            if file_path not in self.files_to_scan:
                self.files_to_scan.append(file_path)
                self.files_listbox.insert(tk.END, os.path.basename(file_path))
                
        logger.info(f"Selected {len(file_paths)} files for scanning")
    
    def clear_files(self):
        """Clear the files list."""
        self.files_to_scan.clear()
        self.files_listbox.delete(0, tk.END)
        self.scan_results.clear()
        
        # Clear results tree
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
            
        logger.info("Cleared files list and results")
    
    def start_scan(self):
        """Start the scanning process."""
        if not self.api:
            messagebox.showerror("Error", "Please test and validate your API key first")
            return
            
        if not self.files_to_scan:
            messagebox.showerror("Error", "Please select files to scan")
            return
            
        if self.is_scanning:
            messagebox.showwarning("Warning", "Scan already in progress")
            return
            
        self.is_scanning = True
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        
        # Start scanning in background thread
        self.scan_thread = threading.Thread(target=self.scan_files_thread, daemon=True)
        self.scan_thread.start()
        
        logger.info(f"Started scanning {len(self.files_to_scan)} files")
    
    def stop_scan(self):
        """Stop the scanning process."""
        self.is_scanning = False
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.message_queue.put(('status', 'Scan stopped by user'))
        logger.info("Scan stopped by user")
    
    def scan_files_thread(self):
        """Background thread for scanning files."""
        scanner = FileScanner(self.api)
        total_files = len(self.files_to_scan)
        
        try:
            for i, file_path in enumerate(self.files_to_scan):
                if not self.is_scanning:
                    break
                    
                self.message_queue.put(('status', f'Scanning {os.path.basename(file_path)}...'))
                self.message_queue.put(('progress', (i / total_files) * 100))
                
                try:
                    # Calculate file hashes
                    md5, sha1, sha256 = scanner.calculate_file_hash(file_path)
                    
                    # Upload file
                    upload_result = self.api.scan_file(file_path)
                    resource = upload_result.get('resource', sha256)
                    
                    # Wait for analysis (VirusTotal needs time to process)
                    time.sleep(10)  # Wait before checking report
                    
                    # Get report with retry logic
                    max_retries = 3
                    report = None
                    for retry in range(max_retries):
                        try:
                            report = self.api.get_report(resource)
                            if 'error' not in report:
                                break
                            else:
                                logger.warning(f"Report error (attempt {retry + 1}): {report.get('error')}")
                                if retry < max_retries - 1:
                                    time.sleep(5)  # Wait before retry
                        except Exception as e:
                            logger.error(f"Report fetch attempt {retry + 1} failed: {e}")
                            if retry < max_retries - 1:
                                time.sleep(5)
                            else:
                                report = {'error': f'Failed after {max_retries} attempts: {str(e)}'}
                    
                    # Handle report errors
                    if report and 'error' in report:
                        error_result = {
                            'file_path': file_path,
                            'filename': os.path.basename(file_path),
                            'error': f"Report error: {report['error']}"
                        }
                        self.message_queue.put(('result', error_result))
                        continue
                    
                    # Analyze results
                    analysis = scanner.analyze_results(report)
                    
                    # Store results
                    result_data = {
                        'file_path': file_path,
                        'filename': os.path.basename(file_path),
                        'md5': md5,
                        'sha1': sha1,
                        'sha256': sha256,
                        'resource': resource,
                        'report': report,
                        'analysis': analysis
                    }
                    
                    self.scan_results[file_path] = result_data
                    self.message_queue.put(('result', result_data))
                    
                    # Check for threats
                    if analysis['is_suspicious'] and analysis['detections'] > 1:
                        self.message_queue.put(('threat_warning', result_data))
                    
                    # Rate limiting - 4 requests per minute for free accounts
                    if i < total_files - 1:
                        time.sleep(15)  # 15 seconds between scans
                        
                except Exception as e:
                    logger.error(f"Error scanning {file_path}: {e}")
                    error_result = {
                        'file_path': file_path,
                        'filename': os.path.basename(file_path),
                        'error': str(e)
                    }
                    self.message_queue.put(('result', error_result))
            
            self.message_queue.put(('progress', 100))
            self.message_queue.put(('scan_complete', None))
            
        except Exception as e:
            logger.error(f"Scanning thread error: {e}")
            self.message_queue.put(('status', f'Scan error: {e}'))
        
    def update_results_display(self, result_data):
        """Update the results tree with scan results."""
        filename = result_data.get('filename', 'Unknown')
        
        if 'error' in result_data:
            # Error case
            self.results_tree.insert('', tk.END, values=(
                filename,
                'Error',
                '-',
                'Error',
                result_data['error']
            ))
        else:
            analysis = result_data.get('analysis', {})
            detections = f"{analysis.get('detections', 0)}/{analysis.get('total_scans', 0)}"
            threat_level = analysis.get('threat_level', 'Unknown').replace('_', ' ').title()
            
            # Color code threat levels
            item_id = self.results_tree.insert('', tk.END, values=(
                filename,
                'Complete',
                detections,
                threat_level,
                result_data.get('sha256', 'Unknown')
            ))
            
            # Apply color coding
            if analysis.get('threat_level') in ['high_risk', 'medium_risk']:
                self.results_tree.set(item_id, 'Threat Level', f"⚠️ {threat_level}")
            elif analysis.get('threat_level') == 'suspicious':
                self.results_tree.set(item_id, 'Threat Level', f"⚡ {threat_level}")
            elif analysis.get('threat_level') == 'clean':
                self.results_tree.set(item_id, 'Threat Level', f"✅ {threat_level}")
    
    def show_threat_warning(self, result_data):
        """Show warning dialog for detected threats."""
        analysis = result_data['analysis']
        filename = result_data['filename']
        detections = analysis['detections']
        
        warning_msg = f"⚠️ THREAT DETECTED ⚠️\n\n"
        warning_msg += f"File: {filename}\n"
        warning_msg += f"Detections: {detections}/{analysis['total_scans']} engines\n"
        warning_msg += f"Threat Level: {analysis['threat_level'].replace('_', ' ').title()}\n\n"
        
        if analysis['malware_types']:
            warning_msg += f"Malware Types: {', '.join(list(analysis['malware_types'])[:3])}\n\n"
        
        warning_msg += "Would you like to view the full report on VirusTotal?"
        
        result = messagebox.askyesno("Threat Detected", warning_msg, icon='warning')
        if result:
            self.open_virustotal_report(result_data['sha256'])
    
    def scan_completed(self):
        """Handle scan completion."""
        self.is_scanning = False
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.message_queue.put(('status', 'Scan completed'))
        
        # Show summary
        total_scanned = len([r for r in self.scan_results.values() if 'analysis' in r])
        total_threats = len([r for r in self.scan_results.values() 
                           if 'analysis' in r and r['analysis'].get('is_suspicious')])
        
        summary_msg = f"Scan completed!\n\n"
        summary_msg += f"Files scanned: {total_scanned}\n"
        summary_msg += f"Threats detected: {total_threats}\n"
        
        if total_threats > 0:
            summary_msg += f"\n⚠️ {total_threats} potentially suspicious files found!"
            
        messagebox.showinfo("Scan Complete", summary_msg)
        logger.info(f"Scan completed: {total_scanned} files scanned, {total_threats} threats detected")
    
    def open_in_virustotal(self, event):
        """Open selected result in VirusTotal (double-click handler)."""
        selection = self.results_tree.selection()
        if selection:
            item = selection[0]
            sha256 = self.results_tree.item(item)['values'][4]
            if sha256 and sha256 != 'Unknown':
                self.open_virustotal_report(sha256)
    
    def open_selected_in_vt(self):
        """Open selected result in VirusTotal (button handler)."""
        selection = self.results_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a file from the results")
            return
            
        item = selection[0]
        sha256 = self.results_tree.item(item)['values'][4]
        if sha256 and sha256 != 'Unknown':
            self.open_virustotal_report(sha256)
        else:
            messagebox.showerror("Error", "No hash available for this file")
    
    def rescan_selected_file(self):
        """Rescan the selected file in the results."""
        selection = self.results_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a file from the results to rescan")
            return
        
        if not self.api:
            messagebox.showerror("Error", "Please validate your API key first")
            return
            
        item = selection[0]
        values = self.results_tree.item(item)['values']
        filename = values[0]
        sha256 = values[4]
        
        if not sha256 or sha256 == 'Unknown':
            messagebox.showerror("Error", "No hash available for this file - cannot rescan")
            return
            
        # Find the original file data
        file_data = None
        for path, result in self.scan_results.items():
            if result.get('filename') == filename:
                file_data = result
                break
                
        if not file_data:
            messagebox.showerror("Error", "Could not find original scan data for this file")
            return
            
        # Confirm rescan
        confirm = messagebox.askyesno(
            "Confirm Rescan", 
            f"Request a fresh scan of '{filename}' from VirusTotal?\n\n"
            f"This will queue the file for re-analysis by all antivirus engines."
        )
        
        if not confirm:
            return
            
        # Start rescan in background thread
        rescan_thread = threading.Thread(
            target=self.rescan_file_thread, 
            args=(file_data, item), 
            daemon=True
        )
        rescan_thread.start()
        
        # Update UI to show rescanning
        self.results_tree.set(item, 'Status', 'Rescanning...')
        logger.info(f"Started rescan for {filename}")
    
    def rescan_file_thread(self, file_data, tree_item):
        """Background thread for rescanning a single file."""
        try:
            filename = file_data['filename']
            resource = file_data.get('resource', file_data.get('sha256'))
            
            self.message_queue.put(('status', f'Requesting rescan of {filename}...'))
            
            # Request rescan
            rescan_result = self.api.rescan_file(resource)
            
            if 'error' in rescan_result:
                self.message_queue.put(('error', f"Rescan request failed: {rescan_result['error']}"))
                self.message_queue.put(('rescan_complete', {'item': tree_item, 'status': 'Error', 'error': True}))
                return
            
            # Wait longer for rescan to complete
            self.message_queue.put(('status', f'Waiting for {filename} rescan to complete...'))
            time.sleep(30)  # Wait 30 seconds for rescan to process
            
            # Fetch updated report
            max_attempts = 5
            updated_report = None
            
            for attempt in range(max_attempts):
                try:
                    updated_report = self.api.get_report(resource)
                    
                    if 'error' not in updated_report and updated_report.get('response_code') == 1:
                        # Check if scan_date is recent (within last hour)
                        scan_date = updated_report.get('scan_date', '')
                        if scan_date:
                            try:
                                from datetime import datetime, timedelta
                                scan_time = datetime.strptime(scan_date, '%Y-%m-%d %H:%M:%S')
                                if datetime.now() - scan_time < timedelta(hours=1):
                                    break  # Recent scan found
                            except:
                                pass  # Continue if date parsing fails
                    
                    # Wait before next attempt
                    if attempt < max_attempts - 1:
                        time.sleep(20)  # Wait 20 seconds between attempts
                        
                except Exception as e:
                    logger.error(f"Error fetching updated report (attempt {attempt + 1}): {e}")
                    if attempt < max_attempts - 1:
                        time.sleep(20)
            
            if not updated_report or 'error' in updated_report:
                error_msg = updated_report.get('error', 'Unknown error') if updated_report else 'No response'
                self.message_queue.put(('error', f"Failed to get updated report: {error_msg}"))
                self.message_queue.put(('rescan_complete', {'item': tree_item, 'status': 'Error', 'error': True}))
                return
            
            # Analyze new results
            scanner = FileScanner(self.api)
            new_analysis = scanner.analyze_results(updated_report)
            
            # Update stored results
            file_data['report'] = updated_report
            file_data['analysis'] = new_analysis
            
            # Prepare update data
            update_data = {
                'item': tree_item,
                'filename': filename,
                'analysis': new_analysis,
                'sha256': file_data.get('sha256'),
                'status': 'Complete',
                'error': False
            }
            
            self.message_queue.put(('rescan_complete', update_data))
            
            # Check for new threats
            if new_analysis['is_suspicious'] and new_analysis['detections'] > 1:
                self.message_queue.put(('threat_warning', file_data))
            
            logger.info(f"Rescan completed for {filename}: {new_analysis['detections']}/{new_analysis['total_scans']} detections")
            
        except Exception as e:
            logger.error(f"Rescan thread error: {e}")
            self.message_queue.put(('error', f"Rescan failed: {str(e)}"))
            self.message_queue.put(('rescan_complete', {'item': tree_item, 'status': 'Error', 'error': True}))
    
    def rescan_completed(self, update_data):
        """Handle rescan completion and update display."""
        item = update_data['item']
        
        if update_data['error']:
            self.results_tree.set(item, 'Status', 'Error')
            return
            
        analysis = update_data['analysis']
        filename = update_data['filename']
        
        # Update tree values
        detections = f"{analysis['detections']}/{analysis['total_scans']}"
        threat_level = analysis['threat_level'].replace('_', ' ').title()
        
        self.results_tree.set(item, 'Status', 'Complete')
        self.results_tree.set(item, 'Detections', detections)
        
        # Apply color coding
        if analysis['threat_level'] in ['high_risk', 'medium_risk']:
            self.results_tree.set(item, 'Threat Level', f"⚠️ {threat_level}")
        elif analysis['threat_level'] == 'suspicious':
            self.results_tree.set(item, 'Threat Level', f"⚡ {threat_level}")
        elif analysis['threat_level'] == 'clean':
            self.results_tree.set(item, 'Threat Level', f"✅ {threat_level}")
        else:
            self.results_tree.set(item, 'Threat Level', threat_level)
            
        self.message_queue.put(('status', f'Rescan completed for {filename}'))
        
        # Show notification
        messagebox.showinfo(
            "Rescan Complete", 
            f"Rescan completed for '{filename}'\n\n"
            f"New results: {detections} detections\n"
            f"Threat level: {threat_level}"
        )
        """Open VirusTotal report in web browser."""
        url = f"https://www.virustotal.com/gui/file/{sha256}"
        try:
            webbrowser.open(url)
            logger.info(f"Opened VirusTotal report: {url}")
        except Exception as e:
            logger.error(f"Failed to open browser: {e}")
            messagebox.showerror("Error", f"Failed to open browser: {e}")
    
    def export_results(self):
        """Export scan results to JSON file."""
        if not self.scan_results:
            messagebox.showwarning("Warning", "No results to export")
            return
            
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                # Prepare export data
                export_data = {
                    'scan_date': datetime.now().isoformat(),
                    'total_files': len(self.scan_results),
                    'results': []
                }
                
                for file_path, result in self.scan_results.items():
                    if 'analysis' in result:
                        export_item = {
                            'filename': result['filename'],
                            'file_path': result['file_path'],
                            'sha256': result['sha256'],
                            'detections': result['analysis']['detections'],
                            'total_scans': result['analysis']['total_scans'],
                            'threat_level': result['analysis']['threat_level'],
                            'suspicious_vendors': result['analysis']['suspicious_vendors'],
                            'malware_types': list(result['analysis']['malware_types'])
                        }
                        export_data['results'].append(export_item)
                
                with open(file_path, 'w') as f:
                    json.dump(export_data, f, indent=2)
                    
                messagebox.showinfo("Success", f"Results exported to {file_path}")
                logger.info(f"Results exported to {file_path}")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export results: {e}")
                logger.error(f"Export failed: {e}")
    
    def clear_logs(self):
        """Clear the debug logs display."""
        self.log_text.delete(1.0, tk.END)
    
    def save_logs(self):
        """Save debug logs to file."""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(self.log_text.get(1.0, tk.END))
                messagebox.showinfo("Success", f"Logs saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save logs: {e}")

def main():
    """Main application entry point."""
    root = tk.Tk()
    app = VirusTotalGUI(root)
    
    try:
        root.mainloop()
    except KeyboardInterrupt:
        logger.info("Application terminated by user")
    except Exception as e:
        logger.error(f"Application error: {e}")
        messagebox.showerror("Fatal Error", f"Application error: {e}")

if __name__ == "__main__":
    main()