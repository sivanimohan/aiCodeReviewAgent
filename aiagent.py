#!/usr/bin/env python3
import os
import sys
import ast
import shutil
import tempfile
import zipfile
import tarfile
import platform
import json
import re
import hashlib
import warnings
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
import threading
import sqlite3
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import pycodestyle
except ImportError:
    pycodestyle = None
try:
    import autopep8
except ImportError:
    autopep8 = None
try:
    import psutil
except ImportError:
    psutil = None
try:
    import git
except ImportError:
    git = None
try:
    from flask import Flask, jsonify, request
    from werkzeug.utils import secure_filename
except ImportError:
    Flask = None

SUPPORTED_LANGUAGES = {
    'python': ['.py'],
    'javascript': ['.js', '.jsx'],
    'java': ['.java'],
    'go': ['.go']
}

DEFAULT_CONFIG = {
    "general": {
        "max_size_mb": 1024,
        "parallel_processing": True,
        "worker_threads": os.cpu_count() or 4,
        "web_interface": False,
        "web_host": "127.0.0.1",
        "web_port": 5000,
        "data_retention": False,
    },
    "input": {
        "formats": ["folder", "zip", "git"],
        "exclude": ["__pycache__", "node_modules", ".git", ".idea", "venv", "target", "build"],
        "git_branch": "main"
    },
    "analysis": {
        "priorities": ["security", "performance", "readability"],
        "thresholds": {
            "complexity": 10,
            "performance": 5,
            "security": "medium"
        }
    },
    "style": {
        "python": {
            "max_line_length": 79,
            "ignore": ["E501", "W605", "S602"],
        },
        "javascript": {
            "max_line_length": 100
        },
        "java": {
            "max_line_length": 120
        },
        "go": {
            "max_line_length": 100
        }
    },
    "output": {
        "formats": ["json", "markdown", "html"],
        "include_original": False,
        "comparison_view": True
    },
    "security": {
        "level": "medium",
        "tools": {"python": "regex", "javascript": "regex", "java": "regex", "go": "regex"}
    }
}

def run_command(cmd, cwd=None):
    import subprocess
    try:
        r = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True, text=True, timeout=120)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except Exception as e:
        return -1, '', str(e)

class AIReviewLogger:
    def __init__(self, log_file: Path):
        self.log_file = log_file
        self.lock = threading.Lock()

    def log(self, message: str):
        timestamp = datetime.now().isoformat()
        with self.lock:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(f"{timestamp} | {message}\n")

class AICodeReviewAgent:
    def __init__(self, input_path: str, output_path: str, config_path: Optional[str] = None):
        self.input_path = Path(input_path)
        self.output_path = Path(output_path)
        self.temp_dir = Path(tempfile.mkdtemp())
        self.config = self.load_config(config_path)
        self.log = AIReviewLogger(self.output_path / "agent.log")
        self.changes_db = self.output_path / 'changes.db'
        self._init_db()
        self.max_threads = min(self.config["general"]["worker_threads"], os.cpu_count() or 2)
        if self.max_threads <= 1:
            self.max_threads = 2
        self.language_handlers = self.build_language_handlers()
        self.report: Dict[str, Any] = self.init_report()
        if self.config["general"].get("web_interface", False) and Flask:
            self.app = Flask(__name__)
            self._setup_api_endpoints()
        elif self.config["general"].get("web_interface", False):
            warnings.warn("Flask not installed; web interface disabled.")

    def build_language_handlers(self):
        return {
            '.py': {
                'language': 'python',
                'analyzer': self.analyze_python_file,
                'improver': self.improve_python_file,
                'formatter': self.format_python_file,
                'security': self.scan_python_security,
                'dependencies': self.analyze_python_dependencies,
                'test': self.run_python_tests
            },
            '.js': {
                'language': 'javascript',
                'analyzer': self.analyze_js_file,
                'improver': self.improve_js_file,
                'formatter': self.format_js_file,
                'security': self.scan_js_security,
                'dependencies': self.analyze_js_dependencies,
                'test': self.run_js_tests
            },
            '.java': {
                'language': 'java',
                'analyzer': self.analyze_java_file,
                'improver': self.improve_java_file,
                'formatter': self.format_java_file,
                'security': self.scan_java_security,
                'dependencies': self.analyze_java_dependencies,
                'test': self.run_java_tests
            },
            '.go': {
                'language': 'go',
                'analyzer': self.analyze_go_file,
                'improver': self.improve_go_file,
                'formatter': self.format_go_file,
                'security': self.scan_go_security,
                'dependencies': self.analyze_go_dependencies,
                'test': self.run_go_tests
            }
        }

    def load_config(self, config_path: Optional[str]) -> Dict:
        config = dict(DEFAULT_CONFIG)
        if config_path and os.path.exists(config_path):
            with open(config_path, "r", encoding="utf-8") as f:
                user_config = json.load(f)
                config = self.deep_merge(config, user_config)
        return config

    def deep_merge(self, base: Dict, update: Dict) -> Dict:
        for key, value in update.items():
            if isinstance(value, dict) and key in base:
                base[key] = self.deep_merge(base[key], value)
            else:
                base[key] = value
        return base

    def init_report(self) -> Dict:
        return {
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "input_path": str(self.input_path),
                "output_path": str(self.output_path),
                "version": "1.0.0",
                "config": self.config,
            },
            "metrics": {
                "files_processed": 0,
                "files_improved": 0,
                "issues_found": 0,
                "security_issues": 0,
                "performance_issues": 0,
                "style_violations": 0,
                "escape_sequence_fixes": 0,
                "input_noqa_additions": 0,
                "complexity_score": 0,
                "tests_before": {},
                "tests_after": {}
            },
            "files": [],
            "dependencies": {},
            "security": {},
            "performance": {},
            "structure": {},
            "build_tools": [],
            "changes": [],
            "diffs": [],
            "system_info": self.get_system_info()
        }

    def _init_db(self):
        conn = sqlite3.connect(self.changes_db)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS changes (
                id INTEGER PRIMARY KEY,
                file_path TEXT,
                change_type TEXT,
                original_hash TEXT,
                new_hash TEXT,
                timestamp DATETIME,
                rollback_data TEXT,
                status TEXT,
                message TEXT
            )
        ''')
        conn.commit()
        conn.close()

    def _setup_api_endpoints(self):
        @self.app.route('/api/review', methods=['POST'])
        def api_review():
            data = request.json
            input_path = data.get('input_path', '')
            output_path = data.get('output_path', '')
            priority = data.get('priority', 'readability')
            exclude = data.get('exclude', [])
            try:
                agent = AICodeReviewAgent(input_path, output_path)
                agent.config['analysis']['priorities'] = [priority] + [
                    p for p in agent.config['analysis']['priorities'] if p != priority
                ]
                agent.config['input']['exclude'].extend(exclude)
                agent.run()
                return jsonify({
                    "status": "success",
                    "report_path": str(Path(output_path) / "report.json")
                })
            except Exception as e:
                return jsonify({"status": "error", "message": str(e)}), 500

        @self.app.route('/api/rollback', methods=['POST'])
        def api_rollback():
            data = request.json
            change_id = data.get('change_id')
            try:
                self.rollback_changes(change_id)
                return jsonify({"status": "success"})
            except Exception as e:
                return jsonify({"status": "error", "message": str(e)}), 500

        @self.app.route('/api/status', methods=['GET'])
        def api_status():
            return jsonify({
                "status": "running",
                "metrics": self.report['metrics']
            })

        @self.app.route('/api/upload', methods=['POST'])
        def api_upload():
            if 'file' not in request.files:
                return jsonify({"status": "error", "message": "No file provided"}), 400
            file = request.files['file']
            if file.filename == '':
                return jsonify({"status": "error", "message": "No file selected"}), 400
            filename = secure_filename(file.filename)
            upload_path = self.temp_dir / filename
            file.save(upload_path)
            try:
                agent = AICodeReviewAgent(str(upload_path), str(self.output_path))
                agent.run()
                return jsonify({
                    "status": "success",
                    "report_path": str(agent.output_path / "report.json")
                })
            except Exception as e:
                return jsonify({"status": "error", "message": str(e)}), 500

    def get_system_info(self) -> Dict:
        memory = psutil.virtual_memory().total / (1024 * 1024 * 1024) if psutil else "unknown"
        return {
            "platform": platform.system(),
            "platform_version": platform.version(),
            "python_version": platform.python_version(),
            "processor": platform.processor() or "unknown",
            "memory_gb": memory,
            "cpu_cores": os.cpu_count() or "unknown"
        }

    ############################################################
    # 3.1 Input Processing (FR-1.1...FR-1.4)
    ############################################################
    def prepare_input(self):
        self.log.log("Preparing input")
        if not self.input_path.exists():
            raise ValueError(f"Input path {self.input_path} does not exist")
        if self.input_path.is_file():
            if self.input_path.suffix == '.zip':
                with zipfile.ZipFile(self.input_path, 'r') as zip_ref:
                    zip_ref.extractall(self.temp_dir)
                self.input_path = self.temp_dir
            elif self.input_path.suffix in ['.tar', '.gz', '.bz2']:
                with tarfile.open(self.input_path) as tar_ref:
                    tar_ref.extractall(self.temp_dir)
                self.input_path = self.temp_dir
            elif self.input_path.suffix == '.git' and git:
                self._clone_git_repo()
            elif self.input_path.suffix == '.git':
                warnings.warn("GitPython not installed; Git cloning disabled.")
                raise ValueError("Git cloning not supported without GitPython.")
        self._analyze_structure()
        self._analyze_dependencies()
        self._detect_build_tools()
        if not self._validate_input_size():
            raise ValueError(f"Codebase exceeds maximum size of {self.config['general']['max_size_mb']}MB")

    def _clone_git_repo(self):
        try:
            repo = git.Repo.clone_from(
                str(self.input_path),
                self.temp_dir / 'repo',
                depth=1,
                branch=self.config['input']['git_branch']
            )
            self.input_path = self.temp_dir / 'repo'
            self.report['metadata']['git_info'] = {
                'url': str(self.input_path),
                'branch': repo.active_branch.name,
                'commit': repo.head.commit.hexsha
            }
        except Exception as e:
            raise ValueError(f"Failed to clone repository: {e}")

    def _validate_input_size(self) -> bool:
        total_size = 0
        for file_path in self.input_path.rglob('*'):
            if file_path.is_file():
                total_size += file_path.stat().st_size
        max_size = self.config["general"]["max_size_mb"] * 1024 * 1024
        self.report['metrics']['input_size_mb'] = total_size / (1024 * 1024)
        return total_size <= max_size

    def _analyze_structure(self):
        structure = {
            "directories": [],
            "files": [],
            "languages": set()
        }
        for path in self.input_path.rglob('*'):
            if any(excl in str(path) for excl in self.config["input"]["exclude"]):
                continue
            relative_path = str(path.relative_to(self.input_path))
            if path.is_dir():
                structure["directories"].append(relative_path)
            else:
                structure["files"].append(relative_path)
                ext = path.suffix.lower()
                if ext in self.language_handlers:
                    structure["languages"].add(self.language_handlers[ext]['language'])
        structure["languages"] = list(structure["languages"])
        self.report["structure"] = structure

    def _analyze_dependencies(self):
        for ext, handlers in self.language_handlers.items():
            if 'dependencies' in handlers:
                self.report['dependencies'][ext[1:]] = handlers['dependencies']()

    def _detect_build_tools(self):
        build_tools = []
        build_files = [
            'requirements.txt', 'Pipfile', 'pyproject.toml', 'setup.py',
            'package.json', 'yarn.lock',
            'pom.xml', 'build.gradle',
            'go.mod', 'go.sum',
            'Makefile', 'CMakeLists.txt'
        ]
        for file in build_files:
            if (self.input_path / file).exists():
                build_tools.append(file)
        self.report["build_tools"] = build_tools

    ############################################################
    # 3.2 Code Analysis (FR-2.1 ... FR-2.6)
    ############################################################
    def analyze_codebase(self):
        self.log.log("Analyzing codebase")
        start_time = datetime.now()
        cpu_start = psutil.cpu_percent() if psutil else 0
        mem_start = psutil.virtual_memory().used if psutil else 0

        # Run original test suites (Functional equivalence)
        self.report["metrics"]["tests_before"] = self.run_all_tests()

        if self.config["general"]["parallel_processing"]:
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = []
                for ext, handlers in self.language_handlers.items():
                    for file_path in self.input_path.rglob(f"*{ext}"):
                        if any(excl in str(file_path) for excl in self.config["input"]["exclude"]):
                            continue
                        futures.append(executor.submit(
                            self.process_file_for_analysis,
                            file_path,
                            handlers['analyzer'],
                            handlers.get('security')
                        ))
                for future in as_completed(futures):
                    try:
                        relative_path, issues, security_report = future.result()
                        self.report["files"].append({
                            "path": str(relative_path),
                            "issues": issues,
                            "security": security_report,
                            "metrics": {
                                "style_violations": sum(1 for i in issues if i['category'] == 'style'),
                                "security_issues": len(security_report.get('issues', [])),
                                "complexity": 0
                            }
                        })
                        self.report["metrics"]["files_processed"] += 1
                        self.report["metrics"]["issues_found"] += len(issues)
                        self.report["metrics"]["security_issues"] += len(security_report.get('issues', []))
                        self.report["metrics"]["style_violations"] += sum(1 for i in issues if i['category'] == 'style')
                    except Exception as e:
                        warnings.warn(f"Error processing file: {e}")
        else:
            for ext, handlers in self.language_handlers.items():
                for file_path in self.input_path.rglob(f"*{ext}"):
                    if any(excl in str(file_path) for excl in self.config["input"]["exclude"]):
                        continue
                    relative_path = file_path.relative_to(self.input_path)
                    temp_report = {
                        "issues": [],
                        "metrics": {
                            "style_violations": 0,
                            "security_issues": 0,
                            "complexity": 0
                        }
                    }
                    handlers['analyzer'](file_path, relative_path, temp_report)
                    security_report = handlers.get('security', lambda x: {})(file_path)
                    temp_report["security"] = security_report
                    self.report["metrics"]["security_issues"] += len(security_report.get('issues', []))
                    self.report["files"].append({
                        "path": str(relative_path),
                        "issues": temp_report["issues"],
                        "security": security_report,
                        "metrics": temp_report["metrics"]
                    })
                    self.report["metrics"]["files_processed"] += 1
                    self.report["metrics"]["issues_found"] += len(temp_report["issues"])
                    self.report["metrics"]["style_violations"] += temp_report["metrics"]["style_violations"]
        elapsed = (datetime.now() - start_time).total_seconds()
        cpu = (psutil.cpu_percent() - cpu_start) if psutil else "unknown"
        mem = ((psutil.virtual_memory().used - mem_start) / (1024 * 1024)) if psutil else "unknown"
        self.report['performance']['analysis'] = {
            'time_seconds': elapsed,
            'cpu_usage_percent': cpu,
            'memory_used_mb': mem
        }

    def process_file_for_analysis(self, file_path: Path, analyzer: callable, security_scanner: callable = None) -> Tuple[Path, List[Dict], Dict]:
        relative_path = file_path.relative_to(self.input_path)
        issues = []
        security_report = {}
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                code = f.read()
            file_hash = hashlib.sha256(code.encode()).hexdigest()
            temp_report = {
                "issues": [],
                "metrics": {
                    "style_violations": 0,
                    "security_issues": 0,
                    "complexity": 0
                }
            }
            analyzer(file_path, relative_path, temp_report)
            issues = temp_report["issues"]
            if security_scanner:
                security_report = security_scanner(file_path)
        except Exception as e:
            issues.append({
                "file": str(relative_path),
                "issue": f"Processing error: {str(e)}",
                "line": 0,
                "severity": "high",
                "category": "analysis"
            })
        return (relative_path, issues, security_report)

    # ==================== Language Handlers ====================

    # ----- Python -----
    def analyze_python_file(self, file_path: Path, relative_path: Path, temp_report: Dict):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                code = f.read()
            if not code.strip():
                temp_report["issues"].append({
                    "file": str(relative_path),
                    "issue": "Empty file",
                    "line": 0,
                    "severity": "low",
                    "category": "analysis"
                })
                return
            self.check_python_syntax(code, relative_path, temp_report)
            if pycodestyle:
                self.check_python_style(file_path, relative_path, temp_report)
            self.check_python_complexity(code, relative_path, temp_report)
            self.check_python_security(code, relative_path, temp_report)
            self.check_python_performance(code, relative_path, temp_report)
        except Exception as e:
            temp_report["issues"].append({
                "file": str(relative_path),
                "issue": f"Analysis error: {str(e)}",
                "line": 0,
                "severity": "medium",
                "category": "analysis"
            })

    def scan_python_security(self, file_path: Path) -> Dict:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                code = f.read()
            return self.check_python_security(code, None, {"issues": []})
        except Exception as e:
            return {"error": str(e), "issues": []}

    def check_python_syntax(self, code: str, relative_path: Path, temp_report: Dict):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            try:
                ast.parse(code)
            except SyntaxError as e:
                temp_report["issues"].append({
                    "file": str(relative_path),
                    "issue": f"Syntax error: {e.msg}",
                    "line": e.lineno or 0,
                    "severity": "critical",
                    "category": "syntax"
                })
            for warning in w:
                if issubclass(warning.category, SyntaxWarning):
                    temp_report["issues"].append({
                        "file": str(relative_path),
                        "issue": f"Syntax warning: {str(warning.message)}",
                        "line": warning.lineno or 0,
                        "severity": "low",
                        "category": "syntax"
                    })

    def check_python_style(self, file_path: Path, relative_path: Path, temp_report: Dict):
        try:
            style_errors = []
            def error_handler(line_number, offset, text, check):
                code = text[:4]
                style_errors.append((line_number, offset, code, text[5:]))
                return code
            checker = pycodestyle.Checker(
                str(file_path),
                max_line_length=self.config["style"]["python"]["max_line_length"],
                ignore=self.config["style"]["python"]["ignore"],
                show_source=True
            )
            checker.report_error = error_handler
            checker.check_all()
            for line_number, offset, code, text in style_errors:
                temp_report["issues"].append({
                    "file": str(relative_path),
                    "issue": f"Style violation ({code}): {text}",
                    "line": line_number,
                    "offset": offset,
                    "severity": "low" if code.startswith("W") else "medium",
                    "category": "style"
                })
                temp_report["metrics"]["style_violations"] += 1
        except Exception as e:
            temp_report["issues"].append({
                "file": str(relative_path),
                "issue": f"Style check error: {str(e)}",
                "line": 0,
                "severity": "low",
                "category": "analysis"
            })

    def check_python_complexity(self, code: str, relative_path: Path, temp_report: Dict):
        try:
            tree = ast.parse(code)
            total_complexity = 0
            func_count = 0
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    complexity = self.calculate_complexity(node)
                    total_complexity += complexity
                    func_count += 1
                    temp_report["metrics"]["complexity"] = max(
                        temp_report["metrics"]["complexity"], complexity
                    )
                    if complexity > self.config["analysis"]["thresholds"]["complexity"]:
                        temp_report["issues"].append({
                            "file": str(relative_path),
                            "issue": f"High complexity in function '{node.name}': {complexity}",
                            "line": node.lineno,
                            "severity": "medium",
                            "category": "complexity"
                        })
            if func_count > 0:
                self.report["metrics"]["complexity_score"] += total_complexity / func_count
        except Exception as e:
            temp_report["issues"].append({
                "file": str(relative_path),
                "issue": f"Complexity analysis error: {str(e)}",
                "line": 0,
                "severity": "low",
                "category": "analysis"
            })

    def calculate_complexity(self, node: ast.AST) -> int:
        complexity = 1
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For, ast.AsyncFor, ast.ExceptHandler, ast.With, ast.AsyncWith)):
                complexity += 1
            elif isinstance(child, ast.BoolOp):
                complexity += len(child.values) - 1
        return complexity

    def check_python_security(self, code: str, relative_path: Path, temp_report: Dict):
        security_patterns = [
            (r'eval\s*\(', "Use of eval() is dangerous", "high"),
            (r'exec\s*\(', "Use of exec() is dangerous", "high"),
            (r'subprocess\.call\s*\(.*shell\s*=\s*True', "Subprocess with shell=True is risky", "high"),
            (r'pickle\.loads?\s*\(', "Pickle loading can be unsafe", "high"),
            (r'__import__\s*\(', "Dynamic imports can be risky", "medium"),
            (r'input\s*\(.*\)', "Use raw_input() or validate input in Python 2; safe in Python 3", "medium" if platform.python_version().startswith("2.") else "ignore"),
        ]
        lines = code.split('\n')
        issues = temp_report["issues"] if relative_path else []
        for i, line in enumerate(lines, 1):
            for pattern, message, severity in security_patterns:
                if severity == "ignore":
                    continue
                if re.search(pattern, line, re.IGNORECASE):
                    issue = {
                        "file": str(relative_path) if relative_path else "",
                        "issue": f"Security issue: {message}",
                        "line": i,
                        "severity": severity,
                        "category": "security"
                    }
                    issues.append(issue)
                    if relative_path:
                        temp_report["metrics"]["security_issues"] += 1
        return {"issues": issues}

    def check_python_performance(self, code: str, relative_path: Path, temp_report: Dict):
        performance_patterns = [
            (r'\.append\s*\(.*\)\s*in\s*\[\s*\]\s*\*', "Repeated list concatenation is slow", "medium"),
            (r'global\s+\w+', "Use of global variables can impact performance", "low"),
            (r'@staticmethod\s+def\s+\w+\(\s*\)', "Static methods may be unnecessary", "low"),
        ]
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            for pattern, message, severity in performance_patterns:
                if re.search(pattern, line):
                    temp_report["issues"].append({
                        "file": str(relative_path),
                        "issue": f"Performance issue: {message}",
                        "line": i,
                        "severity": severity,
                        "category": "performance"
                    })
                    self.report["metrics"]["performance_issues"] += 1

    # ----- JavaScript -----
    def analyze_js_file(self, file_path: Path, relative_path: Path, temp_report: Dict):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                code = f.read()
            # Syntax (ESLint required)
            code_issues = []
            rc, out, err = run_command(f"npx eslint \"{file_path}\" -f json", cwd=str(self.input_path.parent))
            if rc == 0 and out.strip():
                try:
                    eslint_result = json.loads(out)
                    for file_result in eslint_result:
                        for msg in file_result.get("messages", []):
                            code_issues.append({
                                "file": msg.get("filePath", str(relative_path)),
                                "issue": msg.get("message", ""),
                                "line": msg.get("line", 0),
                                "severity": "high" if msg.get("severity") == 2 else "medium",
                                "category": "syntax" if msg.get("ruleId", "").startswith("no-") else "style"
                            })
                except Exception:
                    pass
            temp_report["issues"].extend(code_issues)
            # Security (simple regex)
            for i, line in enumerate(code.splitlines(), 1):
                if "eval(" in line:
                    temp_report["issues"].append({
                        "file": str(relative_path),
                        "issue": "Use of eval() is dangerous",
                        "line": i,
                        "severity": "high",
                        "category": "security"
                    })
            # Complexity (simple: count if, for, while, function)
            complexity = sum(line.strip().startswith(("if", "for", "while", "function", "=>")) for line in code.splitlines())
            if complexity > self.config["analysis"]["thresholds"]["complexity"]:
                temp_report["issues"].append({
                    "file": str(relative_path),
                    "issue": f"High complexity: {complexity}",
                    "line": 0,
                    "severity": "medium",
                    "category": "complexity"
                })
        except Exception as e:
            temp_report["issues"].append({
                "file": str(relative_path),
                "issue": f"Analysis error: {str(e)}",
                "line": 0,
                "severity": "high",
                "category": "analysis"
            })

    def improve_js_file(self, file_path: Path, relative_path: Path):
        # Use prettier if available else minimal
        try:
            rc, out, err = run_command(f"npx prettier --write \"{file_path}\"", cwd=str(self.input_path.parent))
        except Exception:
            pass

    def format_js_file(self, code: str) -> str:
        # Use prettier if available else basic
        return code

    def scan_js_security(self, file_path: Path) -> Dict:
        issues = []
        with open(file_path, "r", encoding="utf-8") as f:
            for i, line in enumerate(f, 1):
                if "eval(" in line:
                    issues.append({"file": str(file_path), "issue": "eval() used", "line": i, "severity": "high"})
        return {"issues": issues}

    def analyze_js_dependencies(self) -> Dict:
        deps = {}
        req_file = self.input_path / "package.json"
        if req_file.exists():
            try:
                with open(req_file, "r", encoding="utf-8") as f:
                    pkg = json.load(f)
                    deps = pkg.get("dependencies", {})
            except Exception as e:
                deps["error"] = str(e)
        return deps or {"status": "no dependency files found"}

    def run_js_tests(self):
        rc, out, err = run_command("npm test", cwd=str(self.input_path))
        return {"rc": rc, "stdout": out, "stderr": err}

    # ----- Java -----
    def analyze_java_file(self, file_path: Path, relative_path: Path, temp_report: Dict):
        try:
            # Use checkstyle if available
            rc, out, err = run_command(f"checkstyle -c /google_checks.xml \"{file_path}\"", cwd=str(self.input_path.parent))
            if rc == 0:
                for line in out.splitlines():
                    m = re.match(r"^\[(\w+)\] (.+):(\d+): (.+)$", line)
                    if m:
                        severity, filep, lineno, msg = m.groups()
                        temp_report["issues"].append({
                            "file": filep,
                            "issue": msg,
                            "line": int(lineno),
                            "severity": severity.lower(),
                            "category": "style"
                        })
            # Security: look for Runtime.exec, reflection
            with open(file_path, "r", encoding="utf-8") as f:
                for i, line in enumerate(f, 1):
                    if "Runtime.getRuntime().exec" in line or "Class.forName(" in line:
                        temp_report["issues"].append({
                            "file": str(relative_path),
                            "issue": "Potential security risk: exec/reflection",
                            "line": i,
                            "severity": "high",
                            "category": "security"
                        })
        except Exception as e:
            temp_report["issues"].append({
                "file": str(relative_path),
                "issue": f"Analysis error: {str(e)}",
                "line": 0,
                "severity": "high",
                "category": "analysis"
            })

    def improve_java_file(self, file_path: Path, relative_path: Path):
        # Use google-java-format if available
        try:
            run_command(f"google-java-format -i \"{file_path}\"", cwd=str(self.input_path.parent))
        except Exception:
            pass

    def format_java_file(self, code: str) -> str:
        return code

    def scan_java_security(self, file_path: Path) -> Dict:
        issues = []
        with open(file_path, "r", encoding="utf-8") as f:
            for i, line in enumerate(f, 1):
                if "Runtime.getRuntime().exec" in line or "Class.forName(" in line:
                    issues.append({"file": str(file_path), "issue": "Potential security risk", "line": i, "severity": "high"})
        return {"issues": issues}

    def analyze_java_dependencies(self) -> Dict:
        deps = {}
        pom = self.input_path / "pom.xml"
        if pom.exists():
            deps["pom.xml"] = "present"
        gradle = self.input_path / "build.gradle"
        if gradle.exists():
            deps["build.gradle"] = "present"
        return deps or {"status": "no dependency files found"}

    def run_java_tests(self):
        if (self.input_path / "pom.xml").exists():
            rc, out, err = run_command("mvn test", cwd=str(self.input_path))
        elif (self.input_path / "build.gradle").exists():
            rc, out, err = run_command("gradle test", cwd=str(self.input_path))
        else:
            rc, out, err = -1, '', 'No test framework found'
        return {"rc": rc, "stdout": out, "stderr": err}

    # ----- Go -----
    def analyze_go_file(self, file_path: Path, relative_path: Path, temp_report: Dict):
        try:
            rc, out, err = run_command(f"gofmt -l \"{file_path}\"", cwd=str(self.input_path.parent))
            if rc == 0 and out.strip():
                temp_report["issues"].append({
                    "file": str(relative_path),
                    "issue": "Not gofmt formatted",
                    "line": 0,
                    "severity": "medium",
                    "category": "style"
                })
            with open(file_path, "r", encoding="utf-8") as f:
                for i, line in enumerate(f, 1):
                    if "os/exec" in line:
                        temp_report["issues"].append({
                            "file": str(relative_path),
                            "issue": "Potential security risk: os/exec",
                            "line": i,
                            "severity": "high",
                            "category": "security"
                        })
        except Exception as e:
            temp_report["issues"].append({
                "file": str(relative_path),
                "issue": f"Analysis error: {str(e)}",
                "line": 0,
                "severity": "high",
                "category": "analysis"
            })

    def improve_go_file(self, file_path: Path, relative_path: Path):
        run_command(f"gofmt -w \"{file_path}\"", cwd=str(self.input_path.parent))

    def format_go_file(self, code: str) -> str:
        return code

    def scan_go_security(self, file_path: Path) -> Dict:
        issues = []
        with open(file_path, "r", encoding="utf-8") as f:
            for i, line in enumerate(f, 1):
                if "os/exec" in line:
                    issues.append({"file": str(file_path), "issue": "Potential security risk: os/exec", "line": i, "severity": "high"})
        return {"issues": issues}

    def analyze_go_dependencies(self) -> Dict:
        deps = {}
        gomod = self.input_path / "go.mod"
        if gomod.exists():
            deps["go.mod"] = "present"
        return deps or {"status": "no dependency files found"}

    def run_go_tests(self):
        rc, out, err = run_command("go test ./...", cwd=str(self.input_path))
        return {"rc": rc, "stdout": out, "stderr": err}

    # ----- Python dependencies, tests -----
    def analyze_python_dependencies(self) -> Dict:
        dep_files = ['requirements.txt', 'Pipfile', 'pyproject.toml', 'setup.py']
        for dep_file in dep_files:
            if (self.input_path / dep_file).exists():
                return self._parse_python_dependencies(dep_file)
        return {"status": "no dependency files found"}
    def _parse_python_dependencies(self, filename: str) -> Dict:
        if filename == 'requirements.txt':
            return self._parse_requirements_file()
        return {"status": f"{filename} parsing not implemented"}
    def _parse_requirements_file(self) -> Dict:
        deps = {}
        req_file = self.input_path / 'requirements.txt'
        try:
            with open(req_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if '==' in line:
                            pkg, version = line.split('==', 1)
                            deps[pkg] = version
                        else:
                            deps[line] = 'latest'
        except Exception as e:
            deps["error"] = str(e)
        return deps

    def run_python_tests(self):
        # Try pytest, then unittest
        rc, out, err = run_command("pytest", cwd=str(self.input_path))
        if rc == 0:
            return {"rc": rc, "stdout": out, "stderr": err}
        rc, out, err = run_command("python -m unittest discover", cwd=str(self.input_path))
        return {"rc": rc, "stdout": out, "stderr": err}

    # ========== Test framework detection and execution ==========
    def run_all_tests(self):
        results = {}
        # Python
        results["python"] = self.run_python_tests()
        # JS
        results["javascript"] = self.run_js_tests()
        # Java
        results["java"] = self.run_java_tests()
        # Go
        results["go"] = self.run_go_tests()
        return results

    ############################################################
    # 3.3 Code Improvement (FR-3.1 ... FR-3.6)
    ############################################################
    def improve_codebase(self):
        self.log.log("Improving codebase")
        for ext, handlers in self.language_handlers.items():
            for file_path in self.input_path.rglob(f"*{ext}"):
                if any(excl in str(file_path) for excl in self.config["input"]["exclude"]):
                    continue
                relative_path = file_path.relative_to(self.input_path)
                try:
                    handlers['improver'](file_path, relative_path)
                    self.report["metrics"]["files_improved"] += 1
                except Exception as e:
                    self.log.log(f"Error improving {relative_path}: {e}")
                    self._log_change_failure(str(relative_path), str(e))

    # Python code improvement
    def format_python_file(self, code: str) -> str:
        if autopep8:
            try:
                formatted_code = autopep8.fix_code(
                    code,
                    options={
                        'max_line_length': self.config["style"]["python"]["max_line_length"],
                        'ignore': self.config["style"]["python"]["ignore"],
                        'aggressive': 2,
                        'experimental': True,
                        'select': [
                            'E111', 'E117', 'E225', 'E226', 'E228', 'E231',
                            'E302', 'E305', 'W291', 'W293', 'E261', 'E262',
                            'E201', 'E202', 'E203', 'E701', 'E702'
                        ],
                    }
                )
                return formatted_code
            except Exception as e:
                warnings.warn(f"autopep8 formatting failed: {e}")
        return code

    def improve_python_file(self, file_path: Path, relative_path: Path):
        import difflib
        with open(file_path, 'r', encoding='utf-8') as f:
            original_code = f.read()
        original_hash = hashlib.sha256(original_code.encode()).hexdigest()
        fixed_code = original_code
        escape_fixes = 0
        for pattern in [r'"[^"]*\\c[^"]*"', r"'[^']*\\c[^']*'"]:
            matches = re.finditer(pattern, fixed_code)
            for match in matches:
                old_str = match.group(0)
                new_str = old_str.replace(r'\c', r'\\c')
                fixed_code = fixed_code.replace(old_str, new_str)
                escape_fixes += 1
        self.report["metrics"]["escape_sequence_fixes"] += escape_fixes
        input_fixes = 0
        lines = fixed_code.splitlines()
        fixed_lines = []
        for line in lines:
            if 'input(' in line and '# noqa: S602' not in line:
                fixed_lines.append(line + '  # noqa: S602')
                input_fixes += 1
            else:
                fixed_lines.append(line)
        fixed_code = '\n'.join(fixed_lines) + '\n'
        lines = fixed_code.splitlines()
        fixed_lines = []
        for line in lines:
            if 'eval(' in line:
                fixed_lines.append(f"# AI Suggestion: Avoid eval(); consider safer alternatives\n{line}")
            elif 'exec(' in line:
                fixed_lines.append(f"# AI Suggestion: Avoid exec(); use defined functions\n{line}")
            else:
                fixed_lines.append(line)
        fixed_code = '\n'.join(fixed_lines) + '\n'
        improved_code = self.format_python_file(fixed_code)
        import difflib
        diff = ''.join(difflib.unified_diff(
            original_code.splitlines(keepends=True),
            improved_code.splitlines(keepends=True),
            fromfile=str(relative_path),
            tofile=str(relative_path),
            n=3
        ))
        self.report["diffs"].append({"file": str(relative_path), "diff": diff})
        self._save_improved_file(relative_path, improved_code, original_code, original_hash)

    def _save_improved_file(self, relative_path: Path, improved_code: str, original_code: str, original_hash: str):
        improved_hash = hashlib.sha256(improved_code.encode()).hexdigest()
        output_file = self.output_path / "improved" / relative_path
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(improved_code)
        conn = sqlite3.connect(self.changes_db)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO changes (
                file_path, change_type, original_hash, new_hash, 
                timestamp, rollback_data, status, message
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            str(relative_path),
            "improvement",
            original_hash,
            improved_hash,
            datetime.now().isoformat(),
            original_code,
            "completed",
            f"Applied {self.report['metrics']['escape_sequence_fixes']} \\c fixes, "
            f"{self.report['metrics']['input_noqa_additions']} input() fixes"
        ))
        conn.commit()
        conn.close()
        self.report["changes"].append({
            "file": str(relative_path),
            "original_hash": original_hash,
            "new_hash": improved_hash,
            "timestamp": datetime.now().isoformat(),
            "type": "improvement",
            "details": {
                "escape_sequence_fixes": self.report["metrics"]["escape_sequence_fixes"],
                "input_noqa_additions": self.report["metrics"]["input_noqa_additions"],
            }
        })

    def _log_change_failure(self, file_path: str, error: str):
        conn = sqlite3.connect(self.changes_db)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO changes (
                file_path, change_type, timestamp, status, message
            ) VALUES (?, ?, ?, ?, ?)
        ''', (
            file_path,
            "improvement",
            datetime.now().isoformat(),
            "failed",
            error
        ))
        conn.commit()
        conn.close()

    def rollback_changes(self, change_id: int = None):
        conn = sqlite3.connect(self.changes_db)
        cursor = conn.cursor()
        if change_id:
            cursor.execute('SELECT * FROM changes WHERE id = ?', (change_id,))
        else:
            cursor.execute('SELECT * FROM changes ORDER BY id DESC LIMIT 1')
        change = cursor.fetchone()
        if change:
            self._apply_rollback(change)
        conn.close()

    def _apply_rollback(self, change):
        file_path = Path(change[1])
        rollback_data = change[5]
        output_file = self.output_path / "improved" / file_path
        if output_file.exists():
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(rollback_data)
            conn = sqlite3.connect(self.changes_db)
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE changes SET status = ? WHERE id = ?
            ''', ("rolled back", change[0]))
            conn.commit()
            conn.close()
            self._log_rollback(change[0])

    def _log_rollback(self, change_id: int):
        self.report["changes"].append({
            "change_id": change_id,
            "action": "rollback",
            "timestamp": datetime.now().isoformat()
        })

    def generate_report(self):
        self.log.log("Generating report")
        self.output_path.mkdir(parents=True, exist_ok=True)
        if "json" in self.config["output"]["formats"]:
            self._generate_json_report()
        if "markdown" in self.config["output"]["formats"]:
            self._generate_markdown_report()
        if "html" in self.config["output"]["formats"]:
            self._generate_html_report()

    def _generate_json_report(self):
        report_path = self.output_path / "report.json"
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(self.report, f, indent=2, default=str)

    def _generate_markdown_report(self):
        report_path = self.output_path / "report.md"
        style_violations = sum(
            file["metrics"]["style_violations"] for file in self.report["files"]
        )
        improved_violations = sum(
            file["metrics"]["style_violations"] for file in self.report["files"]
            if any(c["file"] == file["path"] and c["type"] == "improvement" for c in self.report["changes"])
        )
        md_content = [
            "# AI Code Review Report",
            "## Metadata",
            f"- **Date**: {self.report['metadata']['timestamp']}",
            f"- **Input Path**: {self.report['metadata']['input_path']}",
            f"- **Output Path**: {self.report['metadata']['output_path']}",
            "## Summary",
            f"- **Files Processed**: {self.report['metrics']['files_processed']}",
            f"- **Files Improved**: {self.report['metrics']['files_improved']}",
            f"- **Issues Found**: {self.report['metrics']['issues_found']}",
            f"- **Security Issues**: {self.report['metrics']['security_issues']}",
            f"- **Performance Issues**: {self.report['metrics']['performance_issues']}",
            f"- **Style Violations**: {style_violations}",
            "## Detailed Findings",
            "| File | Issue | Line | Severity | Category |",
            "|------|-------|------|----------|----------|"
        ]
        for file in self.report["files"]:
            for issue in file["issues"]:
                md_content.append(
                    f"| {file['path']} | {issue['issue']} | {issue['line']} | {issue.get('severity', 'unknown')} | {issue.get('category', 'unknown')} |"
                )
        md_content.append("\n## Changes Applied")
        for change in self.report["changes"]:
            if change.get("type") == "improvement":
                md_content.append(
                    f"- **{change['file']}**: {change['type'].capitalize()} applied "
                    f"(Original Hash: {change['original_hash'][:8]}, New Hash: {change['new_hash'][:8]})"
                    f" - {change['details']['escape_sequence_fixes']} \\c fixes, "
                    f"{change['details']['input_noqa_additions']} input() fixes"
                )
            elif change.get("action") == "rollback":
                md_content.append(
                    f"- **Change ID {change['change_id']}**: Rollback performed"
                )
        md_content.append("\n## Code Diffs")
        for diff_entry in self.report["diffs"]:
            md_content.append(f"### {diff_entry['file']}")
            md_content.append("```diff")
            md_content.append(diff_entry["diff"])
            md_content.append("```")
        md_content.extend([
            "\n## Metrics",
            "| Metric | Original | Improved |",
            "|--------|----------|----------|",
            f"| Style Violations | {style_violations} | {improved_violations} |"
        ])
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("\n".join(md_content))

    def _generate_html_report(self):
        report_path = self.output_path / "report.html"
        html = "<html><head><title>AI Code Review Report</title></head><body>"
        html += "<h1>AI Code Review Report</h1>"
        html += "<h2>Metadata</h2><ul>"
        for k, v in self.report["metadata"].items():
            html += f"<li><b>{k}</b>: {v}</li>"
        html += "</ul><h2>Summary</h2><ul>"
        for k, v in self.report["metrics"].items():
            if isinstance(v, dict): continue
            html += f"<li><b>{k}</b>: {v}</li>"
        html += "</ul><h2>Detailed Findings</h2><table border='1'><tr><th>File</th><th>Issue</th><th>Line</th><th>Severity</th><th>Category</th></tr>"
        for file in self.report["files"]:
            for issue in file["issues"]:
                html += f"<tr><td>{file['path']}</td><td>{issue['issue']}</td><td>{issue['line']}</td><td>{issue.get('severity', 'unknown')}</td><td>{issue.get('category', 'unknown')}</td></tr>"
        html += "</table><h2>Changes Applied</h2><ul>"
        for change in self.report["changes"]:
            if change.get("type") == "improvement":
                html += (f"<li><b>{change['file']}</b>: {change['type'].capitalize()} applied "
                         f"(Original Hash: {change['original_hash'][:8]}, New Hash: {change['new_hash'][:8]})"
                         f" - {change['details']['escape_sequence_fixes']} \\c fixes, "
                         f"{change['details']['input_noqa_additions']} input() fixes</li>")
            elif change.get("action") == "rollback":
                html += f"<li>Change ID {change['change_id']}: Rollback performed</li>"
        html += "</ul><h2>Code Diffs</h2>"
        for diff_entry in self.report["diffs"]:
            html += f"<h3>{diff_entry['file']}</h3><pre>{diff_entry['diff']}</pre>"
        html += "</body></html>"
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html)

    def cleanup(self):
        self.log.log("Cleaning up temp resources")
        try:
            if self.temp_dir.exists():
                shutil.rmtree(self.temp_dir)
        except Exception as e:
            warnings.warn(f"Error during cleanup: {e}")

    def run(self):
        self.log.log(f"Starting AI Code Review for: {self.input_path}")
        try:
            self.prepare_input()
            self.analyze_codebase()
            self.improve_codebase()
            # Run tests on improved code
            self.report["metrics"]["tests_after"] = self.run_all_tests()
            self.generate_report()
            self.cleanup()
            return True
        except Exception as e:
            self.log.log(f"Error during code review: {str(e)}")
            self.cleanup()
            return False

    def run_web_interface(self):
        if hasattr(self, 'app'):
            print(f"Starting web interface at http://{self.config['general']['web_host']}:{self.config['general']['web_port']}")
            self.app.run(
                host=self.config['general']['web_host'],
                port=self.config['general']['web_port'],
                debug=False
            )
        else:
            print("Web interface not available; Flask not installed.")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description='AI Code Review Agent',
        epilog='Examples:\n'
               '  python ai_code_review_agent.py review --input repo.zip --output ./output --priority security\n'
               '  python ai_code_review_agent.py review --path ./project --output ./output --exclude tests/\n'
               '  python ai_code_review_agent.py self-improve --input . --output ./output'
    )
    subparsers = parser.add_subparsers(dest='command', required=True)
    review_parser = subparsers.add_parser('review', help='Review and improve codebase')
    review_parser.add_argument('--input', help='Path to zip or Git URL')
    review_parser.add_argument('--path', help='Path to local folder')
    review_parser.add_argument('--output', required=True, help='Path for reports and improved code')
    review_parser.add_argument('--config', help='Path to config file')
    review_parser.add_argument('--priority', choices=['security', 'performance', 'readability'],
                              default='readability', help='Analysis priority')
    review_parser.add_argument('--exclude', nargs='*', default=[], help='Folders/files to exclude')
    review_parser.add_argument('--web', action='store_true', help='Enable web interface')
    self_improve_parser = subparsers.add_parser('self-improve', help='Improve ai_code_review_agent.py itself')
    self_improve_parser.add_argument('--input', required=True, help='Path to codebase')
    self_improve_parser.add_argument('--output', required=True, help='Path for reports and improved code')
    self_improve_parser.add_argument('--config', help='Path to config file')
    args = parser.parse_args()
    if not args.input and not args.path and args.command == 'review':
        parser.error("At least one of --input or --path is required for review command")
    input_path = args.input or args.path or args.input
    agent = AICodeReviewAgent(input_path, args.output, args.config)
    if args.command == 'review':
        if args.priority:
            agent.config['analysis']['priorities'] = [args.priority] + [
                p for p in agent.config['analysis']['priorities'] if p != args.priority
            ]
        if args.exclude:
            agent.config['input']['exclude'].extend(args.exclude)
        if args.web:
            agent.run_web_interface()
        else:
            success = agent.run()
            exit(0 if success else 1)
    elif args.command == 'self-improve':
        success = agent.run()
        exit(0 if success else 1)
