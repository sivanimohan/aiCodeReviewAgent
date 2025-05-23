# AI Code Review Agent

## Overview

The **AI Code Review Agent** (`aiagent.py`) is a multi-language tool that reviews entire codebases for syntax, style, security, and performance issues, automatically generates improved versions of source code, and produces detailed reports. It supports Python, JavaScript, Java, and Go projects, and can be integrated into local development workflows or CI/CD pipelines.

---

## Features

- **Multi-language support:** Python, JavaScript, Java, Go
- **Input formats:** Folder, ZIP archive, or Git repository
- **Automated code analysis:** Syntax, security, style, complexity, performance
- **Automated improvements:** Code formatting, docstring insertion, anti-pattern fixes
- **Detailed reporting:** Generates reports in JSON, Markdown, and HTML with before/after comparisons and metrics
- **Runs test suites:** Executes tests before and after improvement for functional equivalence
- **Parallel processing:** Fast analysis on large codebases
- **Configurable:** Exclude files, set priorities, customize rules via config
- **Web/API interface:** Optional Flask web server and REST API for integration

---

## Requirements

- Python 3.8 or higher
- See [requirements.txt](requirements.txt) for Python dependencies
- For full multi-language support:
  - **Node.js** (for `eslint`, `prettier` - JavaScript analysis and formatting)
  - **Java** (for `checkstyle`, `google-java-format`)
  - **Go** (for `gofmt`)
- (Optional) Git installed for cloning repositories

---

## Quickstart

### 1. Install Python dependencies

```sh
pip install -r requirements.txt
```

### 2. (Optional) Install language-specific tools for JS/Java/Go support

- JavaScript:  
  ```sh
  npm install -g eslint prettier
  ```
- Java:  
  Download and add `checkstyle` and `google-java-format` to your PATH.
- Go:  
  Ensure `go` and `gofmt` are installed and in your PATH.

### 3. Run the Agent

#### On a local code folder

```sh
python aiagent.py review --path /path/to/codebase --output /path/to/output
```

#### On a ZIP archive

```sh
python aiagent.py review --input /path/to/codebase.zip --output /path/to/output
```

#### On a Git repository

```sh
python aiagent.py review --input https://github.com/owner/repo.git --output /path/to/output
```

### 4. (Optional) Web Interface

```sh
python aiagent.py review --path /path/to/codebase --output /path/to/output --web
```
Then open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser.

---

## Output

- **Improved code:** `/path/to/output/improved/`
- **Reports:**  
  - `/path/to/output/report.json`  
  - `/path/to/output/report.md`  
  - `/path/to/output/report.html`
- **Change log:** `/path/to/output/agent.log`

---

## Configuration

- Exclude files/folders: `--exclude tests/ node_modules/`
- Set review priority: `--priority security`
- Use a custom config file: `--config /path/to/config.json`

See the comments in the script or sample `config.json` for full options.

---

## Functional Requirements

See [AI_Code_Review_FRD.md](AI_Code_Review_FRD.md) for the specification.

---

## Sample Run

```sh
python aiagent.py review --path ./sample_input --output ./sample_output
```

---

## License

[MIT License](LICENSE) (if applicable)

---

## Contact

For questions, contact [Your Name] at [your.email@example.com].
