# pentforge

Pentest report generator — parse nmap XML and generate a client-ready HTML report.

## Why

Every pentester spends hours copy-pasting nmap output into Word templates. **pentforge** does it in one command: parse → enrich → report.

## Features

- **Parse nmap XML** (`-oX` output) into structured findings
- **Automatic severity assignment** based on port/service risk
- **Remediation hints** for common findings
- **Professional HTML report** with executive summary + findings table
- **Color-coded severity** (Critical / High / Medium / Low / Info)

## Install

```bash
git clone https://github.com/PacianChigo/pentforge.git
cd pentforge
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

