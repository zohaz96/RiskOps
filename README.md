# RiskOps

A web-based vulnerability management system built with Django, developed as part of a university secure software development module.

## Project Status

Currently in active development. Core functionality is working; tests and deployment pipeline are being expanded.

## Features

- Role-based access control (Admin, Security Manager, Security Analyst, Auditor)
- Vulnerability tracking with CVSS scoring and severity classification
- Asset register with environment and criticality tagging
- Tamper-evident audit log with SHA-256 hash chaining
- Account lockout after 5 failed login attempts (django-axes)
- CI/CD pipeline via GitHub Actions

## Tech Stack

- Python 3.9 / Django 4.2
- PostgreSQL (production) / SQLite (development)
- Bootstrap 5
- Deployed on Render

## Getting Started

### Prerequisites

- Python 3.9+
- pip

### Installation
```bash
git clone https://github.com/zohaz96/RiskOps.git
cd RiskOps
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Environment Variables

Create a `.env` file in the project root:
```
SECRET_KEY=secret-key
DEBUG=True
```

### Run locally
```bash
python manage.py migrate
python seed.py
python manage.py runserver
```

### Demo credentials

| Username | Password | Role |
|---|---|---|
| admin | AdminPass123! | Admin |
| s.manager | ManagerPass123! | Security Manager |
| s.analyst | AnalystPass123! | Security Analyst |
| auditor | AuditorPass123! | Auditor |

## Running Tests
```bash
pytest tests.py -v
```

## Deployment

Deployed to Render. Build process is handled by `build.sh` which runs migrations and seeds demo data on each deploy.

## Known Issues / TODO

- [ ] Add filtering to vulnerability list by severity and status
- [ ] Add pagination to audit log
- [ ] Investigate moving from SQLite to PostgreSQL locally

## Live Demo

https://riskops-435m.onrender.com