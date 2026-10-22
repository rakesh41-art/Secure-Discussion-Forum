# Secure Discussion Forum

A Flask and SQLite web application for creating discussion threads, posting replies, reporting inappropriate content, and moderating a community with role-based permissions.

## Features
- User registration, login, and logout
- Discussion threads and replies
- Role hierarchy: user, moderator, and administrator
- Moderation queue and user reports
- Thread lock, pin, remove, and restore actions
- Reply removal and restoration
- Input validation, duplicate-content checks, and rate limiting
- CSRF protection, password hashing, secure session-cookie settings, and security headers
- Automated tests using pytest

## Requirements
- Python 3.10+ (recommended)
- pip

## Run locally (Windows PowerShell)
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
$env:FORUM_SECRET_KEY = python -c "import secrets; print(secrets.token_hex(32))"
$env:FORUM_INSECURE = "1"
python app.py
```

Open the local URL printed by Flask in your browser. `FORUM_INSECURE=1` is for local HTTP development only. For deployment, use HTTPS and a production WSGI server.

The first account registered becomes the administrator. Register the admin account first.

## Run tests
```powershell
python -m pip install pytest
python -m pytest -q
```

## Security notes
- Do not commit `.env`, secrets, database files, or credentials.
- The development server is not intended for production.
- Configure a production secret key and HTTPS before deployment.
- Review the known limitations in the project report before production use.
