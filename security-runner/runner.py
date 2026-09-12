"""Configured authorization regression tests. This is not a discovery scanner."""
from __future__ import annotations
import argparse
from contextlib import ExitStack
from datetime import datetime, timezone
import html
import ipaddress
import json
import os
from pathlib import Path
from urllib.parse import urlparse
import httpx


def validate_target(config: dict) -> None:
    url = urlparse(config['base_url'])
    if url.scheme not in ('http', 'https') or url.username or url.password or url.query or url.fragment or url.path not in ('', '/'):
        raise ValueError('Use an HTTP(S) origin without credentials, a path, or query.')
    local = url.hostname == 'localhost'
    try:
        local = local or ipaddress.ip_address(url.hostname or '').is_loopback
    except ValueError:
        pass
    if not local and config.get('allow_non_loopback') is not True:
        raise ValueError('Non-loopback targets require explicit allow_non_loopback configuration for an authorized target.')
    for case in config['cases']:
        if not case['path'].startswith('/api/v1/') or '://' in case['path'] or '..' in case['path']:
            raise ValueError('Cases must use local /api/v1/ paths.')


def lookup(value, path):
    for part in path.split('.'):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def contains_key(value, names):
    if isinstance(value, dict):
        return any(k in names or contains_key(v, names) for k, v in value.items())
    return isinstance(value, list) and any(contains_key(v, names) for v in value)


def check_response(case, status, body):
    problems = []
    if status != case['status']:
        problems.append(f"Expected HTTP {case['status']}; received {status}.")
    if 'field' in case:
        value = lookup(body, case['field'])
        if 'equals' in case and value != case['equals']:
            problems.append('Response ownership/content did not match the configured expectation.')
        if case.get('nonempty') and not value:
            problems.append('Expected response content was missing.')
    if any(lookup(body, name) is not None for name in case.get('absent_fields', [])):
        problems.append('Denied response exposed protected content.')
    if contains_key(body, case.get('forbidden_keys', [])):
        problems.append('Response contained a forbidden sensitive field.')
    return problems


def run(config, password):
    validate_target(config)
    results = []
    with ExitStack() as stack:
        clients = {}
        for name in ['anonymous', *config['actors']]:
            # Redirects are disabled: never forward credentials to another origin.
            client = stack.enter_context(httpx.Client(base_url=config['base_url'], timeout=15, follow_redirects=False, trust_env=False))
            clients[name] = client
            if name == 'anonymous':
                continue
            csrf = client.get('/api/v1/auth/csrf')
            csrf.raise_for_status()
            response = client.post('/api/v1/auth/login', headers={'Origin': config['origin'], 'X-CSRF-Token': csrf.json()['csrfToken']}, json={'email': config['actors'][name], 'password': password})
            if response.status_code != 200 or not response.json().get('user', {}).get('id'):
                raise ValueError(f'Could not authenticate configured actor {name}. Check seed data and credentials.')
        for case in config['cases']:
            response = clients[case['actor']].get(case['path'])
            if response.status_code >= 500:
                raise ValueError('Target returned a server error; assertions cannot be evaluated reliably.')
            try:
                body = response.json()
            except ValueError as error:
                raise ValueError('Target returned non-JSON content; verify the API target.') from error
            problems = check_response(case, response.status_code, body)
            # Whitelist report fields. Never serialize requests, raw bodies or headers.
            results.append({'name': case['name'], 'actor': case['actor'], 'expected_status': case['status'], 'actual_status': response.status_code, 'passed': not problems, 'problems': problems})
    return results


def write_report(report, output):
    output.mkdir(parents=True, exist_ok=True)
    (output / 'authorization.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    rows = ''.join(f"<tr><td>{html.escape(r['name'])}</td><td>{r['expected_status']}</td><td>{r['actual_status']}</td><td>{'PASS' if r['passed'] else 'FAIL'}</td><td>{html.escape(' '.join(r['problems']))}</td></tr>" for r in report['results'])
    page = f"""<!doctype html><html lang="en"><meta charset="utf-8"><title>SecureWallet authorization report</title>
    <style>body{{font:16px system-ui;margin:40px auto;padding:20px;max-width:1100px;color:#193c2b}}table{{border-collapse:collapse;width:100%}}td,th{{text-align:left;border-bottom:1px solid #ccd5c8;padding:14px}}th{{background:#edf3e9}}</style>
    <h1>Authorization regression report</h1><p>{html.escape(report['generated_at'])} · Outcome: {report['outcome']}</p>
    <p>Configured checks against seeded local resources. No passwords, cookies, reset tokens, or raw responses are stored.</p>
    <table><thead><tr><th>Rule</th><th>Expected HTTP</th><th>Actual HTTP</th><th>Result</th><th>Detail</th></tr></thead><tbody>{rows}</tbody></table>
    <p>{html.escape(report.get('setup_error', ''))}</p></html>"""
    (output / 'authorization.html').write_text(page, encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=Path(__file__).with_name('rules.json'))
    parser.add_argument('--output', type=Path, default=Path('docs/evidence/secure'))
    args = parser.parse_args()
    report = {'generated_at': datetime.now(timezone.utc).isoformat(), 'results': [], 'outcome': 'setup_error'}
    code = 2
    try:
        config = json.loads(args.config.read_text(encoding='utf-8'))
        password = os.environ.get(config['password_env'])
        if not password:
            raise ValueError('Set the configured password environment variable.')
        report['results'] = run(config, password)
        code = 0 if all(r['passed'] for r in report['results']) else 1
        report['outcome'] = 'passed' if code == 0 else 'failed'
    except (httpx.HTTPError, ValueError, KeyError, OSError):
        # Error objects can contain URLs/credentials. Emit a fixed diagnostic only.
        report['setup_error'] = 'Setup/connection error. Check configuration, running services, seed accounts, and the password environment variable.'
    write_report(report, args.output)
    print(f"{report['outcome']}: {len(report['results'])} configured rules evaluated. Report: {args.output / 'authorization.html'}")
    return code


if __name__ == '__main__':
    raise SystemExit(main())
