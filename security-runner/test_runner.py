import json
import pytest
from runner import validate_target, check_response, write_report
import runner


def test_rejects_external_targets_by_default():
    with pytest.raises(ValueError):
        validate_target({'base_url': 'https://example.com', 'cases': []})


def test_denial_status_cannot_hide_leaked_content():
    case = {'status': 404, 'absent_fields': ['ticket']}
    assert check_response(case, 404, {'ticket': {'subject': 'Private'}})


def test_success_status_cannot_hide_wrong_owner():
    assert check_response({'status': 200, 'field': 'ticket.user_id', 'equals': 'alice'}, 200, {'ticket': {'user_id': 'bob'}})


def test_nested_password_hash_is_rejected():
    assert check_response({'status': 200, 'forbidden_keys': ['password_hash']}, 200, {'items': [{'password_hash': 'secret'}]})


def test_html_escapes_untrusted_labels(tmp_path):
    report = {'generated_at': 'test', 'outcome': 'failed', 'results': [{'name': '<script>bad()</script>', 'expected_status': 403, 'actual_status': 200, 'passed': False, 'problems': []}]}
    write_report(report, tmp_path)
    assert '<script>' not in (tmp_path / 'authorization.html').read_text()
    assert json.loads((tmp_path / 'authorization.json').read_text())['outcome'] == 'failed'


def test_connection_error_has_distinct_exit_code_and_no_secret(tmp_path, monkeypatch):
    config = tmp_path / 'rules.json'
    config.write_text(json.dumps({'base_url': 'http://127.0.0.1:1', 'origin': 'http://127.0.0.1:1', 'password_env': 'RUNNER_TEST_PASSWORD', 'actors': {'alice': 'alice@example.test'}, 'cases': []}))
    monkeypatch.setenv('RUNNER_TEST_PASSWORD', 'sensitive-test-placeholder')
    monkeypatch.setattr('sys.argv', ['runner', '--config', str(config), '--output', str(tmp_path / 'report')])
    assert runner.main() == 2
    report = (tmp_path / 'report' / 'authorization.json').read_text()
    assert 'setup_error' in report
    assert 'sensitive-test-placeholder' not in report


def test_failed_assertion_returns_one(tmp_path, monkeypatch):
    config = tmp_path / 'rules.json'
    config.write_text(json.dumps({'password_env': 'RUNNER_TEST_PASSWORD'}))
    monkeypatch.setenv('RUNNER_TEST_PASSWORD', 'sensitive-test-placeholder')
    monkeypatch.setattr(runner, 'run', lambda *_: [{'name': 'Ownership', 'actor': 'bob', 'expected_status': 404, 'actual_status': 200, 'passed': False, 'problems': ['Protected content exposed.']}])
    monkeypatch.setattr('sys.argv', ['runner', '--config', str(config), '--output', str(tmp_path / 'report')])
    assert runner.main() == 1
    assert json.loads((tmp_path / 'report' / 'authorization.json').read_text())['outcome'] == 'failed'
