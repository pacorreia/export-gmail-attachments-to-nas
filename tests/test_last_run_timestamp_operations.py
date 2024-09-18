from unittest.mock import patch, mock_open
from datetime import datetime
import json
from export_gmail_attachments_to_nas.gmail_service import get_last_run_timestamp, update_last_run_timestamp

@patch('export_gmail_attachments_to_nas.gmail_service.script_logger')
def test_get_last_run_timestamp_valid(mock_logger):
    criteria_data = {'last_run': '2023-01-01T00:00:00'}
    timestamp = get_last_run_timestamp(criteria_data)
    assert timestamp == datetime.fromisoformat('2023-01-01T00:00:00')

@patch('export_gmail_attachments_to_nas.gmail_service.script_logger')
def test_get_last_run_timestamp_missing_last_run(mock_logger):
    criteria_data = {}
    timestamp = get_last_run_timestamp(criteria_data)
    assert timestamp == datetime.fromisoformat('2003-01-01T00:00:00')

@patch('export_gmail_attachments_to_nas.gmail_service.script_logger')
def test_get_last_run_timestamp_invalid_format(mock_logger):
    criteria_data = {'last_run': 'invalid-date'}
    timestamp = get_last_run_timestamp(criteria_data)
    assert timestamp == datetime.fromisoformat('2003-01-01T00:00:00')
    mock_logger.error.assert_called_once_with("Error reading last run timestamp: Invalid isoformat string: 'invalid-date'")

@patch('builtins.open', new_callable=mock_open)
def test_update_last_run_timestamp(mock_open):
    criteria_path = 'path/to/criteria.json'
    criteria_data = {}
    update_last_run_timestamp(criteria_path, criteria_data)
    assert 'last_run' in criteria_data
    mock_open.assert_called_once_with(criteria_path, 'w', encoding='utf-8')
    
    handle = mock_open()
    written_data = ''.join(call.args[0] for call in handle.write.call_args_list)
    written_json = json.loads(written_data)
    assert 'last_run' in written_json