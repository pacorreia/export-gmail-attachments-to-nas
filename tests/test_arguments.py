import pytest
import sys
from unittest.mock import patch
from export_gmail_attachments_to_nas.main import parse_arguments

def test_argument_handling():
    test_args = [
        'main.py',
        '--username', 'testuser',
        '--password', 'testpass',
        '--credentials', 'path/to/credentials.json',
        '--criteria', 'path/to/criteria.json'
    ]

    with patch.object(sys, 'argv', test_args):
        args = parse_arguments()
        assert args.username == 'testuser'
        assert args.password == 'testpass'
        assert args.credentials == 'path/to/credentials.json'
        assert args.criteria == 'path/to/criteria.json'

def test_argument_handling_missing_required():
    test_args = [
        'main.py',
        '--username', 'testuser',
        '--password', 'testpass',
        '--credentials', 'path/to/credentials.json'
        # Missing --criteria
    ]

    with patch.object(sys, 'argv', test_args):
        with pytest.raises(SystemExit):
            parse_arguments()