from unittest.mock import patch, MagicMock
from export_gmail_attachments_to_nas.gmail_service import authenticate_gmail

@patch('export_gmail_attachments_to_nas.gmail_service.build')
@patch('export_gmail_attachments_to_nas.gmail_service.Credentials.from_authorized_user_file')
@patch('export_gmail_attachments_to_nas.gmail_service.InstalledAppFlow.from_client_secrets_file')
@patch('export_gmail_attachments_to_nas.gmail_service.os.path.exists')
def test_authenticate_gmail(mock_path_exists, mock_from_client_secrets_file, mock_from_authorized_user_file, mock_build):
    mock_creds = MagicMock()
    mock_from_authorized_user_file.return_value = mock_creds
    mock_build.return_value = MagicMock()
    
    # Mock the behavior of os.path.exists
    mock_path_exists.side_effect = lambda x: x == 'token.json'

    credential_path = 'path/to/credentials.json'
    service = authenticate_gmail(credential_path)

    mock_from_authorized_user_file.assert_called_once_with('token.json', ['https://mail.google.com/'])
    mock_build.assert_called_once_with('gmail', 'v1', credentials=mock_creds)
    assert service is not None
    
@patch('export_gmail_attachments_to_nas.gmail_service.build')
@patch('export_gmail_attachments_to_nas.gmail_service.Credentials')
@patch('export_gmail_attachments_to_nas.gmail_service.InstalledAppFlow')
@patch('export_gmail_attachments_to_nas.gmail_service.os.path.exists')
def test_creds_none(mock_path_exists, mock_installed_app_flow, mock_credentials, mock_build):
    # Mock creds to be None
    mock_credentials.from_authorized_user_file.return_value = None

    # Mock the flow
    mock_flow = MagicMock()
    mock_installed_app_flow.from_client_secrets_file.return_value = mock_flow
    mock_creds = MagicMock()
    mock_creds.to_json.return_value = '{"token": "fake_token"}'
    mock_flow.run_local_server.return_value = mock_creds

    # Mock the behavior of os.path.exists
    mock_path_exists.side_effect = lambda x: x == 'token.json'

    credential_path = 'path/to/credentials.json'
    authenticate_gmail(credential_path)

    # Check if the flow was run
    mock_installed_app_flow.from_client_secrets_file.assert_called_once()
    mock_flow.run_local_server.assert_called_once()
    
@patch('export_gmail_attachments_to_nas.gmail_service.build')
@patch('export_gmail_attachments_to_nas.gmail_service.Credentials')
@patch('export_gmail_attachments_to_nas.gmail_service.InstalledAppFlow')
@patch('export_gmail_attachments_to_nas.gmail_service.os.path.exists')
def test_creds_not_valid(mock_path_exists, mock_installed_app_flow, mock_credentials, mock_build):
    # Mock creds to be invalid
    mock_creds = MagicMock()
    mock_creds.valid = False
    mock_creds.to_json.return_value = '{"token": "fake_token"}'  # Ensure to_json returns a valid JSON string
    mock_credentials.from_authorized_user_file.return_value = mock_creds

    # Mock the flow
    mock_flow = MagicMock()
    mock_installed_app_flow.from_client_secrets_file.return_value = mock_flow
    mock_flow.run_local_server.return_value = mock_creds

    # Mock the behavior of os.path.exists
    mock_path_exists.side_effect = lambda x: False  # Ensure it returns False for 'token.json'

    credential_path = 'path/to/credentials.json'
    authenticate_gmail(credential_path)

    # Check if the flow was run
    mock_installed_app_flow.from_client_secrets_file.assert_called_once()
    mock_flow.run_local_server.assert_called_once()

@patch('export_gmail_attachments_to_nas.gmail_service.build')
@patch('export_gmail_attachments_to_nas.gmail_service.Credentials')
@patch('export_gmail_attachments_to_nas.gmail_service.InstalledAppFlow')
@patch('export_gmail_attachments_to_nas.gmail_service.os.path.exists')
def test_creds_expired_with_refresh_token(mock_path_exists, mock_installed_app_flow, mock_credentials, mock_build):
    # Mock creds to be expired with a refresh token
    mock_creds = MagicMock()
    mock_creds.valid = False
    mock_creds.expired = True
    mock_creds.refresh_token = 'fake_refresh_token'
    mock_creds.to_json.return_value = '{"token": "fake_token"}'  # Ensure to_json returns a valid JSON string
    mock_credentials.from_authorized_user_file.return_value = mock_creds

    # Mock the behavior of os.path.exists
    mock_path_exists.side_effect = lambda x: x == 'token.json'

    credential_path = 'path/to/credentials.json'
    authenticate_gmail(credential_path)

    # Check if creds were refreshed
    mock_creds.refresh.assert_called_once()

@patch('export_gmail_attachments_to_nas.gmail_service.build')
@patch('export_gmail_attachments_to_nas.gmail_service.Credentials')
@patch('export_gmail_attachments_to_nas.gmail_service.InstalledAppFlow')
@patch('export_gmail_attachments_to_nas.gmail_service.os.path.exists')
def test_creds_expired_without_refresh_token(mock_path_exists, mock_installed_app_flow, mock_credentials, mock_build):
    # Mock creds to be expired without a refresh token
    mock_creds = MagicMock()
    mock_creds.valid = False
    mock_creds.expired = True
    mock_creds.refresh_token = None
    mock_creds.to_json.return_value = '{"token": "fake_token"}'  # Ensure to_json returns a valid JSON string
    mock_credentials.from_authorized_user_file.return_value = mock_creds

    # Mock the flow
    mock_flow = MagicMock()
    mock_installed_app_flow.from_client_secrets_file.return_value = mock_flow
    mock_flow.run_local_server.return_value = mock_creds

    # Mock the behavior of os.path.exists
    mock_path_exists.side_effect = lambda x: x == 'token.json'

    credential_path = 'path/to/credentials.json'
    authenticate_gmail(credential_path)

    # Check if the flow was run
    mock_installed_app_flow.from_client_secrets_file.assert_called_once()
    mock_flow.run_local_server.assert_called_once()