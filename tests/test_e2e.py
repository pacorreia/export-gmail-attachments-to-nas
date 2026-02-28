"""
End-to-end tests that mock a Gmail account with emails and attachments,
and a NAS SMB share, then run a configured instance of the app to verify
that attachments are correctly processed and saved.

External dependencies (Gmail API, smbclient) are replaced with fakes;
all internal application logic runs without additional patching.
"""
import base64
import contextlib
import threading
from datetime import datetime
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from unittest.mock import MagicMock, patch

from smbprotocol import exceptions as smb_exceptions
from smbprotocol.header import NtStatus

from export_gmail_attachments_to_nas.gmail_service import process_emails


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_raw_email(subject, sender, date_str, attachments):
    """Return a base64url-encoded raw email string (as returned by the Gmail API).

    Args:
        subject:     Email subject line.
        sender:      Sender in 'Name <email@example.com>' format.
        date_str:    RFC 2822 date string, e.g. 'Mon, 15 Jan 2024 10:30:00 +0000'.
        attachments: List of (filename, bytes) pairs to attach.

    Returns:
        str – base64url-encoded message bytes, ready for the 'raw' field.
    """
    msg = MIMEMultipart()
    msg['Subject'] = subject
    msg['From'] = sender
    msg['Date'] = date_str
    msg.attach(MIMEText('Test email body.', 'plain'))

    for filename, data in attachments:
        part = MIMEBase('application', 'octet-stream')
        part.set_payload(data)
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', 'attachment', filename=filename)
        msg.attach(part)

    return base64.urlsafe_b64encode(msg.as_bytes()).decode('ASCII')


def _make_gmail_service(raw_emails_by_id):
    """Build a Gmail API service mock.

    Args:
        raw_emails_by_id: dict mapping message-ID str → raw email str.

    Returns:
        MagicMock that behaves like a Gmail API service object.
    """
    service = MagicMock()

    # list() returns all message IDs with no pagination
    service.users.return_value.messages.return_value.list.return_value.execute.return_value = {
        'messages': [{'id': mid} for mid in raw_emails_by_id],
    }

    # get() returns the raw email keyed by the 'id' kwarg
    def _mock_get(**kwargs):
        msg_id = kwargs['id']
        result = MagicMock()
        result.execute.return_value = {'raw': raw_emails_by_id[msg_id]}
        return result

    service.users.return_value.messages.return_value.get.side_effect = _mock_get
    return service


def _smb_patches(saved_files):
    """Return a context manager that patches all smbclient calls to simulate a NAS share.

    Written file data is stored in the *saved_files* dict keyed by file path.

    Args:
        saved_files: mutable dict that will be populated with {path: bytes} entries.

    Returns:
        contextlib.ExitStack – enter it with ``with _smb_patches(saved_files):``.
    """
    class _MockFileHandle:
        def __init__(self, path):
            self._path = path

        def write(self, data):
            saved_files[self._path] = data

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    stack = contextlib.ExitStack()
    stack.enter_context(patch('export_gmail_attachments_to_nas.file_utils.smbclient.register_session'))
    stack.enter_context(patch('export_gmail_attachments_to_nas.file_utils.smbclient.makedirs'))
    # stat() raising SMBOSError(STATUS_OBJECT_NAME_NOT_FOUND) signals the file does
    # not yet exist, so save_attachment proceeds to write it.
    stack.enter_context(patch(
        'export_gmail_attachments_to_nas.file_utils.smbclient.stat',
        side_effect=smb_exceptions.SMBOSError(NtStatus.STATUS_OBJECT_NAME_NOT_FOUND, 'file'),
    ))
    stack.enter_context(patch(
        'export_gmail_attachments_to_nas.file_utils.smbclient.open_file',
        side_effect=lambda path, mode='rb': _MockFileHandle(path),
    ))
    return stack


def _filenames(saved_files):
    """Return just the base filenames from the paths in *saved_files*."""
    return [p.split('/')[-1] if '/' in p else p.split('\\')[-1] for p in saved_files]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_e2e_single_pdf_attachment_saved_to_nas():
    """E2E: one email with a PDF attachment is saved to the NAS share."""
    attachment_data = b'%PDF-1.4 fake pdf content'
    raw_email = _build_raw_email(
        subject='Invoice',
        sender='Alice <alice@example.com>',
        date_str='Mon, 15 Jan 2024 10:30:00 +0000',
        attachments=[('invoice.pdf', attachment_data)],
    )

    mock_service = _make_gmail_service({'msg1': raw_email})
    saved_files = {}

    criteria_data = {
        'smb_server': 'nas-server',
        'criteria': [{
            'enabled': True,
            'query': 'has:attachment',
            'smb_folder': 'TestShare',
            'filters': ['.pdf'],
        }],
    }

    with _smb_patches(saved_files):
        process_emails(
            mock_service,
            datetime(2024, 1, 1),
            'nasuser', 'naspass',
            criteria_data,
            threading.Event(),
        )

    assert len(saved_files) == 1
    saved_path, saved_data = next(iter(saved_files.items()))
    assert 'invoice.pdf' in saved_path
    assert '2024' in saved_path
    assert saved_data == attachment_data


def test_e2e_multiple_emails_all_attachments_saved():
    """E2E: multiple emails with attachments are all saved to the NAS share."""
    attachments = {
        'msg1': ('report.pdf', b'%PDF report'),
        'msg2': ('summary.pdf', b'%PDF summary'),
    }
    raw_emails = {
        mid: _build_raw_email(
            subject=f'Subject {mid}',
            sender=f'Sender <sender{mid}@example.com>',
            date_str='Tue, 20 Feb 2024 09:00:00 +0000',
            attachments=[(fname, data)],
        )
        for mid, (fname, data) in attachments.items()
    }

    mock_service = _make_gmail_service(raw_emails)
    saved_files = {}

    criteria_data = {
        'smb_server': 'nas-server',
        'criteria': [{
            'enabled': True,
            'query': 'has:attachment',
            'smb_folder': 'Docs',
            'filters': ['.pdf'],
        }],
    }

    with _smb_patches(saved_files):
        process_emails(
            mock_service,
            datetime(2024, 1, 1),
            'nasuser', 'naspass',
            criteria_data,
            threading.Event(),
        )

    assert len(saved_files) == 2
    saved_names = _filenames(saved_files)
    assert 'report.pdf' in saved_names
    assert 'summary.pdf' in saved_names


def test_e2e_attachment_skipped_when_filter_not_matched():
    """E2E: an attachment whose extension does not match the filter is not saved."""
    raw_email = _build_raw_email(
        subject='Notes',
        sender='Bob <bob@example.com>',
        date_str='Wed, 10 Apr 2024 08:00:00 +0000',
        attachments=[('notes.txt', b'plain text content')],
    )

    mock_service = _make_gmail_service({'msg1': raw_email})
    saved_files = {}

    criteria_data = {
        'smb_server': 'nas-server',
        'criteria': [{
            'enabled': True,
            'query': 'has:attachment',
            'smb_folder': 'OnlyPDFs',
            'filters': ['.pdf'],       # .txt should be ignored
        }],
    }

    with _smb_patches(saved_files):
        process_emails(
            mock_service,
            datetime(2024, 1, 1),
            'nasuser', 'naspass',
            criteria_data,
            threading.Event(),
        )

    assert len(saved_files) == 0


def test_e2e_attachment_skipped_when_content_filter_not_matched():
    """E2E: a PDF whose text does not match the content filter is not saved."""
    raw_email = _build_raw_email(
        subject='Contract',
        sender='Carol <carol@example.com>',
        date_str='Thu, 25 Jul 2024 14:00:00 +0000',
        attachments=[('contract.pdf', b'%PDF-1.4 fake pdf')],
    )

    mock_service = _make_gmail_service({'msg1': raw_email})
    saved_files = {}

    criteria_data = {
        'smb_server': 'nas-server',
        'criteria': [{
            'enabled': True,
            'query': 'has:attachment',
            'smb_folder': 'Contracts',
            'filters': ['.pdf'],
            'attachment_content_filter': ['CONFIDENTIAL'],  # won't match
        }],
    }

    with _smb_patches(saved_files), \
         patch('export_gmail_attachments_to_nas.file_utils.extract_text_from_pdf',
               return_value='This document does not contain the keyword.'):
        process_emails(
            mock_service,
            datetime(2024, 1, 1),
            'nasuser', 'naspass',
            criteria_data,
            threading.Event(),
        )

    assert len(saved_files) == 0


def test_e2e_convert_pdf_to_png_saved_to_output_folder():
    """E2E: PDF attachment is saved and also converted to PNG pages in the output folder."""
    attachment_data = b'%PDF-1.4 fake pdf content'
    raw_email = _build_raw_email(
        subject='Report',
        sender='Dave <dave@example.com>',
        date_str='Fri, 05 Apr 2024 11:00:00 +0000',
        attachments=[('report.pdf', attachment_data)],
    )

    mock_service = _make_gmail_service({'msg1': raw_email})
    saved_files = {}

    criteria_data = {
        'smb_server': 'nas-server',
        'criteria': [{
            'enabled': True,
            'query': 'has:attachment',
            'smb_folder': 'Originals',
            'filters': ['.pdf'],
            'convert': {
                'to': 'png',
                'output_folder': 'ConvertedPNGs',
            },
        }],
    }

    fake_png_pages = [
        ('report_page1.png', b'\x89PNG\r\n\x1a\npage1'),
        ('report_page2.png', b'\x89PNG\r\n\x1a\npage2'),
    ]

    with _smb_patches(saved_files), \
         patch('export_gmail_attachments_to_nas.gmail_service.convert_attachment',
               return_value=fake_png_pages):
        process_emails(
            mock_service,
            datetime(2024, 1, 1),
            'nasuser', 'naspass',
            criteria_data,
            threading.Event(),
        )

    saved_names = _filenames(saved_files)
    assert 'report.pdf' in saved_names
    assert 'report_page1.png' in saved_names
    assert 'report_page2.png' in saved_names
    # Converted pages must land in the convert output folder, not the originals folder
    for path in saved_files:
        if path.endswith('.png'):
            assert 'ConvertedPNGs' in path
        if path.endswith('.pdf'):
            assert 'Originals' in path


def test_e2e_convert_pdf_to_jpg_saved_to_output_folder():
    """E2E: PDF attachment is saved and also converted to JPG pages in the output folder."""
    attachment_data = b'%PDF-1.4 fake pdf content'
    raw_email = _build_raw_email(
        subject='Photos',
        sender='Eve <eve@example.com>',
        date_str='Sat, 06 Apr 2024 12:00:00 +0000',
        attachments=[('photos.pdf', attachment_data)],
    )

    mock_service = _make_gmail_service({'msg1': raw_email})
    saved_files = {}

    criteria_data = {
        'smb_server': 'nas-server',
        'criteria': [{
            'enabled': True,
            'query': 'has:attachment',
            'smb_folder': 'Originals',
            'filters': ['.pdf'],
            'convert': {
                'to': 'jpg',
                'output_folder': 'ConvertedJPGs',
            },
        }],
    }

    fake_jpg_pages = [('photos_page1.jpg', b'\xff\xd8\xff\xe0page1')]

    with _smb_patches(saved_files), \
         patch('export_gmail_attachments_to_nas.gmail_service.convert_attachment',
               return_value=fake_jpg_pages):
        process_emails(
            mock_service,
            datetime(2024, 1, 1),
            'nasuser', 'naspass',
            criteria_data,
            threading.Event(),
        )

    saved_names = _filenames(saved_files)
    assert 'photos.pdf' in saved_names
    assert 'photos_page1.jpg' in saved_names
    for path in saved_files:
        if path.endswith('.jpg'):
            assert 'ConvertedJPGs' in path
        if path.endswith('.pdf'):
            assert 'Originals' in path


def test_e2e_convert_skipped_when_extension_filter_not_matched():
    """E2E: convert is skipped when extension_filter excludes the attachment type."""
    attachment_data = b'%PDF-1.4 fake pdf content'
    raw_email = _build_raw_email(
        subject='Spec',
        sender='Frank <frank@example.com>',
        date_str='Sun, 07 Apr 2024 08:00:00 +0000',
        attachments=[('spec.pdf', attachment_data)],
    )

    mock_service = _make_gmail_service({'msg1': raw_email})
    saved_files = {}

    criteria_data = {
        'smb_server': 'nas-server',
        'criteria': [{
            'enabled': True,
            'query': 'has:attachment',
            'smb_folder': 'Originals',
            'filters': ['.pdf'],
            'convert': {
                'to': 'png',
                'output_folder': 'ConvertedPNGs',
                'extension_filter': ['.docx'],  # .pdf does not match -> no conversion
            },
        }],
    }

    mock_convert = MagicMock(return_value=[('spec_page1.png', b'\x89PNG')])

    with _smb_patches(saved_files), \
         patch('export_gmail_attachments_to_nas.gmail_service.convert_attachment', mock_convert):
        process_emails(
            mock_service,
            datetime(2024, 1, 1),
            'nasuser', 'naspass',
            criteria_data,
            threading.Event(),
        )

    # Original PDF must be saved; conversion must not have run
    saved_names = _filenames(saved_files)
    assert 'spec.pdf' in saved_names
    assert 'spec_page1.png' not in saved_names
    mock_convert.assert_not_called()


def test_e2e_convert_skipped_when_filename_filter_not_matched():
    """E2E: convert is skipped when filename_filter regex does not match the attachment name."""
    attachment_data = b'%PDF-1.4 fake pdf content'
    raw_email = _build_raw_email(
        subject='Receipt',
        sender='Grace <grace@example.com>',
        date_str='Mon, 08 Apr 2024 09:00:00 +0000',
        attachments=[('receipt.pdf', attachment_data)],
    )

    mock_service = _make_gmail_service({'msg1': raw_email})
    saved_files = {}

    criteria_data = {
        'smb_server': 'nas-server',
        'criteria': [{
            'enabled': True,
            'query': 'has:attachment',
            'smb_folder': 'Originals',
            'filters': ['.pdf'],
            'convert': {
                'to': 'png',
                'output_folder': 'ConvertedPNGs',
                'filename_filter': r'invoice.*',  # 'receipt.pdf' does not match -> no conversion
            },
        }],
    }

    mock_convert = MagicMock(return_value=[('receipt_page1.png', b'\x89PNG')])

    with _smb_patches(saved_files), \
         patch('export_gmail_attachments_to_nas.gmail_service.convert_attachment', mock_convert):
        process_emails(
            mock_service,
            datetime(2024, 1, 1),
            'nasuser', 'naspass',
            criteria_data,
            threading.Event(),
        )

    saved_names = _filenames(saved_files)
    assert 'receipt.pdf' in saved_names
    assert 'receipt_page1.png' not in saved_names
    mock_convert.assert_not_called()
