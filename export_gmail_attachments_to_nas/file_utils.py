import os
import re
import smbclient
from smbprotocol import exceptions as smb_exceptions
import pymupdf
from retry import retry
from .main import exit_event
from .logging_config import configure_logging

script_logger = configure_logging()

def sanitize_filename(filename):
    """
    Sanitize a filename by replacing invalid characters with underscores.
    
    Args:
        filename: The filename to sanitize
        
    Returns:
        A sanitized filename safe for use on filesystems
    """
    return re.sub(r'[<>:"/\\|?*\r\n ]', '_', filename)

def extract_email_address(sender):
    """
    Extract email address from sender string.
    
    Args:
        sender: Sender string in format 'Name <email@domain.com>' or 'email@domain.com'
        
    Returns:
        The extracted email address or the original sender string if no match
    """
    match = re.search(r'<(.+?)>', sender)
    if match:
        return match.group(1)
    return sender

def extract_text_from_pdf(file_data):
    """
    Extract text content from a PDF file.
    
    Args:
        file_data: Binary PDF file data
        
    Returns:
        Extracted text from all pages, or empty string on error
    """
    try:
        pdf_document = pymupdf.Document(stream=file_data, filetype="pdf")
        text = ""
        for page_num in range(pdf_document.page_count):
            if exit_event.is_set():
                break
            page = pdf_document.load_page(page_num)
            text += page.get_text()
        return text
    except Exception as e:
        script_logger.error(f"Error extracting text from PDF: {e}")
        return ""

@retry(tries=5, delay=2, backoff=2, exceptions=(Exception,))
def save_attachment(smb_server, smb_folder, filename, file_data, username, password, content_filters=None):
    """
    Save an email attachment to an SMB share with optional content filtering.
    
    Args:
        smb_server: SMB server hostname
        smb_folder: Target folder path on SMB share
        filename: Name of the file to save
        file_data: Binary file data
        username: SMB username
        password: SMB password
        content_filters: Optional list of strings to filter content (saves only if any filter matches)
        
    Raises:
        Exception: If there's an error saving the attachment (with retry logic)
    """
    try:
        smbclient.register_session(server=smb_server, username=username, password=password)
        smbclient.makedirs(smb_folder, exist_ok=True)

        if content_filters:
            if filename.lower().endswith('.pdf'):
                decoded_content = extract_text_from_pdf(file_data)
            else:
                decoded_content = file_data.decode('utf-8', errors='ignore')
            
            if not any(content_filter in decoded_content for content_filter in content_filters):
                script_logger.info(f"None of the content filters {content_filters} found in {filename}, skipping.")
                return
        
        file_path = os.path.join(smb_folder, filename)
        
        try:
            smbclient.stat(file_path)
            script_logger.info(f"File already exists, skipping: {filename}")
            return
        except smb_exceptions.SMBOSError:
            pass

        with smbclient.open_file(file_path, mode='wb') as file:
            file.write(file_data)
        script_logger.info(f"Saved attachment: {filename}")
    except Exception as e:
        script_logger.error(f"Error saving attachment: {e}")