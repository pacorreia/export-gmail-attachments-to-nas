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
    return re.sub(r'[<>:"/\\|?*\r\n ]', '_', filename)

def extract_email_address(sender):
    match = re.search(r'<(.+?)>', sender)
    if match:
        return match.group(1)
    return sender

def extract_text_from_pdf(file_data):
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