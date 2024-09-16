import logging

def configure_logging():
    script_logger = logging.getLogger(__name__)
    if not script_logger.hasHandlers():
        script_logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        script_logger.addHandler(handler)

        # Set specific logging levels for each library
        logging.getLogger('googleapiclient.discovery_cache').setLevel(logging.ERROR)
        logging.getLogger('smbclient').setLevel(logging.WARNING)
        logging.getLogger('retry').setLevel(logging.ERROR)

    return script_logger