from setuptools import setup, find_packages
from export_gmail_attachments_to_nas import __version__

setup(
    name='export-gmail-attachments-to-nas',
    version=__version__,
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'export-gmail-attachments-to-nas=export_gmail_attachments_to_nas.main:main',
        ],
    },
    install_requires=[
        'google-auth-oauthlib',
        'google-auth-httplib2',
        'google-api-python-client',
        'retry',
        'smbprotocol',
        'python-dateutil',
        'pymupdf',
        'PyInstaller',
    ],
    author='Paulo Correia',
    author_email='pcportugal@gmail.com',
    description='A package for extracting email attachments and saving them to a NAS server.',
    url='https://github.com/pacorreia/export-gmail-attachments-to-nas',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.12.6',
)