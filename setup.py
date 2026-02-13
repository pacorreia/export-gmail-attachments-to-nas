from setuptools import setup, find_packages
from pathlib import Path
from export_gmail_attachments_to_nas import __version__

# Read the contents of README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding='utf-8')

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
    ],
    extras_require={
        'dev': [
            'pytest>=9.0.0',
            'pytest-cov>=7.0.0',
            'build',
            'twine',
        ],
        'build': [
            'PyInstaller',
        ],
    },
    author='Paulo Correia',
    author_email='pcportugal@gmail.com',
    description='A package for extracting email attachments and saving them to a NAS server.',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/pacorreia/export-gmail-attachments-to-nas',
    project_urls={
        'Homepage': 'https://pacorreia.github.io/export-gmail-attachments-to-nas/',
        'Source': 'https://github.com/pacorreia/export-gmail-attachments-to-nas',
        'Bug Reports': 'https://github.com/pacorreia/export-gmail-attachments-to-nas/issues',
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Topic :: Communications :: Email',
        'Topic :: System :: Archiving',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.12',
        'Programming Language :: Python :: 3.13',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    keywords='gmail email attachments nas smb backup automation',
    python_requires='>=3.12',
)