from setuptools import setup, find_packages

setup(
    name='export-gmail-attachments-to-nas',
    version='1.0.0',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'email-extraction=main:main',
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
)