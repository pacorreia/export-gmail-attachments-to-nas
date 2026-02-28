# Email Attachment Extraction

## Description

`email-extraction` is a Python package for extracting email attachments and saving them to a NAS server. This package leverages various Google APIs and other libraries to facilitate the extraction and storage process.

## Installation

To install the package, clone the repository and install the dependencies:

```bash
# Clone the repository
git clone https://github.com/pacorreia/email-extraction.git

# Navigate to the project directory
cd email-extraction

# Install dependencies
pip install -r requirements.txt

# Build the package
python -m build

# Install the package
pip install .
```

## Usage

To use the package, you can run the command line script provided:

`email-extraction`

This will execute the main function defined in the main module.

### Criteria options

Each rule in `criteria.json` can control whether the source email is deleted after a successful save:

```json
{
	"enabled": true,
	"query": "subject:Invoice filename:.pdf",
	"smb_folder": "\\documents\\faturas",
	"filters": [".pdf"],
	"delete_after_save": false
}
```

#### Convert option

Each rule can optionally include a `convert` section to automatically convert saved attachments to another format and store the result in a separate output folder.

Supported conversions:
- PDF → `txt` (text extraction)
- PDF → `png` (one image per page)
- PDF → `jpeg` / `jpg` (one image per page)

Optional selectors control which attachments are converted:
- `extension_filter`: list of file extensions — only attachments whose extension matches will be converted.
- `filename_filter`: a regular expression — only attachments whose filename matches (case-insensitive) will be converted.

```json
{
	"enabled": true,
	"query": "subject:Invoice filename:.pdf",
	"smb_folder": "\\documents\\faturas",
	"filters": [".pdf"],
	"delete_after_save": false,
	"convert": {
		"to": "txt",
		"output_folder": "\\documents\\converted",
		"extension_filter": [".pdf"],
		"filename_filter": "invoice.*"
	}
}
```

| Field | Required | Description |
|---|---|---|
| `to` | ✅ | Target format: `txt`, `png`, `jpeg`, or `jpg` |
| `output_folder` | ✅ | SMB folder path where converted files are saved |
| `extension_filter` | ❌ | Restrict conversion to attachments with these extensions |
| `filename_filter` | ❌ | Restrict conversion to filenames matching this regex |

## Dependencies

This project requires the following Python packages:

* `google-auth-oauthlib`
* `google-auth-httplib2`
* `google-api-python-client`
* `retry`
* `smbprotocol`
* `python-dateutil`
* `pymupdf`
* `PyInstaller`

These dependencies are listed in the [setup.py](./setup.py) file and will be installed automatically when you install the package.

## Contributing

If you would like to contribute to this project, please follow these steps:

1. Fork the repository.
2. Create a new branch (git checkout -b feature-branch).
3. Make your changes.
4. Commit your changes (git commit -m 'Add some feature').
5. Push to the branch (git push origin feature-branch).
6. Open a pull request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

* Paulo Correia - Initial work - [pcportugal@gmail.com](mailto:pcportugal@gmail.com)

## Acknowledgements

* Thanks to the developers of the libraries used in this project.
* Special thanks to the open-source community for their contributions.