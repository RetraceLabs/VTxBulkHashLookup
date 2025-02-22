# VTxBulkHashLookup - VirusTotal Hash Scanner

VTxBulkHashLookup (v.2.0) is a Python-based tool that checks file hashes against the VirusTotal database to identify potential threats. It supports **batch scanning** and exports structured results in **CSV**, **TXT**, and now **PDF** formats.

## Features

- **Bulk Hash Scanning** – Process multiple hashes at once.
- **VirusTotal API Integration** – Uses VirusTotal’s API to fetch scan results.
- **Hash Type Detection** – Automatically identifies **MD5**, **SHA-1**, and **SHA-256** hashes.
- **Structured Output** – Saves results in **CSV (comma-separated)**, **TXT (tab-separated)**, and **PDF (formatted)** formats.
- **Error Handling** – Gracefully handles missing hashes, API failures, and rate limits.

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/RetraceLabs/VTxBulkHashLookup.git
cd VTxBulkHashLookup
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure API Key

Edit `VTxBulkHashLookup.py` and replace `<YOUR API KEY>` with your **VirusTotal API key**.

## Usage

Run the script with an input file containing hashes, specifying output files for CSV, TXT, or PDF:

```bash
python VTxBulkHashLookup.py hash.txt -o results.csv -t results.txt -p results.pdf
```

### Command-line Arguments

| Argument | Description |
| --- | --- |
| `hash.txt` | Input file containing one hash per line |
| `-o results.csv` | Output CSV file for structured results |
| `-t results.txt` | Output TXT file for tabular format |
| `-p results.pdf` | Output PDF file for formatted results |

## Example

### Input (`hashes.txt`):

```bash
44d88612fea8a8f36de82e1278abb02f
99017f6eebbac24f351415dd410d522d
60747e80c3dece47b5c7dc3cfdcfe18abfd4cf12fe9b794749e068760dcb4847
```

### Execution:

```bash
python VTxBulkHashLookup.py hashes.txt -o scan_results.csv -t scan_results.txt -p scan_results.pdf
```

### CSV Output (`scan_results.csv`):

```mathematica
Link,Hash Type,File Name,File Type,Undetected,Detected_Suspicious,Detected_Malicious,Threat Label,Tags
https://www.virustotal.com/gui/file/44d88612fea8a8f36de82e1278abb02f,MD5,eicar.com,DOS Executable,50,2,5,Trojan,executable,testfile
https://www.virustotal.com/gui/file/99017f6eebbac24f351415dd410d522d,MD5,Unknown,Unknown,60,0,1,N/A,N/A
https://www.virustotal.com/gui/file/60747e80c3dece47b5c7dc3cfdcfe18abfd4cf12fe9b794749e068760dcb4847,SHA256,Unknown, DOS Executable, 40,0,31,N/A,peexe,upx,64bits,corrupt,overlay,executes-dropped-file,cve-2016-0101,exploit

```

### TXT Output (`scan_results.txt`):

```mathematica
Link                                            Hash Type    File Name   File Type   Undetected   Suspicious   Malicious   Threat Label       Tags
------------------------------------------------------------------------------------------------------------------------------
https://www.virustotal.com/gui/file/44d88612f   MD5         eicar.com   DOS Executable      50          2          5        Trojan      executable,testfile
https://www.virustotal.com/gui/file/99017f6e    MD5         Unknown     Unknown             60          0          1        N/A         N/A

```

### PDF Output (`scan_results.pdf`):

A well-structured **PDF report** containing tables with VirusTotal scan results for each hash. The PDF includes:

- **Hash**
- **Hash Type**
- **File Name**
- **File Type**
- **Undetected**
- **Suspicious**
- **Malicious**
- **Threat Label**
- **Tags**

## Notes & Limitations

- **VirusTotal API Key Required** – You must have a VirusTotal API key. Create a free account and use the API key.
- **Rate Limits Apply** – The free API has a maximum limit of **4 requests per minute**.
- **No File Uploading** – This tool only checks **existing hash records** on VirusTotal.

## References

- [Get a VirusTotal API Key](https://docs.virustotal.com/docs/please-give-me-an-api-key)
- [VirusTotal API Documentation](https://docs.virustotal.com/docs/api-overview)

## Roadmap

- Parsing:
    - Add more export formats:
        - ✅PDF (Added)
        - ✅JSON (Added)
    - Add more input and search options
- OCR:
    - Add OCR functionality to look up hashes directly from Threat Reports
- Report Generation:
    - Add infographic elements to better represent the data
    - Add summarization of the threats input to the tool
- Support Multiple API keys for faster results
- Support input of a folder with suspicious files, evaluate hashes, and perform the VT lookup

## Changelogs
- v0.1
    - Initial release of tool
- v0.2
    - Added PDF Export features and Improved Error Handling
- v0.3
    -Added JSON Export

## Contributions

**Note:** This tool is developed by [Akash Sinha](https://github.com/imakash-sinha) during their internship with Retrace Labs.  We're excited to continue development efforts and will be posting weekly updates with an updated roadmap.

Contributions are most welcome! Feel free to submit issues, feature requests, or pull requests.

---