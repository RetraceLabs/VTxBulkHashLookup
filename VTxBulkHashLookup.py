import requests
import json
import time
import argparse
import os


API_KEY = "<YOUR API KEY>"

def detect_hash_type(hash_str):
    length = len(hash_str)
    if length == 32:
        return "MD5"
    elif length == 40:
        return "SHA-1"
    elif length == 64:
        return "SHA-256"
    else:
        return "Unknown"

def check_hashes(input_file, csv_output, txt_output):

    with open(input_file, "r") as hashes, open(csv_output, "w") as csv_file, open(txt_output, "w") as txt_file:
    
        header = "Link,Hash Type,File Name,File Type,Undetected,Detected_Suspicious,Detected_Malicious,Threat Label,Tags\n"
        csv_file.write(header)
        txt_file.write(header.replace(",", "\t"))  

        for hashn in hashes:
            hashn = hashn.strip()
            if not hashn:
                continue

            hash_type = detect_hash_type(hashn)
            print(f'Checking {hash_type} hash: {hashn}')

            url = f"https://www.virustotal.com/api/v3/files/{hashn}"
            vt_link = f"https://www.virustotal.com/gui/file/{hashn}"
            
            headers = {
                "accept": "application/json",
                "x-apikey": API_KEY
            }

            try:
                response = requests.get(url, headers=headers, timeout=120)

                if response.status_code == 404:
                    csv_file.write(f"{vt_link},{hash_type},Not Found in VirusTotal Database\n")
                    txt_file.write(f"{vt_link}\t{hash_type}\tNot Found in VirusTotal Database\n")
                elif response.status_code == 200:
                    result = response.json()
                    attributes = result.get('data', {}).get('attributes', {})

                    file_name = attributes.get('names', ['Unknown'])[0]
                    file_type = attributes.get('type_description', 'Unknown')
                    undetected = attributes.get('last_analysis_stats', {}).get('undetected', 0)
                    suspicious = attributes.get('last_analysis_stats', {}).get('suspicious', 0)
                    malicious = attributes.get('last_analysis_stats', {}).get('malicious', 0)
                    threat_label = attributes.get('popular_threat_classification', {}).get('suggested_threat_label', 'N/A')
                    tags = ','.join(attributes.get('tags', []))

                    csv_line = f"{vt_link},{hash_type},{file_name},{file_type},{undetected},{suspicious},{malicious},{threat_label},{tags}\n"
                    txt_line = csv_line.replace(",", "\t")  
                    csv_file.write(csv_line)
                    txt_file.write(txt_line)

            except requests.exceptions.RequestException as e:
                print(f"Error checking {hash_type} hash {hashn}: {e}")

            time.sleep(20)  


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VTxBulkHashLookup - VirusTotal Bulk Hash Lookup Tool")
    parser.add_argument("input_file", help="Input file containing hashes (one per line)")
    parser.add_argument("-o", "--output_csv", required=True, help="Output CSV file")
    parser.add_argument("-t", "--output_txt", required=True, help="Output TXT file")
    
    args = parser.parse_args()

    if not os.path.exists(args.input_file):
        print(f"Error: Input file '{args.input_file}' not found.")
        exit(1)

    
    check_hashes(args.input_file, args.output_csv, args.output_txt)
