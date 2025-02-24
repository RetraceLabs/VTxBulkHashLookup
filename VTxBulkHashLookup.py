import requests
import json
import time
import argparse
import csv
import hashlib
import sys
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

# Your VirusTotal API Key 
API_KEY = "YOUR_API_KEY"

def show_banner():
    print("""
==========================================================================================================================================
   :::     ::: ::::::::::: :::    ::: :::::::::  :::    ::: :::        :::    ::: :::    :::     :::      ::::::::  :::    ::: 
  :+:     :+:     :+:     :+:    :+: :+:    :+: :+:    :+: :+:        :+:   :+:  :+:    :+:   :+: :+:   :+:    :+: :+:    :+: 
  +:+     +:+     +:+      +:+  +:+  +:+    +:+ +:+    +:+ +:+        +:+  +:+   +:+    +:+  +:+   +:+  +:+        +:+    +:+ 
  +#+     +:+     +#+       +#++:+   +#++:++#+  +#+    +:+ +#+        +#++:++    +#++:++#++ +#++:++#++: +#++:++#++ +#++:++#++ 
  +#+   +#+      +#+      +#+  +#+  +#+    +#+ +#+    +#+ +#+        +#+  +#+   +#+    +#+ +#+     +#+        +#+ +#+    +#+ 
   #+#+#+#       #+#     #+#    #+# #+#    #+# #+#    #+# #+#        #+#   #+#  #+#    #+# #+#     #+# #+#    #+# #+#    #+# 
     ###         ###     ###    ### #########   ########  ########## ###    ### ###    ### ###     ###  ########  ###    ### 
:::        ::::::::   ::::::::  :::    ::: :::    ::: :::::::::                                                             
:+:       :+:    :+: :+:    :+: :+:   :+:  :+:    :+: :+:    :+:                                                            
+:+       +:+    +:+ +:+    +:+ +:+  +:+   +:+    +:+ +:+    +:+                                                            
+#+       +#+    +:+ +#+    +:+ +#++:++    +#+    +:+ +#++:++#+                                                             
+#+       +#+    +#+ +#+    +#+ +#+  +#+   +#+    +#+ +#+                                                                   
#+#       #+#    #+# #+#    #+# #+#   #+#  #+#    #+# #+#                                                                   
########## ########   ########  ###    ###  ########  ###                                                                   
==========================================================================================================================================
    VTxBulkHashLookup - Version 2.0
    Developed by: N3xU$_3e1Ng (imakash-sinha)
    Maintained by: Retrace Labs
==========================================================================================================================================
    """)

def detect_hash_type(hash_value):
    hash_length = len(hash_value)
    if hash_length == 32:
        return "MD5"
    elif hash_length == 40:
        return "SHA1"
    elif hash_length == 64:
        return "SHA256"
    else:
        return "Unknown"

def check_virustotal(hash_value):
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=30)
        if response.status_code == 404:
            return [hash_value, detect_hash_type(hash_value), f"https://www.virustotal.com/gui/file/{hash_value}", "Not Found", "N/A", 0, 0, 0, "N/A", "N/A"]
        elif response.status_code == 200:
            data = response.json().get("data", {}).get("attributes", {})
            file_name = data.get("names", ["Unknown"])[0]
            file_type = data.get("type_description", "Unknown")
            undetected = data.get("last_analysis_stats", {}).get("undetected", 0)
            suspicious = data.get("last_analysis_stats", {}).get("suspicious", 0)
            malicious = data.get("last_analysis_stats", {}).get("malicious", 0)
            threat_label = data.get("popular_threat_classification", {}).get("suggested_threat_label", "N/A")
            tags = ", ".join(data.get("tags", [])) or "None"
            return [hash_value, detect_hash_type(hash_value), f"https://www.virustotal.com/gui/file/{hash_value}", file_name, file_type, undetected, suspicious, malicious, threat_label, tags]
        else:
            return [hash_value, detect_hash_type(hash_value), "Error", "Error", "Error", "Error", "Error", "Error", "Error", "Error"]
    except requests.exceptions.RequestException as e:
        print(f"Error fetching data for {hash_value}: {e}")
        return [hash_value, detect_hash_type(hash_value), "Error", "Error", "Error", "Error", "Error", "Error", "Error", "Error"]

def export_to_txt(data, output_txt):
    with open(output_txt, mode="w") as file:
        file.write("Hash\tHash Type\tVirusTotal Link\tFile Name\tFile Type\tUndetected\tSuspicious\tMalicious\tThreat Label\tTags\n")
        for row in data:
            file.write("\t".join(map(str, row)) + "\n")
    print(f"TXT report saved: {output_txt}")

def export_to_csv(data, output_csv):
    with open(output_csv, mode="w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Hash", "Hash Type", "VirusTotal Link", "File Name", "File Type", "Undetected", "Suspicious", "Malicious", "Threat Label", "Tags"])
        writer.writerows(data)
    print(f"[*]CSV report saved: {output_csv}")

def export_to_pdf(data, output_pdf):
    doc = SimpleDocTemplate(output_pdf, pagesize=A4)
    elements = []
    styles = getSampleStyleSheet()
    title = Paragraph("VirusTotal Hash Analysis Report", styles['Title'])
    elements.append(title)
    elements.append(Spacer(1, 12))

    for row in data:
        hash_value, hash_type, vt_link, file_name, file_type, undetected, suspicious, malicious, threat_label, tags = row

        table_data = [
            ["Field", "Value"],
            ["Hash", hash_value],
            ["Hash Type", hash_type],
            ["VirusTotal Link", vt_link],
            ["File Name", file_name],
            ["File Type", file_type],
            ["Undetected", undetected],
            ["Suspicious", suspicious],
            ["Malicious", malicious],
            ["Threat Label", threat_label],
            ["Tags", tags]
        ]

        table = Table(table_data, colWidths=[150, 350])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))

        elements.append(table)
        elements.append(Spacer(1, 12))  # Space between tables

    doc.build(elements)
    print(f"PDF report saved: {output_pdf}")

def show_usage():
    print("\nUsage: python VTxBulkHashLookup.py <input_file> -o <output_csv> -t <output_txt> -p <output_pdf>")
    print("\nParameters:")
    print("  <input_file>    - File containing hashes (one per line)")
    print("  -o <output_csv> - CSV output file")
    print("  -t <output_txt> - TXT output file")
    print("  -p <output_pdf> - PDF output file")
    print("  -j <output_json> - JSON output file")
    print("\nExample:")
    print("  python VTxBulkHashLookup.py hashes.txt -o results.csv -t results.txt -p results.pdf\n")
    sys.exit(1)

def export_to_json(data, output_json):
    json_results = []

    for item in data:
        hash_value, hash_type, vt_link, file_name, file_type, undetected, suspicious, malicious, threat_label, tags = item
        json_entry = {
            "Hash": hash_value,
            "Hash Type": hash_type,
            "VirusTotal Link": vt_link,
            "File Name": file_name,
            "File Type": file_type,
            "Undetected": undetected,
            "Suspicious": suspicious,
            "Malicious": malicious,
            "Threat Label": threat_label,
            "Tags": tags
        }
        json_results.append(json_entry)

    with open(output_json, "w") as json_file:
        json.dump(json_results, json_file, indent=4)

    print(f"[*] JSON report saved: {output_json}")


def main():
    show_banner()
    parser = argparse.ArgumentParser(description="VTxBulkHashLookup - VirusTotal Bulk Hash Analyzer")
    parser.add_argument("input_file", help="File containing hashes (one per line)")
    parser.add_argument("-o", "--output_csv", help="CSV output file", required=False)
    parser.add_argument("-t", "--output_txt", help="TXT output file", required=False)
    parser.add_argument("-p", "--output_pdf", help="PDF output file", required=False)
    parser.add_argument("-j", "--output_json",help="JSON output file", required =False)

    args = parser.parse_args()

    if not any([args.output_csv, args.output_txt, args.output_pdf, args.output_json]):
        show_usage()

    try:
        with open(args.input_file, "r") as file:
            hashes = [line.strip() for line in file if line.strip()]

        if not hashes:
            print("[!] Error: No valid hashes found in input file.")
            return

        results = []
        for hash_value in hashes:
            print(f"[!] Checking hash: {hash_value}")
            results.append(check_virustotal(hash_value))
            time.sleep(15)  


        if args.output_csv:
            export_to_csv(results, args.output_csv)

        if args.output_txt:
            export_to_txt(results, args.output_txt)

        if args.output_pdf:
            export_to_pdf(results, args.output_pdf)
        
        if args.output_json:
            export_to_json(results, args.output_json)

        print("[*] Report generation completed.")

    except FileNotFoundError:
        print(f"[!] Error: Input file '{args.input_file}' not found.")
        show_usage()

if __name__ == "__main__":
    main()

