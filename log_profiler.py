import os
import re
from collections import Counter

# Regex patterns for basic data profiling
EMAIL_PATTERN = re.compile(r'[\w\.-]+@[\w\.-]+\.([a-zA-Z]{2,63})')
PHONE_PATTERN = re.compile(r'(?:\+|00)(\d{1,4})[\s-]?\d{6,14}')

def profile_file(file_path):
    """
    Analyzes a text file to identify top-level domains (TLDs) and phone number country codes.
    """
    tld_counter = Counter()
    cc_counter = Counter()
    total_lines = 0
    errors = 0

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                total_lines += 1
                
                # Check for email TLDs
                emails = EMAIL_PATTERN.findall(line)
                for tld in emails:
                    tld_counter[tld.lower()] += 1
                
                # Check for phone country codes
                phones = PHONE_PATTERN.findall(line)
                for cc in phones:
                    cc_counter[cc] += 1
                    
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return None

    return {
        "total_lines": total_lines,
        "tlds": tld_counter,
        "country_codes": cc_counter
    }

def analyze_directory(directory_path):
    """
    Scans the specified directory and profiles all text files found.
    """
    print(f"Starting analysis of directory: {directory_path}\n")
    
    for root, _, files in os.walk(directory_path):
        for file in files:
            if file.endswith('.txt') or file.endswith('.log'):
                file_path = os.path.join(root, file)
                print(f"Analyzing: {file_path}")
                
                results = profile_file(file_path)
                if not results or results["total_lines"] == 0:
                    print("  No text data or empty file.\n")
                    continue
                
                print(f"  Total lines processed: {results['total_lines']}")
                
                # Report Top domains
                if results["tlds"]:
                    print("  Top Email Domain Extensions (TLDs):")
                    for tld, count in results["tlds"].most_common(5):
                        print(f"    - .{tld}: {count}")
                else:
                    print("  No email patterns detected.")
                    
                # Report Top country codes
                if results["country_codes"]:
                    print("  Top Phone Country Codes:")
                    for cc, count in results["country_codes"].most_common(5):
                        # Add helpful mappings for common codes
                        country_label = ""
                        if cc == "91":
                            country_label = " (India)"
                        elif cc == "1":
                            country_label = " (US/Canada)"
                        elif cc == "44":
                            country_label = " (UK)"
                        
                        print(f"    - +{cc}{country_label}: {count}")
                else:
                    print("  No international phone patterns detected.")
                print("-" * 50)

if __name__ == "__main__":
    # Specify the target directory to analyze
    target_dir = r"c:\Downloads\logs\database"
    analyze_directory(target_dir)
