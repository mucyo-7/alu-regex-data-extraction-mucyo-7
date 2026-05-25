* ALU Regex Data Extraction

* How to run
1. Navigate to src folder
2. Run: py main.py

 What it does
- Extracts emails, credit cards, URLs and phone numbers from raw text
- Validates ALU specific emails
- Detects and warns about malicious input
- Masks credit card numbers for security
- Saves results to output/sample-output.json

* Patterns used
- Email: matches username@domain.extension format
- Credit card: matches Visa, Mastercard and Amex formats
- URL: matches http and https links
- Phone: matches international and local formats