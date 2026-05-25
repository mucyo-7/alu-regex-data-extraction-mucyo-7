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
  * Limitations

some emails slipped through validatiion and here is why:

1. fake@alumni.alueducation (missing .com)
   - Why it slipped: the pattern accepts any 
     text after the dot, so "alueducation" 
     alone was treated as a valid extension
   - Fix would be: strictly require .com at the end

2. student@.alueducation.com (dot right after @)
   - Why it slipped: the pattern allows dots 
     in domain names, so it did not catch 
     the dot appearing immediately after @
   - Fix would be: add a rule that says no dot 
     can appear immediately after the @ symbol

