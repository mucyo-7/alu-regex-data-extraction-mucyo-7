import re
import json

# Read the input file the one that will be checked for patterns.
with open("../input/raw-text.txt", "r") as file:
    text = file.read()

# Security check detect malicious or wrong input
def is_safe(text):
    dangerous = [
        r'<script.*?>',
        r'DROP\s+TABLE',
        r'OR\s+1=1',
        r'SELECT\s+\*'
    ]
    for pattern in dangerous:
        if re.search(pattern, text, re.IGNORECASE):
            print("WARNING: Suspicious input detected!")
            return False
    return True

is_safe(text)

# 1. EMAIL detection method/pattern
email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
all_emails = re.findall(email_pattern, text)

# ALU specific email validation
alu_pattern = r'[a-zA-Z0-9._%+-]+@alueducation\.com'
alumni_pattern = r'[a-zA-Z0-9._%+-]+@alumni\.alueducation\.com'
si_pattern = r'[a-zA-Z0-9._%+-]+@si\.alueducation\.com'

alu_emails = re.findall(alu_pattern, text)
alumni_emails = re.findall(alumni_pattern, text)
si_emails = re.findall(si_pattern, text)

# 2. CREDIT CARD detection method/pattern
card_pattern = r'\b(?:4[0-9]{3}|5[1-5][0-9]{2}|3[47][0-9]{2}|6011)[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{3,4}\b'
cards = re.findall(card_pattern, text)

# Mask credit cards for security (show only last 4 digits)
masked_cards = []
for card in cards:
    digits = re.sub(r'[\s-]', '', card)
    masked = '**** **** **** ' + digits[-4:]
    masked_cards.append(masked)

# 3. URL PATTERN
url_pattern = r'https?://[a-zA-Z0-9./_@-]+'
urls = re.findall(url_pattern, text)

# 4. PHONE PATTERN
phone_pattern = r'\+?[\d]{1,3}[\s\-.]?\(?[\d]{3}\)?[\s\-.]?[\d]{3}[\s\-.]?[\d]{3,4}'
phones = re.findall(phone_pattern, text)

# Build output
output = {
    "emails": {
        "all_emails": all_emails,
        "alu_official": alu_emails,
        "alu_alumni": alumni_emails,
        "alu_si": si_emails
    },
    "credit_cards": masked_cards,
    "urls": urls,
    "phones": phones
}

# Print results
print(json.dumps(output, indent=4))

# Save to output file
with open("../output/sample-output.json", "w") as f:
    json.dump(output, f, indent=4)

print("\nResults saved to output/sample-output.json")