import email
import re
from urllib.parse import urlparse
from difflib import SequenceMatcher
import pandas as pd
from sklearn.metrics import confusion_matrix

# Hardcoded array of legitimate domains
phishing_terms = [
    "urgent business assistance",
    "confidential",
    "trapped funds",
    "inflated sum",
    "share the money",
    r"100% safe",
    "repatriate the money",
    "confiscate",
    "personal attorney",
    "lost their lives",
    "car accident",
    "financial assistance",
    "inheritance",
    "money laundering",
    "transfer funds",
    "business proposal",
    "investment opportunity",
    "risk-free",
    "guarantee",
    "immediate action required",
    "urgent response needed"
]


legitimate_domains = [
    "google.com",
    "proton.me",
    "example.com",
    "mybank.com",
    "yahoo.com",
    "outlook.com",
    "gmail.com",
    "apple.com",
    "amazon.com",
    "microsoft.com"
]


def contains_phishing_terms(email_body):
    return any(term.lower() in email_body.lower() for term in phishing_terms)

def is_suspicious_domain(email, legitimate_domains):
    domain = email.split('@')[-1]
    for legit_domain in legitimate_domains:
        ratio = SequenceMatcher(None, domain, legit_domain).ratio()
        if ratio > 0.8:
            return True
    return False

def is_suspicious_sender_email(sender_email):
    suspicious_patterns = [
        r'[0-9]',  # Contains numbers in suspicious places
        r'-',      # Hyphens in unexpected places
        r'[^\w.-]', # Non-alphanumeric characters
        r'(.*)(login|verify|secure|support)(.*)\.com'  # Suspicious subdomains or extra words
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, sender_email):
            return True
    return False

def contains_legal_jargon(email_body):
    legal_terms = [
        "court order", "alleged", "investigation", "criminal", "cybercrime", "forensic",
        "data extraction", "legal action", "respond", "notice"
    ]
    return any(term in email_body.lower() for term in legal_terms)

def contains_urgent_language(email_body):
    urgent_phrases = [ 
        "act now", "limited time", "important", "hurry", "quickly", "soon", 
        "serious legal action", "respond within 24 hours", "immediate action required",
        "urgent", "failure to respond", "important notice", "last warning"
    ]
    return any(phrase in email_body.lower() for phrase in urgent_phrases)

def contains_promotional_content(email_body):
    promotional_phrases = [
        "save your money", "buy now", "limited offer", "discount", 
        "free", "trial", "offer"
    ]
    return any(phrase in email_body.lower() for phrase in promotional_phrases)


def clean_url(url):
    # Remove unwanted characters from the URL
    return url.strip('[]')  # Example cleaning, adjust as necessary

def has_mismatched_urls(email_body, sender_domain):
    urls = re.findall(r'https?://[^\s]+', email_body)
    for url in urls:
        cleaned_url = clean_url(url)
        try:
            extracted = urlparse(cleaned_url)
            if extracted.netloc != sender_domain:
                return True
        except ValueError:
            print(f"Invalid URL encountered: {cleaned_url}")  # Log invalid URLs
            continue
    return False

def has_malicious_attachments(attachments):
    malicious_extensions = ['.exe', '.zip', '.scr', '.bat', '.js', '.rar', '.7z']
    return any(attachment.lower().endswith(ext) for ext in malicious_extensions for attachment in attachments)

def contains_spam_keywords(email_body):
    spam_keywords = [
        "free", "buy now", "limited time", "act now", 
        "click here", "guaranteed", "winner"
    ]
    return any(keyword in email_body.lower() for keyword in spam_keywords)

def has_excessive_punctuation(email_body):
    return len(re.findall(r'[!?.]{2,}', email_body)) > 0

def has_long_sentences(email_body):
    sentences = re.split(r'[.!?]', email_body)
    return any(len(sentence.split()) > 30 for sentence in sentences)

def parse_eml_file(file_path):
    with open(file_path, 'r') as file:
        message = email.message_from_file(file)
    
    sender_email = message['From']
    email_body = ''
    attachments = []

    if message.is_multipart():
        for part in message.walk():
            if part.get_content_type() == 'text/plain':
                email_body = part.get_payload(decode=True).decode('utf-8')
            elif part.get_content_maintype() == 'application':
                attachments.append(part.get_filename())
    else:
        email_body = message.get_payload(decode=True).decode('utf-8')

    return sender_email, email_body, attachments

def evaluate_email(sender_email, email_body, attachments):
    score = 0
    sender_domain = sender_email.split('@')[-1]

    if is_suspicious_domain(sender_email, legitimate_domains):
        score += 1
    if is_suspicious_sender_email(sender_email):
        score += 1
    if contains_urgent_language(email_body):
        score += 1
    if contains_legal_jargon(email_body):
        score += 1
    if contains_promotional_content(email_body):
        score += 1
    if contains_phishing_terms(email_body):
        score += 1
    if has_mismatched_urls(email_body, sender_domain):
        score += 1
    if has_malicious_attachments(attachments):
        score += 1
    if contains_spam_keywords(email_body):
        score += 1
    if has_excessive_punctuation(email_body):
        score += 1
    if has_long_sentences(email_body):
        score += 1

    return score



def main():
    print("1. Check an EML file")
    print("2. Benchmark")
    choice = int(input("Enter your choice (1 or 2): "))

    if choice == 1:
        filename = str(input("Enter file name with .eml extension: "))
        file_path = filename

        sender_email, email_body, attachments = parse_eml_file(file_path)
        score = evaluate_email(sender_email, email_body, attachments)

        if score >= 4:  # Set threshold for flagging as phishing
            print("This email is likely a phishing attempt.")
        else:
            print("This email seems safe.")
    elif choice == 2:
        # Load dataset
        filename = str(input("Enter file name with .csv extension: "))  # Corrected to .csv
        dt = pd.read_csv(filename)

        # Print the first few rows to understand the structure
        print("Dataset preview:")
        print(dt.head())

        # Remove rows with NaN in 'body' or 'label' columns
        dt = dt.dropna(subset=['body', 'label'])

        # Initialize lists for true and predicted labels
        y_true = []
        y_pred = []

        # Evaluate emails in the dataset
        for index, row in dt.iterrows():
            sender = row['sender'] if pd.notna(row['sender']) else "unknown@example.com"  # Use a dummy value
            body = row['body']
            label = row['label']

            # Debugging information
            print(f"Processing row {index}: sender={sender}, label={label}")

            # Check if sender is valid
            if isinstance(sender, str) and sender:  # Ensure sender is a string and not empty
                score = evaluate_email(sender, body, [])
                if isinstance(label, str):
                    y_true.append(1 if label.strip().lower() == 'phishing' else 0)
                elif isinstance(label, (int, float)):
                    y_true.append(int(label))
                else:
                    print(f"Skipping row with invalid label at index {index}: {label}")
                    continue
                y_pred.append(score >= 4)
            else:
                print(f"Skipping row with invalid sender at index {index}: {sender}")
                continue

        # Check if y_true and y_pred are not empty before calculating confusion matrix
        if len(y_true) > 0 and len(y_pred) > 0:
            tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
            # Calculate metrics
            tpr = tp / (tp + fn) if (tp + fn) > 0 else 0
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
            tnr = tn / (tn + fp) if (tn + fp) > 0 else 0
            fnr = fn / (tp + fn) if (tp + fn) > 0 else 0
            accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0

            print("Confusion Matrix:")
            print("TN:", tn, "FP:", fp)
            print("FN:", fn, "TP:", tp)
            print("\nMetrics:")
            print(f"TPR (Recall): {tpr:.2f}")
            print(f"FPR: {fpr:.2f}")
            print(f"TNR (Specificity): {tnr:.2f}")
            print(f"FNR: {fnr:.2f}")
            print(f"Accuracy: {accuracy:.2f}")
        else:
            print("No valid predictions were made. Unable to calculate confusion matrix.")
    else:
        print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
