# Phishing Email Feature Engineering

A Python-based feature engineering system for phishing email detection. This tool extracts 70+ behavioral, structural, and content-based features from email data to support machine learning classification models.

## Overview

The `PhishingFeatureEngineer` class processes email datasets and extracts features across multiple categories including text analysis, URL inspection, sender verification, temporal patterns, and HTML structure analysis. The system is designed to identify phishing emails by analyzing suspicious patterns commonly found in malicious messages.

## Features Extracted

### Text Features (11 features)
- Character and word counts
- Average word length
- Uppercase, digit, and special character ratios
- Punctuation counts (exclamation marks, question marks, dollar signs)
- All-caps word detection
- Ellipsis usage

### Keyword Features (10 features)
The system detects five categories of phishing-related keywords:
- **Urgency words**: "act now", "limited time", "expires today", "final notice"
- **Reward words**: "you have won", "lottery", "jackpot", "claim your prize"
- **Threat words**: "account suspended", "unauthorized access", "security alert"
- **Financial words**: "bank account", "credit card", "wire transfer", "verify payment"
- **Action words**: "click here", "open attachment", "update your information"

### Erotic Content Features (7 features)
- Detection of adult/erotic terminology in subject and body
- Word counts and density metrics
- Separate tracking for subject vs. body

### URL Features (18 features)
- URL count and presence
- URL length statistics
- IP address detection
- Suspicious TLD identification (.ru, .cn, .tk, etc.)
- URL shortener detection (bit.ly, tinyurl, etc.)
- Subdomain analysis
- Special character detection (@, //, %)
- Hex encoding identification

### Sender Features (6 features)
- Display name analysis
- Domain verification
- Name/email mismatch detection
- Suspicious TLD in sender domain
- Local part length
- Numeric characters in domain

### Temporal Features (5 features)
- Hour of day
- Day of week
- Weekend detection
- Business hours classification
- Night-time sending patterns

### Subject Line Features (9 features)
- Length and word count
- RE:/FWD: detection
- All-caps detection
- Specific keyword presence ("urgent", "free")
- Exclamation mark count

### HTML Features (9 features)
- HTML tag detection and counting
- Form and input field presence
- Script and iframe detection
- Hidden element identification
- Image counting
- Suspicious link pattern detection

## Requirements
```python
pandas
numpy
```

## Installation

No installation required. Simply ensure the required packages are installed:
```bash
pip install pandas numpy --break-system-packages
```

## Usage

### Basic Usage
```python
import pandas as pd
from feature_engineer import PhishingFeatureEngineer

# Load your email dataset
df = pd.read_csv('your_email_data.csv')

# Initialize the feature engineer
fe = PhishingFeatureEngineer()

# Extract all features
features_df = fe.extract_all_features(df)

# Add original labels
features_df['label'] = df['label']

# Save the feature matrix
features_df.to_csv('phishing_features.csv', index=False)
```

### Feature Variance Analysis

The script includes a variance analysis function to identify low-quality features:
```python
from feature_engineer import analyze_feature_variance

# Analyze feature variance
variance_results = analyze_feature_variance(features_df)

# Drop zero-variance features if needed
features_clean = features_df.drop(columns=variance_results['zero_variance'])
```

## Input Data Format

The script expects a CSV file with the following columns:

- `subject`: Email subject line
- `body`: Email body text
- `sender`: Sender email address (format: "Display Name <email@domain.com>")
- `date`: Timestamp of the email
- `label`: Classification label (0 for legitimate, 1 for phishing)
- `urls`: Original URLs (optional, for reference)

## Output Format

The output CSV contains all extracted features plus the original label. Feature names are descriptive:

- `body_char_count`: Number of characters in email body
- `urgency_word_count`: Count of urgency-related keywords
- `has_suspicious_tld`: Binary flag for suspicious top-level domains
- `sender_name_email_mismatch`: Binary flag for sender spoofing attempts
- And 60+ additional features...

## Feature Customization

You can modify the keyword lists in the `__init__` method to adapt to your specific use case:
```python
fe = PhishingFeatureEngineer()
fe.urgency_words.append('your custom urgent phrase')
fe.suspicious_tlds.append('.custom')
```

## Performance

The feature extraction processes approximately 1,000 emails per progress update. Processing speed depends on:
- Email length
- Number of URLs per email
- System specifications

Expected processing time: ~1-5 seconds per 1,000 emails on modern hardware.

## Feature Quality Analysis

The variance analysis function categorizes features as:

- **Good variance**: >1% non-zero values (suitable for modeling)
- **Low variance**: <1% non-zero values (may need removal)
- **Zero variance**: All values identical (should be removed)

Features with zero or low variance provide little information for classification and can be safely removed before model training.

## Best Practices

1. **Data Quality**: Ensure your input CSV is properly formatted with all required columns
2. **Missing Data**: The script handles missing values gracefully, treating them as empty strings or zero values
3. **Feature Selection**: Use the variance analysis to identify and remove uninformative features
4. **Scaling**: Consider normalizing features before feeding them to machine learning models
5. **Keyword Updates**: Regularly update keyword lists to capture evolving phishing tactics

## Output Files

When running the example script:
- `phishing_features.csv`: Complete feature matrix with all extracted features
- `phishing_features_clean.csv`: Feature matrix with zero-variance features removed (if applicable)

## Troubleshooting

**Issue**: Date parsing errors
- **Solution**: The script attempts to handle various date formats. If errors persist, standardize date formats in your input data.

**Issue**: Memory errors with large datasets
- **Solution**: Process data in chunks using pandas `chunksize` parameter, or increase system RAM.

**Issue**: All features showing zero variance
- **Solution**: Verify your input data contains actual phishing examples with varied content.

## Future Enhancements

Potential areas for extension:
- Natural language processing features (TF-IDF, embeddings)
- Image analysis for attached files
- Header analysis (SPF, DKIM, DMARC)
- Reply-to address mismatches
- Attachment-based features
- Domain age lookup

## License

This code is provided as-is for educational and research purposes.

## Contributing

To contribute improvements:
1. Test new features on diverse email datasets
2. Ensure backward compatibility
3. Update keyword lists based on emerging threats
4. Add documentation for new features

## Acknowledgments

This feature engineering approach is based on common phishing detection methodologies found in cybersecurity research and industry best practices.
