import pandas as pd
import numpy as np
import re
from urllib.parse import urlparse
from datetime import datetime
from collections import Counter

class PhishingFeatureEngineer:
    """Feature engineering for phishing email detection."""
    
    def __init__(self):
        # Expanded urgency words
        self.urgency_words = [
            'act now', 'act fast', 'act immediately',
            'action required', 'response required', 'attention required',
            'urgent action', 'immediate action', 'immediate response',
            'limited time offer', 'limited time only',
            'offer expires', 'expiring soon', 'expires today',
            'final notice', 'last chance', 'last warning',
            'dont delay', "don't delay", 'do not delay',
            'before its too late', "before it's too late",
            'within 24 hours', 'within 48 hours',
            'must be completed', 'must respond',
            'time sensitive', 'respond immediately'
        ]
        
        # TRIMMED reward words - spam-specific
        self.reward_words = [
            'you have won', 'youve won', "you've won", 'you won',
            'winner', 'winning notification',
            'lottery', 'lotto', 'jackpot', 'sweepstakes',
            'prize winner', 'claim your prize', 'collect your prize',
            'million dollars', 'million pounds', 'million euros',
            'cash prize', 'cash reward', 'cash bonus',
            'free gift', 'free money', 'free offer',
            'gift card', 'gift certificate',
            'no purchase necessary',
            'inheritance fund', 'next of kin', 'beneficiary',
            'unclaimed funds', 'dormant account', 'fund transfer',
            'risk free', 'guaranteed winner', '100% free'
        ]
        
        # TRIMMED threat words - specific to phishing
        self.threat_words = [
            'account suspended', 'account locked', 'account disabled',
            'account terminated', 'account closed', 'account restricted',
            'will be suspended', 'will be locked', 'will be terminated',
            'has been compromised', 'has been hacked', 'has been breached',
            'unauthorized access', 'unauthorized activity', 'unauthorized transaction',
            'unusual activity', 'suspicious activity', 'suspicious login',
            'security alert', 'security warning', 'security breach',
            'verify your account', 'verify your identity', 'verify immediately',
            'confirm your identity', 'confirm your account',
            'failure to verify', 'failure to confirm', 'failure to respond',
            'legal action', 'legal consequences',
            'permanently deleted', 'permanently disabled',
            'your account will be', 'your access will be'
        ]
        
        # TRIMMED financial words - specific to phishing
        self.financial_words = [
            'bank account', 'banking details', 'account details',
            'credit card number', 'card number', 'card details',
            'social security number', 'ssn',
            'wire transfer', 'money transfer', 'fund transfer',
            'western union', 'moneygram',
            'verify your account', 'update your account', 'confirm your account',
            'verify payment', 'update payment', 'confirm payment',
            'billing information', 'payment information', 'payment details',
            'enter your password', 'enter your pin', 'enter your credentials',
            'login credentials', 'account credentials',
            'paypal account', 'ebay account',
            'refund pending', 'refund available', 'tax refund',
            'overdue payment', 'outstanding balance', 'past due'
        ]
        
        # TRIMMED action words - specific phishing phrases
        self.action_words = [
            'click here', 'click below', 'click the link below',
            'click this link', 'follow this link', 'visit this link',
            'open attachment', 'open the attachment', 'see attachment',
            'download attachment', 'view attachment',
            'log into your account', 'login to your account', 'sign into your account',
            'update your information', 'update your details', 'update your profile',
            'verify your information', 'verify your details', 'confirm your details',
            'fill out the form', 'complete the form', 'submit the form',
            'enter your details', 'provide your details',
            'click here to verify', 'click here to confirm', 'click here to update'
        ]
        
        # Erotic/adult words - keep as is (these are specific)
        self.erotic_words = [
            'sex', 'sexy', 'sexual', 'nude', 'naked', 'porn', 'xxx',
            'adult content', 'erotic', 'horny', 'hot girls', 'hot women',
            'hookup', 'affair', 'discreet relationship',
            'viagra', 'cialis', 'enlargement', 'enhancement', 'erectile',
            'webcam', 'cam girl', 'escort', 'stripper',
            'orgasm', 'aroused', 'libido',
            'lover', 'lust', 'seductive',
            'explicit', 'uncensored'
        ]
        
        # Suspicious TLDs
        self.suspicious_tlds = [
            '.ru', '.cn', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.top',
            '.xyz', '.work', '.click', '.link', '.info', '.biz', '.cc', '.ws',
            '.su', '.ua', '.kz', '.by', '.in', '.br', '.ph', '.de'
        ]
        
        # URL shorteners
        self.url_shorteners = [
            'bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
            'buff.ly', 'adf.ly', 'bit.do', 'mcaf.ee', 'shorte.st',
            'tiny.cc', 'lnkd.in', 'db.tt', 'qr.ae', 'cur.lv'
        ]
        
        # Legitimate domains (for comparison)
        self.legitimate_domains = [
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'facebook.com', 'twitter.com', 'linkedin.com', 'github.com',
            'cnn.com', 'bbc.com', 'nytimes.com', 'yahoo.com'
        ]

    def extract_urls(self, text):
        """Extract all URLs from text."""
        if pd.isna(text):
            return []
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        return re.findall(url_pattern, str(text), re.IGNORECASE)
    
    def extract_email_domain(self, email):
        """Extract domain from email address."""
        if pd.isna(email):
            return ''
        match = re.search(r'@([\w.-]+)', str(email))
        return match.group(1).lower() if match else ''
    
    def extract_display_name(self, sender):
        """Extract display name from sender field."""
        if pd.isna(sender):
            return ''
        match = re.match(r'^([^<]+)', str(sender))
        return match.group(1).strip() if match else ''

    # ==================== TEXT FEATURES ====================
    
    def text_length_features(self, text):
        """Extract length-based features from text."""
        if pd.isna(text):
            return {'body_char_count': 0, 'body_word_count': 0, 'body_avg_word_length': 0}
        
        text = str(text)
        words = text.split()
        
        return {
            'body_char_count': len(text),
            'body_word_count': len(words),
            'body_avg_word_length': np.mean([len(w) for w in words]) if words else 0
        }
    
    def text_style_features(self, text):
        """Extract style-based features."""
        if pd.isna(text):
            return {
                'body_uppercase_ratio': 0, 'body_digit_ratio': 0, 'body_special_char_ratio': 0,
                'body_exclamation_count': 0, 'body_question_count': 0, 'body_dollar_count': 0,
                'body_ellipsis_count': 0, 'body_all_caps_word_count': 0
            }
        
        text = str(text)
        alpha_chars = sum(c.isalpha() for c in text)
        
        return {
            'body_uppercase_ratio': sum(c.isupper() for c in text) / max(alpha_chars, 1),
            'body_digit_ratio': sum(c.isdigit() for c in text) / max(len(text), 1),
            'body_special_char_ratio': sum(not c.isalnum() and not c.isspace() for c in text) / max(len(text), 1),
            'body_exclamation_count': text.count('!'),
            'body_question_count': text.count('?'),
            'body_dollar_count': text.count('$'),
            'body_ellipsis_count': text.count('...'),
            'body_all_caps_word_count': sum(1 for w in text.split() if w.isupper() and len(w) > 1)
        }
    
    def keyword_features(self, text):
        """Count phishing-related keywords."""
        if pd.isna(text):
            return {
                'urgency_word_count': 0, 'reward_word_count': 0,
                'threat_word_count': 0, 'financial_word_count': 0,
                'action_word_count': 0, 'total_phishing_keywords': 0,
                'has_urgency_words': 0, 'has_reward_words': 0,
                'has_threat_words': 0, 'has_financial_words': 0
            }
        
        text_lower = str(text).lower()
        
        urgency = sum(1 for w in self.urgency_words if w in text_lower)
        reward = sum(1 for w in self.reward_words if w in text_lower)
        threat = sum(1 for w in self.threat_words if w in text_lower)
        financial = sum(1 for w in self.financial_words if w in text_lower)
        action = sum(1 for w in self.action_words if w in text_lower)
        
        return {
            'urgency_word_count': urgency,
            'reward_word_count': reward,
            'threat_word_count': threat,
            'financial_word_count': financial,
            'action_word_count': action,
            'total_phishing_keywords': urgency + reward + threat + financial + action,
            'has_urgency_words': int(urgency > 0),
            'has_reward_words': int(reward > 0),
            'has_threat_words': int(threat > 0),
            'has_financial_words': int(financial > 0)
        }

    # ==================== EROTIC WORD FEATURES ====================
    
    def erotic_word_features(self, subject, body):
        """Count erotic/adult words in subject and body."""
        subject_lower = str(subject).lower() if not pd.isna(subject) else ''
        body_lower = str(body).lower() if not pd.isna(body) else ''
        
        subject_erotic_count = sum(1 for w in self.erotic_words if w in subject_lower)
        body_erotic_count = sum(1 for w in self.erotic_words if w in body_lower)
        
        combined_text = subject_lower + ' ' + body_lower
        total_erotic_count = sum(1 for w in self.erotic_words if w in combined_text)
        
        body_words = len(body_lower.split()) if body_lower else 0
        erotic_density = (body_erotic_count / max(body_words, 1)) * 100
        
        return {
            'subject_erotic_word_count': subject_erotic_count,
            'body_erotic_word_count': body_erotic_count,
            'total_erotic_word_count': total_erotic_count,
            'has_erotic_words_subject': int(subject_erotic_count > 0),
            'has_erotic_words_body': int(body_erotic_count > 0),
            'has_erotic_words': int(total_erotic_count > 0),
            'erotic_word_density': erotic_density
        }

    # ==================== URL FEATURES ====================
    
    def url_count_features(self, text):
        """Count and analyze URLs in text."""
        urls = self.extract_urls(text)
        
        return {
            'url_count': len(urls),
            'has_urls': int(len(urls) > 0),
            'multiple_urls': int(len(urls) > 1)
        }
    
    def url_structure_features(self, text):
        """Analyze URL structure."""
        urls = self.extract_urls(text)
        
        if not urls:
            return {
                'avg_url_length': 0, 'max_url_length': 0,
                'has_ip_address_url': 0, 'has_port_in_url': 0,
                'has_suspicious_tld': 0, 'has_url_shortener': 0,
                'suspicious_tld_count': 0, 'url_shortener_count': 0,
                'avg_subdomain_count': 0, 'has_long_subdomain': 0,
                'has_at_symbol_in_url': 0, 'has_double_slash_redirect': 0,
                'has_hex_encoding': 0, 'total_url_dots': 0
            }
        
        features = {
            'avg_url_length': np.mean([len(u) for u in urls]),
            'max_url_length': max(len(u) for u in urls),
            'has_ip_address_url': 0,
            'has_port_in_url': 0,
            'has_suspicious_tld': 0,
            'has_url_shortener': 0,
            'suspicious_tld_count': 0,
            'url_shortener_count': 0,
            'avg_subdomain_count': 0,
            'has_long_subdomain': 0,
            'has_at_symbol_in_url': 0,
            'has_double_slash_redirect': 0,
            'has_hex_encoding': 0,
            'total_url_dots': 0
        }
        
        subdomain_counts = []
        
        for url in urls:
            url_lower = url.lower()
            
            if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
                features['has_ip_address_url'] = 1
            
            if re.search(r':\d{2,5}/', url):
                features['has_port_in_url'] = 1
            
            for tld in self.suspicious_tlds:
                if tld in url_lower:
                    features['has_suspicious_tld'] = 1
                    features['suspicious_tld_count'] += 1
            
            for shortener in self.url_shorteners:
                if shortener in url_lower:
                    features['has_url_shortener'] = 1
                    features['url_shortener_count'] += 1
            
            try:
                parsed = urlparse(url)
                hostname = parsed.netloc
                subdomain_count = hostname.count('.') - 1
                subdomain_counts.append(max(0, subdomain_count))
                
                parts = hostname.split('.')
                if any(len(p) > 20 for p in parts):
                    features['has_long_subdomain'] = 1
            except:
                pass
            
            if '@' in url:
                features['has_at_symbol_in_url'] = 1
            
            if '//' in url[8:]:
                features['has_double_slash_redirect'] = 1
            
            if '%' in url:
                features['has_hex_encoding'] = 1
            
            features['total_url_dots'] += url.count('.')
        
        features['avg_subdomain_count'] = np.mean(subdomain_counts) if subdomain_counts else 0
        
        return features

    # ==================== SENDER FEATURES ====================
    
    def sender_features(self, sender):
        """Extract features from sender field."""
        if pd.isna(sender):
            return {
                'sender_has_display_name': 0, 'sender_name_email_mismatch': 0,
                'sender_domain_length': 0, 'sender_has_numbers_in_domain': 0,
                'sender_has_suspicious_tld': 0, 'sender_local_part_length': 0
            }
        
        sender = str(sender)
        display_name = self.extract_display_name(sender)
        domain = self.extract_email_domain(sender)
        
        match = re.search(r'<([^@]+)@', sender)
        local_part = match.group(1) if match else ''
        
        mismatch = 0
        if display_name and domain:
            for legit in self.legitimate_domains:
                if legit.split('.')[0] in display_name.lower() and legit.split('.')[0] not in domain:
                    mismatch = 1
                    break
        
        return {
            'sender_has_display_name': int(bool(display_name)),
            'sender_name_email_mismatch': mismatch,
            'sender_domain_length': len(domain),
            'sender_has_numbers_in_domain': int(bool(re.search(r'\d', domain))),
            'sender_has_suspicious_tld': int(any(tld in domain for tld in self.suspicious_tlds)),
            'sender_local_part_length': len(local_part)
        }

    # ==================== TEMPORAL FEATURES ====================
    
    def temporal_features(self, date_str):
        """Extract temporal features from date."""
        if pd.isna(date_str):
            return {
                'hour_of_day': -1, 'day_of_week': -1, 'is_weekend': 0,
                'is_business_hours': 0, 'is_night': 0
            }
        
        try:
            date_str = str(date_str)
            date_str = re.sub(r'\s+\([A-Z]{3,4}\)\s*$', '', date_str)
            
            dt = pd.to_datetime(date_str)
            
            hour = dt.hour
            dow = dt.dayofweek
            
            return {
                'hour_of_day': hour,
                'day_of_week': dow,
                'is_weekend': int(dow >= 5),
                'is_business_hours': int(9 <= hour <= 17 and dow < 5),
                'is_night': int(hour < 6 or hour > 22)
            }
        except:
            return {
                'hour_of_day': -1, 'day_of_week': -1, 'is_weekend': 0,
                'is_business_hours': 0, 'is_night': 0
            }

    # ==================== SUBJECT-SPECIFIC FEATURES ====================
    
    def subject_features(self, subject):
        """Extract features specific to email subject."""
        if pd.isna(subject):
            return {
                'subject_length': 0, 'subject_word_count': 0,
                'subject_has_re': 0, 'subject_has_fwd': 0,
                'subject_all_caps': 0, 'subject_starts_caps': 0,
                'subject_has_urgent': 0, 'subject_has_free': 0,
                'subject_exclamation_count': 0
            }
        
        subject = str(subject)
        words = subject.split()
        
        # Check if subject is all caps (at least 3 characters, majority uppercase)
        alpha_chars = [c for c in subject if c.isalpha()]
        all_caps = 0
        if len(alpha_chars) >= 3:
            upper_ratio = sum(1 for c in alpha_chars if c.isupper()) / len(alpha_chars)
            all_caps = int(upper_ratio > 0.8)
        
        # Check if subject starts with caps (first 3+ words are uppercase)
        starts_caps = 0
        if len(words) >= 2:
            first_words = ' '.join(words[:3])
            first_alpha = [c for c in first_words if c.isalpha()]
            if len(first_alpha) >= 3:
                starts_caps = int(sum(1 for c in first_alpha if c.isupper()) / len(first_alpha) > 0.8)
        
        return {
            'subject_length': len(subject),
            'subject_word_count': len(words),
            'subject_has_re': int(subject.lower().startswith('re:')),
            'subject_has_fwd': int('fwd:' in subject.lower() or 'fw:' in subject.lower()),
            'subject_all_caps': all_caps,
            'subject_starts_caps': starts_caps,
            'subject_has_urgent': int('urgent' in subject.lower()),
            'subject_has_free': int('free' in subject.lower()),
            'subject_exclamation_count': subject.count('!')
        }

    # ==================== HTML FEATURES ====================
    
    def html_features(self, body):
        """Extract HTML-related features."""
        if pd.isna(body):
            return {
                'has_html': 0, 'html_tag_count': 0, 'has_form_tag': 0,
                'has_input_tag': 0, 'has_script_tag': 0, 'has_iframe': 0,
                'has_hidden_elements': 0, 'image_count': 0,
                'link_text_mismatch_indicator': 0
            }
        
        body = str(body)
        body_lower = body.lower()
        
        # More comprehensive HTML detection
        html_indicators = ['<html', '<body', '<div', '<table', '<tr', '<td', 
                          '<span', '<p>', '<br', '<a href', '<img']
        has_html = int(any(tag in body_lower for tag in html_indicators))
        
        return {
            'has_html': has_html,
            'html_tag_count': len(re.findall(r'<[^>]+>', body)),
            'has_form_tag': int('<form' in body_lower),
            'has_input_tag': int('<input' in body_lower),
            'has_script_tag': int('<script' in body_lower),
            'has_iframe': int('<iframe' in body_lower),
            'has_hidden_elements': int('display:none' in body_lower or 'visibility:hidden' in body_lower or 'hidden' in body_lower),
            'image_count': len(re.findall(r'<img', body_lower)),
            'link_text_mismatch_indicator': int(bool(re.search(r'<a[^>]*href=["\'][^"\']*["\'][^>]*>[^<]*(?:click|here|link)[^<]*</a>', body_lower)))
        }

    # ==================== MAIN FEATURE EXTRACTION ====================
    
    def extract_all_features(self, df):
        """Extract all features from dataframe."""
        print("Extracting features...")
        
        all_features = []
        total_rows = len(df)
        
        for idx, row in df.iterrows():
            features = {}
            
            full_text = f"{row.get('subject', '')} {row.get('body', '')}"
            
            features.update(self.text_length_features(row.get('body', '')))
            features.update(self.text_style_features(row.get('body', '')))
            features.update(self.keyword_features(full_text))
            features.update(self.erotic_word_features(row.get('subject', ''), row.get('body', '')))
            features.update(self.url_count_features(row.get('body', '')))
            features.update(self.url_structure_features(row.get('body', '')))
            features.update(self.sender_features(row.get('sender', '')))
            features.update(self.temporal_features(row.get('date', '')))
            features.update(self.subject_features(row.get('subject', '')))
            features.update(self.html_features(row.get('body', '')))
            
            all_features.append(features)
            
            if (idx + 1) % 1000 == 0:
                print(f"  Processed {idx + 1}/{total_rows} emails...")
        
        feature_df = pd.DataFrame(all_features)
        print(f"Extracted {len(feature_df.columns)} features from {total_rows} emails.")
        
        return feature_df


def analyze_feature_variance(features_df, label_col='label'):
    """Analyze which features have zero or low variance."""
    print("\n" + "="*70)
    print("FEATURE VARIANCE ANALYSIS")
    print("="*70)
    
    feature_cols = [col for col in features_df.columns if col not in [label_col, 'urls_original']]
    
    zero_variance = []
    low_variance = []
    good_variance = []
    
    for col in feature_cols:
        variance = features_df[col].var()
        unique_values = features_df[col].nunique()
        non_zero_count = (features_df[col] != 0).sum()
        non_zero_pct = non_zero_count / len(features_df) * 100
        
        if variance == 0 or unique_values == 1:
            zero_variance.append((col, non_zero_pct))
        elif non_zero_pct < 1:
            low_variance.append((col, non_zero_pct))
        else:
            good_variance.append((col, non_zero_pct))
    
    print(f"\n✓ GOOD VARIANCE ({len(good_variance)} features with >1% non-zero values):")
    for col, pct in sorted(good_variance, key=lambda x: -x[1]):
        print(f"    {col}: {pct:.1f}% non-zero")
    
    print(f"\n⚠ LOW VARIANCE ({len(low_variance)} features with <1% non-zero values):")
    for col, pct in low_variance:
        print(f"    {col}: {pct:.2f}% non-zero")
    
    print(f"\n✗ ZERO VARIANCE ({len(zero_variance)} features - all same value):")
    for col, pct in zero_variance:
        print(f"    {col}: {pct:.2f}% non-zero")
    
    # Recommendation
    print("\n" + "-"*70)
    print("RECOMMENDATION:")
    print("-"*70)
    drop_candidates = [col for col, _ in zero_variance + low_variance]
    if drop_candidates:
        print(f"Consider dropping {len(drop_candidates)} low/zero variance features:")
        print(f"    {drop_candidates}")
        print("\nTo drop these features before training:")
        print("    X = X.drop(columns=drop_candidates)")
    else:
        print("All features have good variance!")
    
    return {
        'zero_variance': [col for col, _ in zero_variance],
        'low_variance': [col for col, _ in low_variance],
        'good_variance': [col for col, _ in good_variance]
    }


# ==================== USAGE EXAMPLE ====================

if __name__ == "__main__":
    # Load your data
    df = pd.read_csv(r'C:\Users\ethan\Teradata\CEAS_08.csv')
    
    # Initialize feature engineer
    fe = PhishingFeatureEngineer()
    
    # Extract features
    features_df = fe.extract_all_features(df)
    
    # Add the original label and urls columns
    features_df['label'] = df['label']
    features_df['urls_original'] = df['urls']
    
    # Analyze feature variance
    variance_results = analyze_feature_variance(features_df)
    
    # Show keyword statistics
    print("\n" + "="*70)
    print("KEYWORD FEATURE STATISTICS")
    print("="*70)
    keyword_cols = ['urgency_word_count', 'reward_word_count', 'threat_word_count', 
                    'financial_word_count', 'action_word_count', 'total_phishing_keywords']
    print(features_df[keyword_cols].describe())
    
    # Correlation with label
    print("\n" + "-"*70)
    print("KEYWORD CORRELATION WITH PHISHING LABEL")
    print("-"*70)
    for col in keyword_cols:
        corr = features_df[col].corr(features_df['label'])
        print(f"    {col}: {corr:.4f}")
    
    # Save features
    features_df.to_csv('phishing_features.csv', index=False)
    print("\n" + "="*70)
    print("Features saved to 'phishing_features.csv'")
    print("="*70)
    
    # Optionally save a version without zero-variance features
    if variance_results['zero_variance']:
        features_clean = features_df.drop(columns=variance_results['zero_variance'])
        features_clean.to_csv('phishing_features_clean.csv', index=False)
        print(f"Clean version (without zero-variance features) saved to 'phishing_features_clean.csv'")
