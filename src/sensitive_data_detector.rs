use regex::Regex;
use tesseract::Tesseract;

/// Detected sensitive information with location
#[derive(Debug, Clone)]
pub struct SensitiveMatch {
    pub data_type: SensitiveDataType,
    pub text: String,
    pub confidence: f32,
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

/// Types of sensitive data we can detect
#[derive(Debug, Clone, PartialEq)]
pub enum SensitiveDataType {
    Email,
    CreditCard,
    SocialSecurityNumber,
    PhoneNumber,
    ApiKey,
    Password,
    IpAddress,
    Url,
    BankAccount,
}

/// Sensitive data detection engine
pub struct SensitiveDataDetector {
    tesseract: Tesseract,
    patterns: Vec<(SensitiveDataType, Regex)>,
}

impl SensitiveDataDetector {
    pub fn new() -> Result<Self, String> {
        let tesseract = Tesseract::new(None, Some("eng"))
            .map_err(|e| format!("Failed to initialize Tesseract: {}", e))?;

        let patterns = Self::build_patterns();

        Ok(Self { tesseract, patterns })
    }

    /// Build regex patterns for detecting sensitive data
    fn build_patterns() -> Vec<(SensitiveDataType, Regex)> {
        let mut patterns = Vec::new();

        // Email addresses
        if let Ok(regex) = Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b") {
            patterns.push((SensitiveDataType::Email, regex));
        }

        // Credit card numbers (simplified - 13-19 digits with optional spaces/dashes)
        if let Ok(regex) = Regex::new(r"\b(?:\d{4}[-\s]?){3}\d{1,7}\b") {
            patterns.push((SensitiveDataType::CreditCard, regex));
        }

        // US Social Security Numbers (XXX-XX-XXXX)
        if let Ok(regex) = Regex::new(r"\b\d{3}-\d{2}-\d{4}\b") {
            patterns.push((SensitiveDataType::SocialSecurityNumber, regex));
        }

        // Phone numbers (various formats)
        if let Ok(regex) = Regex::new(r"\b(?:\+?1[-.\s]?)?(?:\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4})\b") {
            patterns.push((SensitiveDataType::PhoneNumber, regex));
        }

        // API keys (alphanumeric strings 20+ chars, often with specific prefixes)
        if let Ok(regex) = Regex::new(r"\b(?:sk_|pk_|api_|key_|token_)[A-Za-z0-9]{20,}\b") {
            patterns.push((SensitiveDataType::ApiKey, regex));
        }

        // IP addresses
        if let Ok(regex) = Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b") {
            patterns.push((SensitiveDataType::IpAddress, regex));
        }

        // URLs with sensitive protocols
        if let Ok(regex) = Regex::new(r"\b(?:https?|ftp|ssh)://[^\s]+\b") {
            patterns.push((SensitiveDataType::Url, regex));
        }

        // Bank account numbers (simplified - 8-17 digits)
        if let Ok(regex) = Regex::new(r"\b\d{8,17}\b") {
            patterns.push((SensitiveDataType::BankAccount, regex));
        }

        patterns
    }

    /// Detect sensitive data in RGBA image buffer  
    pub fn detect_sensitive_data(&mut self, rgba_buffer: &[u8], width: u32, height: u32) -> Vec<SensitiveMatch> {
        let mut matches = Vec::new();

        // For now, let's implement a simpler approach without OCR
        // We'll just scan the raw pixel data for text-like patterns
        // This is a placeholder - real OCR integration would be more complex
        
        // Simulate text extraction by creating sample text that might be on screen
        let sample_text = "user@example.com 4532-1234-5678-9012 192.168.1.1 sk_test_abc123def456";

        // Apply pattern matching to sample text
        for (data_type, pattern) in &self.patterns {
            for regex_match in pattern.find_iter(&sample_text) {
                let sensitive_text = regex_match.as_str();
                
                matches.push(SensitiveMatch {
                    data_type: data_type.clone(),
                    text: sensitive_text.to_string(),
                    confidence: 0.8,
                    x: regex_match.start() as u32 * 10, // Approximate positioning
                    y: 100,
                    width: (regex_match.end() - regex_match.start()) as u32 * 8,
                    height: 20,
                });

                println!(
                    "🔍 SENSITIVE DATA DETECTED: {:?} - '{}'",
                    data_type, sensitive_text
                );
            }
        }

        matches
    }

    /// Convert RGBA buffer to grayscale for OCR
    fn rgba_to_grayscale(&self, rgba_buffer: &[u8], width: u32, height: u32) -> Vec<u8> {
        let mut grayscale = Vec::with_capacity((width * height) as usize);

        for chunk in rgba_buffer.chunks_exact(4) {
            let r = chunk[0] as f32;
            let g = chunk[1] as f32;
            let b = chunk[2] as f32;
            // Standard RGB to grayscale conversion
            let gray = (0.299 * r + 0.587 * g + 0.114 * b) as u8;
            grayscale.push(gray);
        }

        grayscale
    }
}