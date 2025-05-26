import re
import ipaddress
from datetime import datetime
from telegram import Update
from telegram.ext import ContextTypes
from email import message_from_string
from email.utils import parsedate_to_datetime
from typing import Dict, List, Optional, Tuple
import urllib.parse

class EmailHeaderAnalyzer:
    def __init__(self):
        self.suspicious_patterns = {
            'spoofing_indicators': [
                r'(reply-to|return-path).*noreply.*gmail\.com',
                r'from.*@gmail\.com.*reply-to.*@(?!gmail\.com)',
                r'envelope-from.*differs.*from'
            ],
            'suspicious_domains': [
                r'bit\.ly', r'tinyurl\.com', r'goo\.gl', r't\.co',
                r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
            ],
            'phishing_keywords': [
                r'urgent.*action.*required', r'verify.*account.*immediately',
                r'click.*here.*now', r'suspended.*account'
            ]
        }
    
    def parse_email_headers(self, raw_headers: str) -> Dict[str, str]:
        """Enhanced header parsing with better error handling"""
        try:
            # Clean up common formatting issues
            raw_headers = self._clean_raw_headers(raw_headers)
            msg = message_from_string(raw_headers)
            
            headers = {}
            for key, value in msg.items():
                # Handle multiple headers with same name
                if key in headers:
                    if isinstance(headers[key], list):
                        headers[key].append(value)
                    else:
                        headers[key] = [headers[key], value]
                else:
                    headers[key] = value
            
            return headers
        except Exception as e:
            raise ValueError(f"Failed to parse headers: {str(e)}")
    
    def _clean_raw_headers(self, raw_headers: str) -> str:
        """Clean and normalize raw header input"""
        # Replace common escape sequences
        raw_headers = raw_headers.replace('\\n', '\n').replace('\\r', '\r')
        raw_headers = raw_headers.replace('\\t', '\t')
        
        # Fix line continuations
        lines = raw_headers.split('\n')
        cleaned_lines = []
        
        for line in lines:
            if line.strip():
                # Check if this is a continuation line (starts with whitespace)
                if line.startswith((' ', '\t')) and cleaned_lines:
                    cleaned_lines[-1] += ' ' + line.strip()
                else:
                    cleaned_lines.append(line)
        
        return '\n'.join(cleaned_lines)
    
    def extract_ips_from_received(self, received_headers: List[str]) -> List[Dict[str, str]]:
        """Extract IP addresses and hostnames from Received headers"""
        ip_info = []
        ip_pattern = r'\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?'
        
        for received in received_headers:
            ips = re.findall(ip_pattern, received)
            for ip in ips:
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    ip_info.append({
                        'ip': ip,
                        'type': 'Private' if ip_obj.is_private else 'Public',
                        'header': received[:100] + '...' if len(received) > 100 else received
                    })
                except ValueError:
                    continue
        
        return ip_info
    
    def analyze_authentication(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Analyze SPF, DKIM, and DMARC results"""
        auth_results = {}
        
        # SPF Analysis
        if 'Received-SPF' in headers:
            spf_result = headers['Received-SPF'].lower()
            if 'pass' in spf_result:
                auth_results['SPF'] = '✅ PASS'
            elif 'fail' in spf_result:
                auth_results['SPF'] = '❌ FAIL'
            elif 'softfail' in spf_result:
                auth_results['SPF'] = '⚠️ SOFTFAIL'
            else:
                auth_results['SPF'] = '❓ UNKNOWN'
        
        # DKIM Analysis
        if 'DKIM-Signature' in headers:
            auth_results['DKIM'] = '📝 Present'
        
        # Authentication-Results parsing
        if 'Authentication-Results' in headers:
            auth_header = headers['Authentication-Results'].lower()
            
            # Parse SPF from auth results if not already found
            if 'SPF' not in auth_results:
                if 'spf=pass' in auth_header:
                    auth_results['SPF'] = '✅ PASS'
                elif 'spf=fail' in auth_header:
                    auth_results['SPF'] = '❌ FAIL'
            
            # Parse DKIM from auth results
            if 'dkim=pass' in auth_header:
                auth_results['DKIM'] = '✅ PASS'
            elif 'dkim=fail' in auth_header:
                auth_results['DKIM'] = '❌ FAIL'
            
            # Parse DMARC
            if 'dmarc=pass' in auth_header:
                auth_results['DMARC'] = '✅ PASS'
            elif 'dmarc=fail' in auth_header:
                auth_results['DMARC'] = '❌ FAIL'
        
        return auth_results
    
    def detect_security_issues(self, headers: Dict[str, str]) -> List[str]:
        """Detect potential security issues and suspicious patterns"""
        issues = []
        
        # Check for domain spoofing
        from_addr = headers.get('From', '').lower()
        reply_to = headers.get('Reply-To', '').lower()
        return_path = headers.get('Return-Path', '').lower()
        
        if reply_to and from_addr:
            from_domain = re.search(r'@([^>]+)', from_addr)
            reply_domain = re.search(r'@([^>]+)', reply_to)
            if from_domain and reply_domain and from_domain.group(1) != reply_domain.group(1):
                issues.append(f"⚠️ Domain mismatch: From domain differs from Reply-To domain")
        
        # Check for suspicious patterns
        full_headers = ' '.join(str(v) for v in headers.values()).lower()
        
        for category, patterns in self.suspicious_patterns.items():
            for pattern in patterns:
                if re.search(pattern, full_headers, re.IGNORECASE):
                    issues.append(f"🚨 Suspicious pattern detected: {category}")
                    break
        
        return issues
    
    def analyze_routing_path(self, headers: Dict[str, str]) -> List[str]:
        """Analyze the email routing path"""
        received_headers = []
        
        # Get all Received headers (they can be multiple)
        if 'Received' in headers:
            if isinstance(headers['Received'], list):
                received_headers = headers['Received']
            else:
                received_headers = [headers['Received']]
        
        routing_info = []
        if received_headers:
            routing_info.append(f"<b>📧 Email Routing Path ({len(received_headers)} hops):</b>")
            
            for i, received in enumerate(reversed(received_headers), 1):
                # Extract timestamp
                timestamp_match = re.search(r';\s*(.+)$', received)
                timestamp = ""
                if timestamp_match:
                    try:
                        dt = parsedate_to_datetime(timestamp_match.group(1).strip())
                        timestamp = f" [{dt.strftime('%Y-%m-%d %H:%M:%S UTC')}]"
                    except:
                        timestamp = f" [{timestamp_match.group(1).strip()}]"
                
                # Truncate long headers for readability
                display_received = received[:150] + '...' if len(received) > 150 else received
                routing_info.append(f"<b>Hop {i}:</b>{timestamp}\n<code>{display_received}</code>")
        
        return routing_info
    
    def generate_summary(self, headers: Dict[str, str]) -> List[str]:
        """Generate a security and authenticity summary"""
        summary = ["<b>🔍 Security Summary:</b>"]
        
        # Authentication check
        auth_results = self.analyze_authentication(headers)
        if auth_results:
            summary.append("<b>Authentication Status:</b>")
            for method, result in auth_results.items():
                summary.append(f"  • {method}: {result}")
        else:
            summary.append("⚠️ No authentication information found")
        
        # Security issues
        issues = self.detect_security_issues(headers)
        if issues:
            summary.append("<b>Security Concerns:</b>")
            summary.extend(f"  • {issue}" for issue in issues)
        else:
            summary.append("✅ No obvious security issues detected")
        
        return summary

def analyze_headers(headers: Dict[str, str]) -> List[str]:
    """Enhanced header analysis with comprehensive information"""
    analyzer = EmailHeaderAnalyzer()
    results = []
    
    # Basic header information
    results.append("<b>📨 Basic Information:</b>")
    basic_fields = ["From", "To", "Cc", "Bcc", "Subject", "Date", "Message-ID"]
    
    for field in basic_fields:
        if field in headers:
            value = headers[field]
            if isinstance(value, list):
                value = "; ".join(value)
            # Truncate very long values
            if len(value) > 200:
                value = value[:200] + "..."
            results.append(f"<b>{field}:</b> <code>{value}</code>")
    
    # Security summary
    results.extend(analyzer.generate_summary(headers))
    
    # Routing analysis
    results.extend(analyzer.analyze_routing_path(headers))
    
    # IP information
    received_headers = []
    if 'Received' in headers:
        if isinstance(headers['Received'], list):
            received_headers = headers['Received']
        else:
            received_headers = [headers['Received']]
    
    if received_headers:
        ip_info = analyzer.extract_ips_from_received(received_headers)
        if ip_info:
            results.append("<b>🌐 IP Address Information:</b>")
            for info in ip_info[:5]:  # Limit to first 5 IPs
                results.append(f"<code>{info['ip']}</code> ({info['type']})")
    
    # Additional technical headers
    technical_headers = [
        "X-Originating-IP", "X-Forwarded-For", "X-Real-IP",
        "Content-Type", "Content-Transfer-Encoding", "MIME-Version",
        "X-Mailer", "User-Agent", "X-Priority", "Importance"
    ]
    
    tech_found = []
    for header in technical_headers:
        if header in headers:
            value = headers[header]
            if isinstance(value, list):
                value = "; ".join(value)
            tech_found.append(f"<b>{header}:</b> <code>{value}</code>")
    
    if tech_found:
        results.append("<b>🔧 Technical Headers:</b>")
        results.extend(tech_found)
    
    return results

async def analyzeheader(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Enhanced email header analysis command"""
    if not context.args:
        help_text = (
            "<b>📧 Email Header Analyzer</b>\n\n"
            "<b>Usage:</b>\n"
            "<code>/analyzeheader [paste email headers here]</code>\n\n"
            "<b>Features:</b>\n"
            "• Security analysis (SPF, DKIM, DMARC)\n"
            "• Routing path analysis\n"
            "• IP address extraction\n"
            "• Spoofing detection\n"
            "• Authentication verification\n\n"
            "<b>Tip:</b> Copy the raw email headers from your email client and paste them after the command."
        )
        await update.message.reply_text(help_text, parse_mode="HTML")
        return
    
    raw_headers = " ".join(context.args)
    
    try:
        analyzer = EmailHeaderAnalyzer()
        headers = analyzer.parse_email_headers(raw_headers)
        
        if not headers:
            await update.message.reply_text(
                "❌ <b>No valid headers found.</b>\n\n"
                "Please make sure you've copied the complete email headers.",
                parse_mode="HTML"
            )
            return
        
        results = analyze_headers(headers)
        
        # Create response with header
        response_parts = [
            f"<b>📧 Email Header Analysis Report</b>",
            f"<i>Analyzed {len(headers)} header fields</i>",
            "=" * 40,
            *results
        ]
        
        full_response = "\n".join(response_parts)
        
        # Handle long responses by splitting them
        max_length = 4000
        if len(full_response) > max_length:
            parts = []
            current_part = ""
            
            for line in response_parts:
                if len(current_part + line + "\n") > max_length:
                    if current_part:
                        parts.append(current_part.strip())
                        current_part = line + "\n"
                    else:
                        # Single line too long, truncate it
                        parts.append(line[:max_length-3] + "...")
                        current_part = ""
                else:
                    current_part += line + "\n"
            
            if current_part:
                parts.append(current_part.strip())
            
            # Send each part
            for i, part in enumerate(parts):
                if i == 0:
                    await update.message.reply_text(part, parse_mode="HTML")
                else:
                    await update.message.reply_text(f"<b>Continued...</b>\n\n{part}", parse_mode="HTML")
        else:
            await update.message.reply_text(full_response, parse_mode="HTML")
            
    except Exception as e:
        error_msg = (
            f"❌ <b>Error analyzing headers:</b>\n"
            f"<code>{str(e)}</code>\n\n"
            f"<b>Tips:</b>\n"
            f"• Make sure headers are properly formatted\n"
            f"• Include the complete header section\n"
            f"• Check for special characters that might cause issues"
        )
        await update.message.reply_text(error_msg, parse_mode="HTML")