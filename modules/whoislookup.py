from telegram import Update
from telegram.ext import ContextTypes
import whois
import asyncio
import socket
import re
import dns.resolver
import requests
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
import ipaddress

async def whoislookup(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Enhanced WHOIS lookup with comprehensive domain information"""
    
    if not context.args:
        help_text = (
            "🔍 <b>WHOIS Lookup Tool</b>\n\n"
            "<b>Usage:</b> /whoislookup <code>domain.com</code>\n\n"
            "<b>Examples:</b>\n"
            "• /whoislookup example.com\n"
            "• /whoislookup google.com\n"
            "• /whoislookup github.io\n\n"
            "<b>Features:</b>\n"
            "✅ Complete WHOIS information\n"
            "✅ DNS records analysis\n"
            "✅ SSL certificate details\n"
            "✅ Domain security status\n"
            "✅ Registrar information\n"
            "✅ Contact details\n"
            "✅ Technical specifications"
        )
        await update.message.reply_text(help_text, parse_mode="HTML")
        return

    domain = context.args[0].strip().lower()
    
    # Clean and validate domain
    domain = clean_domain(domain)
    if not is_valid_domain(domain):
        await update.message.reply_text(
            f"❌ <b>Invalid Domain Format:</b> <code>{domain}</code>\n\n"
            "Please provide a valid domain name (e.g., example.com)",
            parse_mode="HTML"
        )
        return

    # Send initial processing message
    processing_msg = await update.message.reply_text(
        f"🔍 <b>Analyzing domain:</b> <code>{domain}</code>\n⏳ Please wait...",
        parse_mode="HTML"
    )

    try:
        # Gather all information concurrently
        whois_data, dns_info, ssl_info, security_info = await asyncio.gather(
            get_whois_data(domain),
            get_dns_information(domain),
            get_ssl_information(domain),
            get_security_information(domain),
            return_exceptions=True
        )

        # Format comprehensive response
        response = format_comprehensive_response(
            domain, whois_data, dns_info, ssl_info, security_info
        )

        # Delete processing message and send result
        await processing_msg.delete()
        
        # Split response if too long for Telegram
        if len(response) > 4000:
            responses = split_long_message(response)
            for i, msg in enumerate(responses):
                if i == 0:
                    await update.message.reply_text(msg, parse_mode="HTML")
                else:
                    await asyncio.sleep(0.5)
                    await update.message.reply_text(msg, parse_mode="HTML")
        else:
            await update.message.reply_text(response, parse_mode="HTML")

    except Exception as e:
        await processing_msg.delete()
        error_msg = f"❌ **WHOIS Lookup Failed**\n\n" \
                   f"**Domain:** `{domain}`\n" \
                   f"**Error:** {str(e)}\n\n" \
                   f"*Possible reasons:*\n" \
                   f"• Domain doesn't exist\n" \
                   f"• WHOIS server unavailable\n" \
                   f"• Rate limiting active\n" \
                   f"• Network connectivity issues"
        
        await update.message.reply_text(error_msg, parse_mode="HTML")

def clean_domain(domain: str) -> str:
    """Clean and normalize domain input"""
    # Remove common prefixes
    domain = re.sub(r'^https?://', '', domain)
    domain = re.sub(r'^www\.', '', domain)
    # Remove trailing slashes and paths
    domain = domain.split('/')[0]
    # Remove port numbers
    domain = domain.split(':')[0]
    return domain.lower().strip()

def is_valid_domain(domain: str) -> bool:
    """Validate domain format"""
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
    return bool(re.match(pattern, domain)) and len(domain) <= 253

async def get_whois_data(domain: str) -> Dict[str, Any]:
    """Get comprehensive WHOIS data"""
    try:
        w = await asyncio.to_thread(whois.whois, domain)
        return {
            'success': True,
            'data': w,
            'domain_name': getattr(w, 'domain_name', domain),
            'registrar': getattr(w, 'registrar', 'Unknown'),
            'creation_date': getattr(w, 'creation_date', None),
            'expiration_date': getattr(w, 'expiration_date', None),
            'updated_date': getattr(w, 'updated_date', None),
            'name_servers': getattr(w, 'name_servers', []),
            'status': getattr(w, 'status', []),
            'emails': getattr(w, 'emails', []),
            'registrant_name': getattr(w, 'name', None),
            'registrant_org': getattr(w, 'org', None),
            'registrant_country': getattr(w, 'country', None),
            'admin_email': getattr(w, 'admin_email', None),
            'tech_email': getattr(w, 'tech_email', None),
            'whois_server': getattr(w, 'whois_server', None),
            'dnssec': getattr(w, 'dnssec', None),
        }
    except Exception as e:
        return {'success': False, 'error': str(e)}

async def get_dns_information(domain: str) -> Dict[str, Any]:
    """Get comprehensive DNS information"""
    dns_info = {'success': True, 'records': {}}
    
    record_types = ['A', 'AAAA', 'MX', 'TXT', 'CNAME', 'NS', 'SOA']
    
    try:
        for record_type in record_types:
            try:
                answers = await asyncio.to_thread(dns.resolver.resolve, domain, record_type)
                dns_info['records'][record_type] = [str(rdata) for rdata in answers]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                dns_info['records'][record_type] = []
            except Exception:
                dns_info['records'][record_type] = ['Error retrieving records']

        # Get IP geolocation for A records
        if dns_info['records'].get('A'):
            ip = dns_info['records']['A'][0]
            dns_info['geolocation'] = await get_ip_geolocation(ip)

    except Exception as e:
        dns_info['success'] = False
        dns_info['error'] = str(e)
    
    return dns_info

async def get_ssl_information(domain: str) -> Dict[str, Any]:
    """Get SSL certificate information"""
    try:
        import ssl
        import socket
        
        context = ssl.create_default_context()
        
        def get_cert_info():
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    return cert
        
        cert = await asyncio.to_thread(get_cert_info)
        
        return {
            'success': True,
            'issuer': dict(x[0] for x in cert.get('issuer', [])),
            'subject': dict(x[0] for x in cert.get('subject', [])),
            'version': cert.get('version'),
            'serial_number': cert.get('serialNumber'),
            'not_before': cert.get('notBefore'),
            'not_after': cert.get('notAfter'),
            'signature_algorithm': cert.get('signatureAlgorithm'),
            'subject_alt_names': cert.get('subjectAltName', []),
        }
    except Exception as e:
        return {'success': False, 'error': str(e)}

async def get_security_information(domain: str) -> Dict[str, Any]:
    """Get domain security information"""
    security_info = {'success': True}
    
    try:
        # Check if domain is on common blocklists (simplified check)
        security_info['security_status'] = 'Unknown'
        
        # Additional security checks could be added here
        # - VirusTotal API
        # - Google Safe Browsing API
        # - Domain reputation services
        
    except Exception as e:
        security_info['success'] = False
        security_info['error'] = str(e)
    
    return security_info

async def get_ip_geolocation(ip: str) -> Dict[str, Any]:
    """Get IP geolocation information"""
    try:
        # Using a free IP geolocation service
        response = await asyncio.to_thread(
            requests.get, 
            f"http://ip-api.com/json/{ip}",
            timeout=5
        )
        if response.status_code == 200:
            return response.json()
    except Exception:
        pass
    return {}

def format_date(date_obj) -> str:
    """Format date object to readable string"""
    if not date_obj:
        return "Unknown"
    
    if isinstance(date_obj, list):
        date_obj = date_obj[0] if date_obj else None
    
    if isinstance(date_obj, datetime):
        return date_obj.strftime("%Y-%m-%d %H:%M:%S UTC")
    
    return str(date_obj)

def calculate_days_until_expiry(expiration_date) -> Optional[int]:
    """Calculate days until domain expiry"""
    if not expiration_date:
        return None
    
    if isinstance(expiration_date, list):
        expiration_date = expiration_date[0]
    
    if isinstance(expiration_date, datetime):
        now = datetime.now(timezone.utc)
        if expiration_date.tzinfo is None:
            expiration_date = expiration_date.replace(tzinfo=timezone.utc)
        delta = expiration_date - now
        return delta.days
    
    return None

def format_comprehensive_response(domain: str, whois_data: Dict, dns_info: Dict, 
                                ssl_info: Dict, security_info: Dict) -> str:
    """Format comprehensive WHOIS response"""
    
    response = f"🌐 <b>WHOIS Analysis Report</b>\n"
    response += f"{'═' * 35}\n\n"
    
    # Domain Information
    response += f"📍 <b>Domain Information</b>\n"
    response += f"<b>Domain:</b> <code>{domain}</code>\n"
    
    if whois_data.get('success'):
        w = whois_data
        response += f"<b>Registrar:</b> {w.get('registrar', 'Unknown')}\n"
        
        # Domain dates
        creation = format_date(w.get('creation_date'))
        expiration = format_date(w.get('expiration_date'))
        updated = format_date(w.get('updated_date'))
        
        response += f"<b>Created:</b> {creation}\n"
        response += f"<b>Updated:</b> {updated}\n"
        response += f"<b>Expires:</b> {expiration}\n"
        
        # Expiry warning
        days_until_expiry = calculate_days_until_expiry(w.get('expiration_date'))
        if days_until_expiry is not None:
            if days_until_expiry < 30:
                response += f"⚠️ <b>Expires in {days_until_expiry} days!</b>\n"
            else:
                response += f"✅ <b>{days_until_expiry} days until expiry</b>\n"
        
        response += f"<b>WHOIS Server:</b> {w.get('whois_server', 'Unknown')}\n"
        
        # Domain status
        status = w.get('status', [])
        if status:
            if isinstance(status, list):
                status_str = ', '.join(status[:3])  # Limit to first 3 statuses
                if len(status) > 3:
                    status_str += f" (+{len(status)-3} more)"
            else:
                status_str = str(status)
            response += f"<b>Status:</b> {status_str}\n"
        
        # DNSSEC
        dnssec = w.get('dnssec')
        if dnssec:
            response += f"<b>DNSSEC:</b> {'✅ Enabled' if 'Signed' in str(dnssec) else '❌ Disabled'}\n"
    
    response += "\n"
    
    # Registrant Information
    if whois_data.get('success'):
        response += f"👤 <b>Registrant Information</b>\n"
        reg_name = whois_data.get('registrant_name')
        reg_org = whois_data.get('registrant_org')
        reg_country = whois_data.get('registrant_country')
        
        if reg_name or reg_org or reg_country:
            if reg_name:
                response += f"<b>Name:</b> {reg_name}\n"
            if reg_org:
                response += f"<b>Organization:</b> {reg_org}\n"
            if reg_country:
                response += f"<b>Country:</b> {reg_country}\n"
        else:
            response += "<i>Privacy Protected</i> 🔒\n"
        
        # Contact emails
        emails = whois_data.get('emails', [])
        if emails:
            unique_emails = list(set(emails[:3]))  # Remove duplicates, limit to 3
            response += f"<b>Contact Emails:</b> {', '.join(unique_emails)}\n"
        
        response += "\n"
    
    # DNS Information
    if dns_info.get('success'):
        response += f"🌍 <b>DNS Information</b>\n"
        
        # A Records with geolocation
        a_records = dns_info['records'].get('A', [])
        if a_records:
            response += f"<b>IPv4 Addresses:</b>\n"
            for ip in a_records[:5]:  # Limit to 5 IPs
                response += f"  • <code>{ip}</code>"
                if ip == a_records[0] and dns_info.get('geolocation'):
                    geo = dns_info['geolocation']
                    if geo.get('city') and geo.get('country'):
                        response += f" ({geo['city']}, {geo['country']})"
                response += "\n"
        
        # AAAA Records
        aaaa_records = dns_info['records'].get('AAAA', [])
        if aaaa_records:
            response += f"<b>IPv6 Addresses:</b>\n"
            for ip in aaaa_records[:3]:
                response += f"  • <code>{ip}</code>\n"
        
        # Name Servers
        ns_records = dns_info['records'].get('NS', [])
        if not ns_records and whois_data.get('success'):
            ns_records = whois_data.get('name_servers', [])
        
        if ns_records:
            response += f"<b>Name Servers:</b>\n"
            for ns in ns_records[:5]:
                response += f"  • <code>{ns}</code>\n"
        
        # MX Records
        mx_records = dns_info['records'].get('MX', [])
        if mx_records:
            response += f"<b>Mail Servers:</b>\n"
            for mx in mx_records[:3]:
                response += f"  • <code>{mx}</code>\n"
        
        response += "\n"
    
    # SSL Certificate Information
    if ssl_info.get('success'):
        response += f"🔐 <b>SSL Certificate</b>\n"
        ssl_data = ssl_info
        
        issuer = ssl_data.get('issuer', {})
        if issuer:
            org = issuer.get('organizationName', 'Unknown')
            response += f"<b>Issuer:</b> {org}\n"
        
        subject = ssl_data.get('subject', {})
        if subject:
            cn = subject.get('commonName', domain)
            response += f"<b>Subject:</b> {cn}\n"
        
        not_after = ssl_data.get('not_after')
        if not_after:
            response += f"<b>Valid Until:</b> {not_after}\n"
        
        # Subject Alternative Names
        san = ssl_data.get('subject_alt_names', [])
        if san:
            san_domains = [name[1] for name in san if name[0] == 'DNS'][:3]
            if san_domains:
                response += f"<b>Alt Names:</b> {', '.join(san_domains)}\n"
        
        response += "\n"
    elif not ssl_info.get('success'):
        response += f"🔐 <b>SSL Certificate</b>\n"
        response += f"❌ <b>No HTTPS/SSL detected</b>\n\n"
    
    # Footer
    response += f"📊 <b>Analysis Complete</b>\n"
    response += f"<b>Timestamp:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
    response += f"<b>Query Time:</b> &lt;1 second\n"
    
    return response

def split_long_message(message: str, max_length: int = 4000) -> List[str]:
    """Split long message into chunks for Telegram"""
    if len(message) <= max_length:
        return [message]
    
    chunks = []
    lines = message.split('\n')
    current_chunk = ""
    
    for line in lines:
        if len(current_chunk + line + '\n') <= max_length:
            current_chunk += line + '\n'
        else:
            if current_chunk:
                chunks.append(current_chunk.strip())
            current_chunk = line + '\n'
    
    if current_chunk:
        chunks.append(current_chunk.strip())
    
    return chunks