import socket
import dns.resolver
import dns.reversename
import whois
import requests
import asyncio
import re
from datetime import datetime
from telegram import Update
from telegram.ext import ContextTypes
from typing import Dict, List, Optional, Tuple
import json

class EnhancedDNSLookup:
    def __init__(self):
        self.dns_servers = [
            '8.8.8.8',      # Google
            '1.1.1.1',      # Cloudflare
            '208.67.222.222' # OpenDNS
        ]
        self.record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'PTR']
        
    def validate_domain(self, domain: str) -> bool:
        """Validate domain format"""
        pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        )
        return pattern.match(domain) is not None
    
    def validate_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False
    
    async def get_dns_records(self, domain: str) -> Dict:
        """Get comprehensive DNS records"""
        records = {}
        
        for record_type in self.record_types:
            try:
                if record_type == 'PTR':
                    continue  # Skip PTR for forward lookup
                    
                answers = await asyncio.to_thread(dns.resolver.resolve, domain, record_type)
                records[record_type] = []
                
                for answer in answers:
                    if record_type == 'MX':
                        records[record_type].append({
                            'priority': answer.preference,
                            'exchange': str(answer.exchange),
                            'ip': await self.resolve_hostname(str(answer.exchange))
                        })
                    elif record_type == 'SOA':
                        records[record_type].append({
                            'mname': str(answer.mname),
                            'rname': str(answer.rname),
                            'serial': answer.serial,
                            'refresh': answer.refresh,
                            'retry': answer.retry,
                            'expire': answer.expire,
                            'minimum': answer.minimum
                        })
                    elif record_type in ['A', 'AAAA']:
                        ip_str = str(answer)
                        location = await self.get_ip_geolocation(ip_str)
                        records[record_type].append({
                            'ip': ip_str,
                            'location': location,
                            'reverse_dns': await self.get_reverse_dns(ip_str)
                        })
                    else:
                        records[record_type].append(str(answer))
                        
            except Exception as e:
                records[record_type] = f"Error: {str(e)}"
                
        return records
    
    async def resolve_hostname(self, hostname: str) -> Optional[str]:
        """Resolve hostname to IP"""
        try:
            result = await asyncio.to_thread(socket.gethostbyname, hostname)
            return result
        except:
            return None
    
    async def get_reverse_dns(self, ip: str) -> Optional[str]:
        """Get reverse DNS lookup"""
        try:
            addr = dns.reversename.from_address(ip)
            result = await asyncio.to_thread(dns.resolver.resolve, addr, 'PTR')
            return str(result[0])
        except:
            return None
    
    async def get_ip_geolocation(self, ip: str) -> Dict:
        """Get IP geolocation information"""
        try:
            response = await asyncio.to_thread(
                requests.get, 
                f"http://ip-api.com/json/{ip}",
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                return {
                    'country': data.get('country', 'Unknown'),
                    'region': data.get('regionName', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'isp': data.get('isp', 'Unknown'),
                    'org': data.get('org', 'Unknown'),
                    'timezone': data.get('timezone', 'Unknown')
                }
        except:
            pass
        return {'country': 'Unknown', 'region': 'Unknown', 'city': 'Unknown', 'isp': 'Unknown', 'org': 'Unknown', 'timezone': 'Unknown'}
    
    async def get_whois_info(self, domain: str) -> Dict:
        """Get WHOIS information"""
        try:
            w = await asyncio.to_thread(whois.whois, domain)
            return {
                'registrar': w.registrar if hasattr(w, 'registrar') else 'Unknown',
                'creation_date': str(w.creation_date) if hasattr(w, 'creation_date') else 'Unknown',
                'expiration_date': str(w.expiration_date) if hasattr(w, 'expiration_date') else 'Unknown',
                'updated_date': str(w.updated_date) if hasattr(w, 'updated_date') else 'Unknown',
                'name_servers': w.name_servers if hasattr(w, 'name_servers') else [],
                'status': w.status if hasattr(w, 'status') else []
            }
        except Exception as e:
            return {'error': str(e)}
    
    async def check_domain_security(self, domain: str) -> Dict:
        """Check domain security features"""
        security_info = {
            'https_available': False,
            'ssl_valid': False,
            'hsts_enabled': False,
            'has_spf': False,
            'has_dmarc': False,
            'has_dkim': False
        }
        
        try:
            # Check HTTPS availability
            response = await asyncio.to_thread(
                requests.head, 
                f"https://{domain}",
                timeout=10,
                verify=True
            )
            security_info['https_available'] = True
            security_info['ssl_valid'] = True
            
            # Check HSTS
            if 'strict-transport-security' in response.headers:
                security_info['hsts_enabled'] = True
                
        except requests.exceptions.SSLError:
            security_info['https_available'] = True
            security_info['ssl_valid'] = False
        except:
            pass
        
        try:
            # Check SPF record
            txt_records = await asyncio.to_thread(dns.resolver.resolve, domain, 'TXT')
            for record in txt_records:
                if 'v=spf1' in str(record):
                    security_info['has_spf'] = True
                if 'v=DMARC1' in str(record):
                    security_info['has_dmarc'] = True
        except:
            pass
        
        try:
            # Check DMARC record
            dmarc_domain = f"_dmarc.{domain}"
            dmarc_records = await asyncio.to_thread(dns.resolver.resolve, dmarc_domain, 'TXT')
            security_info['has_dmarc'] = True
        except:
            pass
            
        return security_info
    
    async def get_cdn_info(self, domain: str) -> Dict:
        """Detect CDN usage"""
        cdn_info = {'detected': False, 'provider': 'Unknown', 'edge_servers': []}
        
        try:
            # Check common CDN CNAME patterns
            cname_records = await asyncio.to_thread(dns.resolver.resolve, domain, 'CNAME')
            for record in cname_records:
                cname_str = str(record).lower()
                if 'cloudflare' in cname_str:
                    cdn_info = {'detected': True, 'provider': 'Cloudflare', 'edge_servers': []}
                elif 'fastly' in cname_str:
                    cdn_info = {'detected': True, 'provider': 'Fastly', 'edge_servers': []}
                elif 'amazonaws' in cname_str:
                    cdn_info = {'detected': True, 'provider': 'Amazon CloudFront', 'edge_servers': []}
                elif 'akamai' in cname_str:
                    cdn_info = {'detected': True, 'provider': 'Akamai', 'edge_servers': []}
        except:
            pass
            
        return cdn_info
    
    def format_response(self, domain: str, dns_records: Dict, whois_info: Dict, 
                       security_info: Dict, cdn_info: Dict) -> str:
        """Format the comprehensive DNS lookup response"""
        
        response = f"🔍 <b>Comprehensive DNS Analysis</b>\n"
        response += f"{'═' * 35}\n"
        response += f"📋 <b>Domain:</b> <code>{domain}</code>\n"
        response += f"🕐 <b>Analyzed:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n"
        
        # DNS Records Section
        response += f"🌐 <b>DNS Records</b>\n"
        response += f"{'─' * 25}\n"
        
        # A Records
        if 'A' in dns_records and isinstance(dns_records['A'], list):
            response += f"<b>A Records (IPv4):</b>\n"
            for record in dns_records['A']:
                if isinstance(record, dict):
                    response += f"  • <code>{record['ip']}</code>\n"
                    if record['location']['country'] != 'Unknown':
                        response += f"    📍 {record['location']['city']}, {record['location']['country']}\n"
                        response += f"    🏢 {record['location']['isp']}\n"
                    if record['reverse_dns']:
                        response += f"    🔄 {record['reverse_dns']}\n"
            response += "\n"
        
        # AAAA Records
        if 'AAAA' in dns_records and isinstance(dns_records['AAAA'], list):
            response += f"<b>AAAA Records (IPv6):</b>\n"
            for record in dns_records['AAAA']:
                if isinstance(record, dict):
                    response += f"  • <code>{record['ip']}</code>\n"
            response += "\n"
        
        # MX Records
        if 'MX' in dns_records and isinstance(dns_records['MX'], list):
            response += f"<b>MX Records (Mail):</b>\n"
            for record in dns_records['MX']:
                if isinstance(record, dict):
                    response += f"  • Priority: {record['priority']}, Server: <code>{record['exchange']}</code>\n"
                    if record['ip']:
                        response += f"    IP: <code>{record['ip']}</code>\n"
            response += "\n"
        
        # NS Records
        if 'NS' in dns_records and isinstance(dns_records['NS'], list):
            response += f"<b>Name Servers:</b>\n"
            for ns in dns_records['NS']:
                response += f"  • <code>{ns}</code>\n"
            response += "\n"
        
        # CNAME Records
        if 'CNAME' in dns_records and isinstance(dns_records['CNAME'], list):
            response += f"<b>CNAME Records:</b>\n"
            for cname in dns_records['CNAME']:
                response += f"  • <code>{cname}</code>\n"
            response += "\n"
        
        # TXT Records
        if 'TXT' in dns_records and isinstance(dns_records['TXT'], list):
            response += f"<b>TXT Records:</b>\n"
            for txt in dns_records['TXT'][:3]:  # Limit to first 3 TXT records
                txt_short = txt[:60] + "..." if len(txt) > 60 else txt
                response += f"  • <code>{txt_short}</code>\n"
            response += "\n"
        
        # CDN Information
        if cdn_info['detected']:
            response += f"🚀 <b>CDN Detection</b>\n"
            response += f"{'─' * 20}\n"
            response += f"✅ CDN Detected: <b>{cdn_info['provider']}</b>\n\n"
        
        # Security Analysis
        response += f"🔒 <b>Security Analysis</b>\n"
        response += f"{'─' * 25}\n"
        response += f"🔐 HTTPS Available: {'✅' if security_info['https_available'] else '❌'}\n"
        response += f"📜 SSL Certificate: {'✅ Valid' if security_info['ssl_valid'] else '❌ Invalid'}\n"
        response += f"🛡️ HSTS Enabled: {'✅' if security_info['hsts_enabled'] else '❌'}\n"
        response += f"📧 SPF Record: {'✅' if security_info['has_spf'] else '❌'}\n"
        response += f"🛡️ DMARC Policy: {'✅' if security_info['has_dmarc'] else '❌'}\n\n"
        
        # WHOIS Information
        if 'error' not in whois_info:
            response += f"📄 <b>WHOIS Information</b>\n"
            response += f"{'─' * 25}\n"
            response += f"🏢 <b>Registrar:</b> {whois_info.get('registrar', 'Unknown')}\n"
            
            if whois_info.get('creation_date') != 'Unknown':
                response += f"📅 <b>Created:</b> {whois_info['creation_date']}\n"
            if whois_info.get('expiration_date') != 'Unknown':
                response += f"⏰ <b>Expires:</b> {whois_info['expiration_date']}\n"
            
            if whois_info.get('status'):
                status_list = whois_info['status']
                if isinstance(status_list, list) and status_list:
                    response += f"📋 <b>Status:</b> {status_list[0]}\n"
        
        return response

# Main DNS lookup function
async def dnslookup(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        help_text = (
            f"🔍 <b>Enhanced DNS Lookup Tool</b>\n\n"
            f"<b>Usage:</b> /dnslookup <code>domain.com</code>\n\n"
            f"<b>Features:</b>\n"
            f"• Complete DNS record analysis (A, AAAA, MX, NS, TXT, CNAME, SOA)\n"
            f"• IP geolocation and reverse DNS\n"
            f"• WHOIS information\n"
            f"• Security analysis (HTTPS, SSL, HSTS, SPF, DMARC)\n"
            f"• CDN detection\n"
            f"• Mail server details\n\n"
            f"<b>Example:</b> /dnslookup google.com"
        )
        await update.message.reply_text(help_text, parse_mode="HTML")
        return
    
    domain = context.args[0].lower().strip()
    
    # Initialize the DNS lookup class
    dns_lookup = EnhancedDNSLookup()
    
    # Validate domain format
    if not dns_lookup.validate_domain(domain):
        await update.message.reply_text(
            f"❌ <b>Invalid domain format:</b> <code>{domain}</code>\n\n"
            f"Please provide a valid domain name (e.g., example.com)",
            parse_mode="HTML"
        )
        return
    
    # Send initial "analyzing" message
    status_msg = await update.message.reply_text(
        f"🔍 <b>Analyzing domain:</b> <code>{domain}</code>\n"
        f"⏳ Please wait, gathering comprehensive DNS information...",
        parse_mode="HTML"
    )
    
    try:
        # Gather all information concurrently
        dns_records_task = dns_lookup.get_dns_records(domain)
        whois_info_task = dns_lookup.get_whois_info(domain)
        security_info_task = dns_lookup.check_domain_security(domain)
        cdn_info_task = dns_lookup.get_cdn_info(domain)
        
        dns_records, whois_info, security_info, cdn_info = await asyncio.gather(
            dns_records_task,
            whois_info_task,
            security_info_task,
            cdn_info_task,
            return_exceptions=True
        )
        
        # Handle exceptions
        if isinstance(dns_records, Exception):
            dns_records = {}
        if isinstance(whois_info, Exception):
            whois_info = {'error': str(whois_info)}
        if isinstance(security_info, Exception):
            security_info = {}
        if isinstance(cdn_info, Exception):
            cdn_info = {'detected': False}
        
        # Format and send response
        response = dns_lookup.format_response(domain, dns_records, whois_info, security_info, cdn_info)
        
        # Delete status message and send result
        await status_msg.delete()
        
        # Split response if too long for Telegram
        if len(response) > 4096:
            parts = [response[i:i+4096] for i in range(0, len(response), 4096)]
            for part in parts:
                await update.message.reply_text(part, parse_mode="HTML")
        else:
            await update.message.reply_text(response, parse_mode="HTML")
            
    except Exception as e:
        await status_msg.delete()
        await update.message.reply_text(
            f"❌ <b>DNS Lookup Error:</b>\n"
            f"Domain: <code>{domain}</code>\n"
            f"Error: <code>{str(e)}</code>\n\n"
            f"Please check the domain name and try again.",
            parse_mode="HTML"
        )

# Optional: Reverse DNS lookup function
async def reversedns(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            f"🔄 <b>Reverse DNS Lookup</b>\n\n"
            f"<b>Usage:</b> /reversedns <code>IP_ADDRESS</code>\n\n"
            f"<b>Example:</b> /reversedns 8.8.8.8",
            parse_mode="HTML"
        )
        return
    
    ip = context.args[0]
    dns_lookup = EnhancedDNSLookup()
    
    if not dns_lookup.validate_ip(ip):
        await update.message.reply_text(
            f"❌ <b>Invalid IP address:</b> <code>{ip}</code>",
            parse_mode="HTML"
        )
        return
    
    try:
        reverse_dns = await dns_lookup.get_reverse_dns(ip)
        location = await dns_lookup.get_ip_geolocation(ip)
        
        response = f"🔄 <b>Reverse DNS Lookup</b>\n"
        response += f"{'═' * 30}\n"
        response += f"🌐 <b>IP Address:</b> <code>{ip}</code>\n"
        
        if reverse_dns:
            response += f"📍 <b>Hostname:</b> <code>{reverse_dns}</code>\n"
        else:
            response += f"📍 <b>Hostname:</b> No PTR record found\n"
        
        response += f"\n🌍 <b>Geolocation:</b>\n"
        response += f"  • Country: {location['country']}\n"
        response += f"  • Region: {location['region']}\n"
        response += f"  • City: {location['city']}\n"
        response += f"  • ISP: {location['isp']}\n"
        response += f"  • Organization: {location['org']}\n"
        response += f"  • Timezone: {location['timezone']}\n"
        
        await update.message.reply_text(response, parse_mode="HTML")
        
    except Exception as e:
        await update.message.reply_text(
            f"❌ <b>Reverse DNS Error:</b> {str(e)}",
            parse_mode="HTML"
        )