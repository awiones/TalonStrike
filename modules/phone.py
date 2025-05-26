import phonenumbers
from phonenumbers import geocoder, carrier, timezone
from phonenumbers.phonenumberutil import NumberParseException
from telegram import Update
from telegram.ext import ContextTypes
import logging
import re
import json
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class PhoneAnalysis:
    """Structured phone analysis result."""
    original_input: str
    is_valid: bool
    is_possible: bool
    formatted_international: str
    formatted_national: str
    formatted_e164: str
    country_code: str
    national_number: str
    country_name: str
    region_code: str
    carrier: str
    line_type: str
    line_type_confidence: str
    timezones: List[str]
    geographic_description: str
    number_length: int
    is_mobile: bool
    is_landline: bool
    is_voip: bool
    is_toll_free: bool
    risk_assessment: str
    additional_info: Dict[str, str]

class EnhancedPhoneScanner:
    """Enhanced phone number scanner with advanced validation and analysis."""
    
    def __init__(self):
        self.country_mappings = self._load_country_mappings()
        self.carrier_patterns = self._load_carrier_patterns()
        
    def _load_country_mappings(self) -> Dict[str, str]:
        """Load extended country code mappings."""
        return {
            '1': 'United States/Canada',
            '7': 'Russia/Kazakhstan',
            '20': 'Egypt',
            '27': 'South Africa',
            '30': 'Greece',
            '31': 'Netherlands',
            '32': 'Belgium',
            '33': 'France',
            '34': 'Spain',
            '36': 'Hungary',
            '39': 'Italy',
            '40': 'Romania',
            '41': 'Switzerland',
            '43': 'Austria',
            '44': 'United Kingdom',
            '45': 'Denmark',
            '46': 'Sweden',
            '47': 'Norway',
            '48': 'Poland',
            '49': 'Germany',
            '51': 'Peru',
            '52': 'Mexico',
            '53': 'Cuba',
            '54': 'Argentina',
            '55': 'Brazil',
            '56': 'Chile',
            '57': 'Colombia',
            '58': 'Venezuela',
            '60': 'Malaysia',
            '61': 'Australia',
            '62': 'Indonesia',
            '63': 'Philippines',
            '64': 'New Zealand',
            '65': 'Singapore',
            '66': 'Thailand',
            '81': 'Japan',
            '82': 'South Korea',
            '84': 'Vietnam',
            '86': 'China',
            '90': 'Turkey',
            '91': 'India',
            '92': 'Pakistan',
            '93': 'Afghanistan',
            '94': 'Sri Lanka',
            '95': 'Myanmar',
            '98': 'Iran',
            '212': 'Morocco',
            '213': 'Algeria',
            '216': 'Tunisia',
            '218': 'Libya',
            '220': 'Gambia',
            '221': 'Senegal',
            '222': 'Mauritania',
            '223': 'Mali',
            '224': 'Guinea',
            '225': 'Ivory Coast',
            '226': 'Burkina Faso',
            '227': 'Niger',
            '228': 'Togo',
            '229': 'Benin',
            '230': 'Mauritius',
            '231': 'Liberia',
            '232': 'Sierra Leone',
            '233': 'Ghana',
            '234': 'Nigeria',
            '235': 'Chad',
            '236': 'Central African Republic',
            '237': 'Cameroon',
            '238': 'Cape Verde',
            '239': 'São Tomé and Príncipe',
            '240': 'Equatorial Guinea',
            '241': 'Gabon',
            '242': 'Republic of the Congo',
            '243': 'Democratic Republic of the Congo',
            '244': 'Angola',
            '245': 'Guinea-Bissau',
            '246': 'British Indian Ocean Territory',
            '248': 'Seychelles',
            '249': 'Sudan',
            '250': 'Rwanda',
            '251': 'Ethiopia',
            '252': 'Somalia',
            '253': 'Djibouti',
            '254': 'Kenya',
            '255': 'Tanzania',
            '256': 'Uganda',
            '257': 'Burundi',
            '258': 'Mozambique',
            '260': 'Zambia',
            '261': 'Madagascar',
            '262': 'Réunion/Mayotte',
            '263': 'Zimbabwe',
            '264': 'Namibia',
            '265': 'Malawi',
            '266': 'Lesotho',
            '267': 'Botswana',
            '268': 'Eswatini',
            '269': 'Comoros',
            '290': 'Saint Helena',
            '291': 'Eritrea',
            '297': 'Aruba',
            '298': 'Faroe Islands',
            '299': 'Greenland',
            '350': 'Gibraltar',
            '351': 'Portugal',
            '352': 'Luxembourg',
            '353': 'Ireland',
            '354': 'Iceland',
            '355': 'Albania',
            '356': 'Malta',
            '357': 'Cyprus',
            '358': 'Finland',
            '359': 'Bulgaria',
            '370': 'Lithuania',
            '371': 'Latvia',
            '372': 'Estonia',
            '373': 'Moldova',
            '374': 'Armenia',
            '375': 'Belarus',
            '376': 'Andorra',
            '377': 'Monaco',
            '378': 'San Marino',
            '380': 'Ukraine',
            '381': 'Serbia',
            '382': 'Montenegro',
            '383': 'Kosovo',
            '385': 'Croatia',
            '386': 'Slovenia',
            '387': 'Bosnia and Herzegovina',
            '389': 'North Macedonia',
            '420': 'Czech Republic',
            '421': 'Slovakia',
            '423': 'Liechtenstein',
            '500': 'Falkland Islands',
            '501': 'Belize',
            '502': 'Guatemala',
            '503': 'El Salvador',
            '504': 'Honduras',
            '505': 'Nicaragua',
            '506': 'Costa Rica',
            '507': 'Panama',
            '508': 'Saint Pierre and Miquelon',
            '509': 'Haiti',
            '590': 'Guadeloupe',
            '591': 'Bolivia',
            '592': 'Guyana',
            '593': 'Ecuador',
            '594': 'French Guiana',
            '595': 'Paraguay',
            '596': 'Martinique',
            '597': 'Suriname',
            '598': 'Uruguay',
            '599': 'Curaçao',
            '670': 'East Timor',
            '672': 'Australian Antarctic Territory',
            '673': 'Brunei',
            '674': 'Nauru',
            '675': 'Papua New Guinea',
            '676': 'Tonga',
            '677': 'Solomon Islands',
            '678': 'Vanuatu',
            '679': 'Fiji',
            '680': 'Palau',
            '681': 'Wallis and Futuna',
            '682': 'Cook Islands',
            '683': 'Niue',
            '684': 'American Samoa',
            '685': 'Samoa',
            '686': 'Kiribati',
            '687': 'New Caledonia',
            '688': 'Tuvalu',
            '689': 'French Polynesia',
            '690': 'Tokelau',
            '691': 'Federated States of Micronesia',
            '692': 'Marshall Islands',
            '850': 'North Korea',
            '852': 'Hong Kong',
            '853': 'Macau',
            '855': 'Cambodia',
            '856': 'Laos',
            '880': 'Bangladesh',
            '886': 'Taiwan',
            '960': 'Maldives',
            '961': 'Lebanon',
            '962': 'Jordan',
            '963': 'Syria',
            '964': 'Iraq',
            '965': 'Kuwait',
            '966': 'Saudi Arabia',
            '967': 'Yemen',
            '968': 'Oman',
            '970': 'Palestine',
            '971': 'United Arab Emirates',
            '972': 'Israel',
            '973': 'Bahrain',
            '974': 'Qatar',
            '975': 'Bhutan',
            '976': 'Mongolia',
            '977': 'Nepal',
            '992': 'Tajikistan',
            '993': 'Turkmenistan',
            '994': 'Azerbaijan',
            '995': 'Georgia',
            '996': 'Kyrgyzstan',
            '998': 'Uzbekistan'
        }
    
    def _load_carrier_patterns(self) -> Dict[str, List[str]]:
        """Load carrier identification patterns."""
        return {
            'voip_indicators': ['skype', 'google', 'vonage', 'magicjack', 'ooma'],
            'premium_indicators': ['900', '976', '970'],
            'toll_free_patterns': ['800', '888', '877', '866', '855', '844', '833', '822']
        }
    
    def _clean_phone_input(self, phone_input: str) -> str:
        """Advanced phone number cleaning and normalization."""
        # Remove common separators and keep only digits, +, -, (, ), and spaces
        cleaned = re.sub(r'[^\d+\-\(\)\s]', '', phone_input.strip())
        
        # Handle common formatting patterns
        cleaned = re.sub(r'\s+', ' ', cleaned)  # Normalize spaces
        cleaned = re.sub(r'^\+?1?\s*\((\d{3})\)\s*(\d{3})\s*-?\s*(\d{4})$', r'+1\1\2\3', cleaned)  # US format
        cleaned = re.sub(r'^(\d{3})\s*-?\s*(\d{3})\s*-?\s*(\d{4})$', r'+1\1\2\3', cleaned)  # US without country code
        
        return cleaned.strip()
    
    def _get_enhanced_line_type(self, parsed_number) -> Tuple[str, str, bool, bool, bool, bool]:
        """Get enhanced line type information with confidence level."""
        number_type = phonenumbers.number_type(parsed_number)
        
        type_mapping = {
            phonenumbers.PhoneNumberType.MOBILE: ("📱 Mobile", "High", True, False, False, False),
            phonenumbers.PhoneNumberType.FIXED_LINE: ("📞 Landline", "High", False, True, False, False),
            phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: ("📱📞 Mobile/Landline", "Medium", True, True, False, False),
            phonenumbers.PhoneNumberType.TOLL_FREE: ("🆓 Toll-free", "High", False, False, False, True),
            phonenumbers.PhoneNumberType.PREMIUM_RATE: ("💰 Premium Rate", "High", False, False, False, False),
            phonenumbers.PhoneNumberType.SHARED_COST: ("💸 Shared Cost", "Medium", False, False, False, False),
            phonenumbers.PhoneNumberType.VOIP: ("🌐 VoIP", "High", False, False, True, False),
            phonenumbers.PhoneNumberType.PERSONAL_NUMBER: ("👤 Personal", "Medium", False, False, False, False),
            phonenumbers.PhoneNumberType.PAGER: ("📟 Pager", "High", False, False, False, False),
            phonenumbers.PhoneNumberType.UAN: ("📋 UAN", "Medium", False, False, False, False),
            phonenumbers.PhoneNumberType.VOICEMAIL: ("📧 Voicemail", "Medium", False, False, False, False),
            phonenumbers.PhoneNumberType.UNKNOWN: ("❓ Unknown", "Low", False, False, False, False)
        }
        
        return type_mapping.get(number_type, ("❓ Unknown", "Low", False, False, False, False))
    
    def _assess_risk(self, analysis: PhoneAnalysis) -> str:
        """Assess potential risk factors of the phone number."""
        risk_factors = []
        
        if not analysis.is_valid:
            risk_factors.append("Invalid number format")
        
        if analysis.line_type_confidence == "Low":
            risk_factors.append("Uncertain line type")
        
        if "Premium Rate" in analysis.line_type:
            risk_factors.append("Premium rate charges may apply")
        
        if analysis.carrier == "Unknown" or not analysis.carrier:
            risk_factors.append("Unknown carrier")
        
        if analysis.is_voip:
            risk_factors.append("VoIP number (easier to spoof)")
        
        if len(analysis.timezones) == 0:
            risk_factors.append("No timezone information")
        
        # Check for suspicious patterns
        if re.search(r'(\d)\1{4,}', analysis.national_number):
            risk_factors.append("Repetitive digit pattern")
        
        if len(risk_factors) == 0:
            return "🟢 Low Risk"
        elif len(risk_factors) <= 2:
            return f"🟡 Medium Risk ({', '.join(risk_factors)})"
        else:
            return f"🔴 High Risk ({', '.join(risk_factors)})"
    
    def _get_additional_info(self, parsed_number, analysis: PhoneAnalysis) -> Dict[str, str]:
        """Get additional contextual information."""
        info = {}
        
        # Leading digits analysis
        national_str = str(parsed_number.national_number)
        if len(national_str) >= 3:
            info['Leading Digits'] = national_str[:3]
        
        # Number pattern analysis
        if re.search(r'(\d)\1{3,}', national_str):
            info['Pattern'] = "Contains repetitive digits"
        elif re.search(r'(012|123|234|345|456|567|678|789)', national_str):
            info['Pattern'] = "Contains sequential digits"
        else:
            info['Pattern'] = "Normal digit distribution"
        
        # Special number detection
        if analysis.country_code == "+1":
            if national_str.startswith('911'):
                info['Special'] = "Emergency number pattern"
            elif national_str.startswith('411'):
                info['Special'] = "Directory assistance pattern"
            elif national_str.startswith('611'):
                info['Special'] = "Repair service pattern"
        
        # Length analysis
        expected_lengths = {
            '1': [10],  # US/Canada
            '44': [10, 11],  # UK
            '49': [11, 12],  # Germany
            '33': [10],  # France
            '39': [10, 11],  # Italy
            '91': [10],  # India
            '86': [11],  # China
            '81': [10, 11],  # Japan
        }
        
        country_code_str = str(parsed_number.country_code)
        if country_code_str in expected_lengths:
            expected = expected_lengths[country_code_str]
            actual = len(national_str)
            if actual in expected:
                info['Length Check'] = "✅ Standard length"
            else:
                info['Length Check'] = f"⚠️ Unusual length (expected {expected}, got {actual})"
        
        return info
    
    def analyze_phone_number(self, phone_input: str) -> PhoneAnalysis:
        """Comprehensive phone number analysis."""
        cleaned_input = self._clean_phone_input(phone_input)
        
        try:
            # Try parsing with different region hints
            parsed_number = None
            region_hints = [None, 'US', 'GB', 'DE', 'FR', 'IT', 'ES', 'CA', 'AU', 'IN', 'CN', 'JP']
            
            for region in region_hints:
                try:
                    parsed_number = phonenumbers.parse(cleaned_input, region)
                    if phonenumbers.is_valid_number(parsed_number):
                        break
                except:
                    continue
            
            if not parsed_number:
                # Last attempt with original input
                parsed_number = phonenumbers.parse(cleaned_input, None)
            
            # Get basic information
            is_valid = phonenumbers.is_valid_number(parsed_number)
            is_possible = phonenumbers.is_possible_number(parsed_number)
            
            # Format the number
            international_format = phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
            national_format = phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.NATIONAL)
            e164_format = phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.E164)
            
            # Get location and carrier information
            country_name = geocoder.description_for_number(parsed_number, "en") or "Unknown"
            carrier_name = carrier.name_for_number(parsed_number, "en") or "Unknown"
            timezone_list = list(timezone.time_zones_for_number(parsed_number)) or []
            
            # Get enhanced line type information
            line_type, confidence, is_mobile, is_landline, is_voip, is_toll_free = self._get_enhanced_line_type(parsed_number)
            
            # Get country code and region
            country_code = f"+{parsed_number.country_code}"
            region_code = phonenumbers.region_code_for_number(parsed_number) or "Unknown"
            
            # Create analysis object
            analysis = PhoneAnalysis(
                original_input=phone_input,
                is_valid=is_valid,
                is_possible=is_possible,
                formatted_international=international_format,
                formatted_national=national_format,
                formatted_e164=e164_format,
                country_code=country_code,
                national_number=str(parsed_number.national_number),
                country_name=country_name,
                region_code=region_code,
                carrier=carrier_name,
                line_type=line_type,
                line_type_confidence=confidence,
                timezones=timezone_list,
                geographic_description=country_name,
                number_length=len(str(parsed_number.national_number)),
                is_mobile=is_mobile,
                is_landline=is_landline,
                is_voip=is_voip,
                is_toll_free=is_toll_free,
                risk_assessment="",
                additional_info={}
            )
            
            # Assess risk and get additional info
            analysis.risk_assessment = self._assess_risk(analysis)
            analysis.additional_info = self._get_additional_info(parsed_number, analysis)
            
            return analysis
            
        except Exception as e:
            # Return error analysis
            return PhoneAnalysis(
                original_input=phone_input,
                is_valid=False,
                is_possible=False,
                formatted_international="N/A",
                formatted_national="N/A",
                formatted_e164="N/A",
                country_code="N/A",
                national_number="N/A",
                country_name="Unknown",
                region_code="Unknown",
                carrier="Unknown",
                line_type="❓ Parse Error",
                line_type_confidence="None",
                timezones=[],
                geographic_description="Parse failed",
                number_length=0,
                is_mobile=False,
                is_landline=False,
                is_voip=False,
                is_toll_free=False,
                risk_assessment=f"🔴 Parse Error: {str(e)}",
                additional_info={"Error": str(e)}
            )

# Enhanced phone command handler
scanner = EnhancedPhoneScanner()

async def phone(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Enhanced phone number analysis with comprehensive information and advanced error handling."""
    
    # Check if user provided arguments
    if not context.args:
        help_text = (
            "📱 <b>Enhanced Phone Number Scanner v2.0</b>\n\n"
            "<b>Usage:</b> /phone <code>[+country_code]number</code>\n\n"
            "<b>Examples:</b>\n"
            "• <code>/phone +14155552671</code> (US)\n"
            "• <code>/phone +447911123456</code> (UK)\n"
            "• <code>/phone +33612345678</code> (France)\n"
            "• <code>/phone +8613800138000</code> (China)\n"
            "• <code>/phone +919876543210</code> (India)\n\n"
            "<b>Supported formats:</b>\n"
            "• International: +1 415 555 2671\n"
            "• E164: +14155552671\n"
            "• National: (415) 555-2671\n"
            "• Various local formats\n\n"
            "<b>New Features:</b>\n"
            "• 🔍 Advanced validation\n"
            "• 🛡️ Risk assessment\n"
            "• 📊 Pattern analysis\n"
            "• 🌍 Extended country support\n"
            "• ⚡ Smart format detection\n\n"
            "💡 <i>Always include country code for maximum accuracy</i>"
        )
        await update.message.reply_text(help_text, parse_mode="HTML")
        return
    
    # Get the phone number from arguments
    phone_input = " ".join(context.args).strip()
    
    # Show processing message for complex analysis
    processing_msg = await update.message.reply_text("🔍 <b>Analyzing phone number...</b>", parse_mode="HTML")
    
    try:
        # Perform comprehensive analysis
        analysis = scanner.analyze_phone_number(phone_input)
        
        # Delete processing message
        await processing_msg.delete()
        
        if not analysis.is_valid and "Parse Error" in analysis.risk_assessment:
            # Handle parse errors
            error_response = (
                f"❌ <b>Analysis Failed</b>\n\n"
                f"<b>Input:</b> <code>{phone_input}</code>\n"
                f"<b>Issue:</b> {analysis.additional_info.get('Error', 'Unknown error')}\n\n"
                f"<b>💡 Troubleshooting Tips:</b>\n"
                f"• Ensure country code is included (+1, +44, etc.)\n"
                f"• Remove all special characters except + - ( )\n"
                f"• Check for correct number length\n"
                f"• Verify the country code exists\n"
                f"• Try different formatting\n\n"
                f"<b>📋 Common Formats:</b>\n"
                f"• US: +1 555 123 4567\n"
                f"• UK: +44 20 1234 5678\n"
                f"• Germany: +49 30 12345678\n"
                f"• France: +33 1 23 45 67 89"
            )
            await update.message.reply_text(error_response, parse_mode="HTML")
            return
        
        # Build comprehensive response
        status_icon = "✅" if analysis.is_valid else "❌"
        confidence_icon = {"High": "🟢", "Medium": "🟡", "Low": "🔴"}.get(analysis.line_type_confidence, "⚪")
        
        response = (
            f"📱 <b>Enhanced Phone Analysis Report</b>\n"
            f"{'═' * 35}\n\n"
            f"<b>📋 Number Information:</b>\n"
            f"• <b>Original Input:</b> <code>{analysis.original_input}</code>\n"
            f"• <b>International:</b> <code>{analysis.formatted_international}</code>\n"
            f"• <b>National:</b> <code>{analysis.formatted_national}</code>\n"
            f"• <b>E164 Format:</b> <code>{analysis.formatted_e164}</code>\n"
            f"• <b>National Number:</b> <code>{analysis.national_number}</code>\n\n"
            f"<b>🌍 Geographic Information:</b>\n"
            f"• <b>Country/Region:</b> {analysis.country_name}\n"
            f"• <b>Country Code:</b> <code>{analysis.country_code}</code>\n"
            f"• <b>Region Code:</b> <code>{analysis.region_code}</code>\n"
            f"• <b>Carrier/Network:</b> {analysis.carrier}\n\n"
            f"<b>📞 Line Type Analysis:</b>\n"
            f"• <b>Type:</b> {analysis.line_type} {confidence_icon}\n"
            f"• <b>Confidence:</b> {analysis.line_type_confidence}\n"
            f"• <b>Mobile:</b> {'✅' if analysis.is_mobile else '❌'}\n"
            f"• <b>Landline:</b> {'✅' if analysis.is_landline else '❌'}\n"
            f"• <b>VoIP:</b> {'✅' if analysis.is_voip else '❌'}\n"
            f"• <b>Toll-free:</b> {'✅' if analysis.is_toll_free else '❌'}\n\n"
            f"<b>🕐 Time & Location:</b>\n"
            f"• <b>Timezone(s):</b> {', '.join(analysis.timezones) if analysis.timezones else 'Unknown'}\n"
            f"• <b>Number Length:</b> {analysis.number_length} digits\n\n"
            f"<b>✅ Validation Results:</b>\n"
            f"• <b>Valid Number:</b> {status_icon} {'Yes' if analysis.is_valid else 'No'}\n"
            f"• <b>Possible Number:</b> {'✅' if analysis.is_possible else '❌'} {'Yes' if analysis.is_possible else 'No'}\n\n"
            f"<b>🛡️ Risk Assessment:</b>\n"
            f"• <b>Overall Risk:</b> {analysis.risk_assessment}\n\n"
        )
        
        # Add additional information if available
        if analysis.additional_info:
            response += f"<b>📊 Additional Analysis:</b>\n"
            for key, value in analysis.additional_info.items():
                response += f"• <b>{key}:</b> {value}\n"
            response += "\n"
        
        # Add footer
        response += (
            f"<b>📝 Analysis Metadata:</b>\n"
            f"• <b>Scan Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
        )
        
        # Log successful analysis
        logger.info(f"Enhanced phone analysis completed: {analysis.formatted_e164} - "
                   f"Valid: {analysis.is_valid}, Type: {analysis.line_type}, "
                   f"Risk: {analysis.risk_assessment}, User: {update.effective_user.id}")
        
        # Send response (split if too long)
        if len(response) > 4096:
            # Split message
            parts = [response[i:i+4000] for i in range(0, len(response), 4000)]
            for part in parts:
                await update.message.reply_text(part, parse_mode="HTML")
        else:
            await update.message.reply_text(response, parse_mode="HTML")
        
    except Exception as e:
        # Delete processing message on error
        try:
            await processing_msg.delete()
        except:
            pass
        
        error_response = (
            f"❌ <b>System Error</b>\n\n"
            f"An unexpected error occurred during analysis.\n\n"
            f"<b>Error Details:</b> <code>{str(e)}</code>\n"
            f"<b>Input:</b> <code>{phone_input}</code>\n\n"
            f"Please try again or contact support if the issue persists.\n\n"
            f"<i>Error logged for investigation.</i>"
        )
        
        logger.error(f"System error in enhanced phone scanner: {str(e)} for input: {phone_input}")
        await update.message.reply_text(error_response, parse_mode="HTML")

# Rate-limited version (optional)
async def phone_with_rate_limit(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Enhanced phone scanner with rate limiting."""
    user_id = update.effective_user.id
    
    # Implement rate limiting logic here if needed
    # For now, just call the main function
    await phone(update, context)