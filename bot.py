import os
import time
import asyncio
import logging
from datetime import datetime
from collections import defaultdict, deque
import socket
import ssl
import requests
from urllib.parse import urlparse
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, CallbackQueryHandler, ContextTypes, filters

# Logging configuration
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Storage for historical analysis
site_history = defaultdict(lambda: deque(maxlen=50))
monitoring_tasks = {}

class SiteAnalyzer:
    """Class for analyzing websites"""
    
    @staticmethod
    def resolve_ip(domain):
        """Resolves domain IP"""
        try:
            ip = socket.gethostbyname(domain)
            all_ips = socket.getaddrinfo(domain, None)
            unique_ips = list(set([addr[4][0] for addr in all_ips]))
            return {
                'success': True,
                'primary_ip': ip,
                'all_ips': unique_ips,
                'ip_count': len(unique_ips)
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    @staticmethod
    def check_cdn_waf(headers, ip):
        """Detects CDN and WAF"""
        cdn_indicators = {
            'cloudflare': ['cf-ray', 'cf-cache-status', '__cfduid'],
            'akamai': ['akamai', 'x-akamai'],
            'fastly': ['fastly', 'x-fastly'],
            'amazon_cloudfront': ['x-amz-cf-id', 'via'],
            'incapsula': ['x-iinfo', 'x-cdn']
        }
        
        detected = []
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        for cdn, indicators in cdn_indicators.items():
            for indicator in indicators:
                if indicator in headers_lower or any(indicator in v.lower() for v in headers_lower.values()):
                    detected.append(cdn)
                    break
        
        # Check Server header
        server = headers_lower.get('server', '').lower()
        if 'cloudflare' in server:
            detected.append('cloudflare')
        
        return list(set(detected))
    
    @staticmethod
    def analyze_security_headers(headers):
        """Analyzes security headers"""
        security_headers = {
            'Strict-Transport-Security': 'HSTS',
            'Content-Security-Policy': 'CSP',
            'X-Frame-Options': 'Clickjacking Protection',
            'X-Content-Type-Options': 'MIME Sniffing Protection',
            'X-XSS-Protection': 'XSS Protection',
            'Referrer-Policy': 'Referrer Policy',
            'Permissions-Policy': 'Permissions Policy'
        }
        
        found = {}
        missing = []
        
        for header, desc in security_headers.items():
            if header in headers:
                found[desc] = headers[header]
            else:
                missing.append(desc)
        
        return found, missing
    
    @staticmethod
    def get_tls_info(domain):
        """Gets TLS information"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    return {
                        'success': True,
                        'tls_version': version,
                        'cipher': cipher[0] if cipher else 'Unknown',
                        'bits': cipher[2] if cipher and len(cipher) > 2 else 0,
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'valid_until': cert.get('notAfter', 'Unknown')
                    }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    @staticmethod
    async def analyze_site(url):
        """Complete site analysis"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.path
            scheme = parsed.scheme or 'https'
            full_url = f"{scheme}://{domain}"
            
            # IP resolution
            ip_info = SiteAnalyzer.resolve_ip(domain)
            
            # HTTP request with timing
            start_time = time.time()
            headers = {
                'User-Agent': 'Mozilla/5.0 (Security Monitor Bot)',
                'Accept': 'text/html,application/json'
            }
            
            response = requests.get(full_url, headers=headers, timeout=10, allow_redirects=True)
            rtt = (time.time() - start_time) * 1000  # ms
            
            # Headers analysis
            cdn_waf = SiteAnalyzer.check_cdn_waf(response.headers, ip_info.get('primary_ip'))
            sec_headers, missing_headers = SiteAnalyzer.analyze_security_headers(response.headers)
            
            # TLS info
            tls_info = None
            if scheme == 'https':
                tls_info = SiteAnalyzer.get_tls_info(domain)
            
            # Response analysis
            result = {
                'timestamp': datetime.now().isoformat(),
                'url': full_url,
                'domain': domain,
                'ip_info': ip_info,
                'status_code': response.status_code,
                'rtt': round(rtt, 2),
                'response_size': len(response.content),
                'cdn_waf': cdn_waf,
                'security_headers': sec_headers,
                'missing_security_headers': missing_headers,
                'tls_info': tls_info,
                'is_https': scheme == 'https',
                'redirects': len(response.history),
                'final_url': response.url,
                'server': response.headers.get('Server', 'Unknown'),
                'content_type': response.headers.get('Content-Type', 'Unknown')
            }
            
            # Anomaly detection
            result['anomalies'] = SiteAnalyzer.detect_anomalies(result, domain)
            
            return result
            
        except requests.exceptions.Timeout:
            return {
                'error': 'timeout',
                'message': 'Timeout - site not responding',
                'timestamp': datetime.now().isoformat()
            }
        except requests.exceptions.ConnectionError:
            return {
                'error': 'connection',
                'message': 'Connection error',
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {
                'error': 'unknown',
                'message': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    @staticmethod
    def detect_anomalies(current_data, domain):
        """Detects anomalies by comparing with historical data"""
        anomalies = []
        history = site_history[domain]
        
        # Check timeout
        if current_data.get('rtt', 0) > 5000:
            anomalies.append('[!]: cVery high RTT (>5s)')
        
        # Check 5xx errors
        if 500 <= current_data.get('status_code', 200) < 600:
            anomalies.append('🚨 Server error (5xx)')
        
        # Check rate limiting
        if current_data.get('status_code') == 429:
            anomalies.append('⛔ Rate limiting active (429)')
        
        # Check WAF/CDN
        if current_data.get('cdn_waf'):
            anomalies.append(f"🛡️ Protection active: {', '.join(current_data['cdn_waf'])}")
        
        # Historical comparison
        if len(history) >= 3:
            # Sudden IP change
            recent_ips = [h['ip_info']['primary_ip'] for h in list(history)[-3:] if 'ip_info' in h and h['ip_info'].get('success')]
            current_ip = current_data.get('ip_info', {}).get('primary_ip')
            if current_ip and recent_ips and current_ip not in recent_ips:
                anomalies.append('🔄 IP change detected (possible failover/CDN)')
            
            # Unstable RTT
            recent_rtt = [h['rtt'] for h in list(history)[-5:] if 'rtt' in h]
            if recent_rtt and current_data.get('rtt'):
                avg_rtt = sum(recent_rtt) / len(recent_rtt)
                if current_data['rtt'] > avg_rtt * 2:
                    anomalies.append('📊 Unstable RTT (2x average)')
        
        # Save to history
        history.append(current_data)
        
        return anomalies

def format_analysis_message(data):
    """Formats the analysis message"""
    if 'error' in data:
        return f"❌ **ERROR**: {data['message']}\n⏰ {data['timestamp']}"
    
    msg = f"🌐 **WEBSITE ANALYSIS**\n"
    msg += f"━━━━━━━━━━━━━━━━━━━━\n\n"
    msg += f"🔗 **URL**: `{data['url']}`\n"
    msg += f"📅 **Date**: {data['timestamp']}\n\n"
    
    # IP Info
    msg += "🌍 **DNS RESOLUTION**\n"
    if data['ip_info']['success']:
        msg += f"├ Primary IP: `{data['ip_info']['primary_ip']}`\n"
        if len(data['ip_info']['all_ips']) > 1:
            msg += f"├ Other IPs: {len(data['ip_info']['all_ips']) - 1}\n"
            for ip in data['ip_info']['all_ips'][:3]:
                msg += f"│  └ `{ip}`\n"
    else:
        msg += f"└ ❌ Error: {data['ip_info']['error']}\n"
    
    msg += "\n📡 **HTTP RESPONSE ANALYSIS**\n"
    msg += f"├ Status: `{data['status_code']}`\n"
    msg += f"├ RTT: `{data['rtt']} ms`\n"
    msg += f"├ Size: `{data['response_size']:,} bytes`\n"
    msg += f"├ Server: `{data['server']}`\n"
    msg += f"└ Content-Type: `{data['content_type']}`\n"
    
    # CDN/WAF
    if data['cdn_waf']:
        msg += f"\n🛡️ **CDN/WAF DETECTED**\n"
        for cdn in data['cdn_waf']:
            msg += f"├ {cdn.upper()}\n"
    
    # TLS
    if data['tls_info'] and data['tls_info']['success']:
        msg += f"\n🔒 **TLS/SSL SECURITY**\n"
        msg += f"├ Version: `{data['tls_info']['tls_version']}`\n"
        msg += f"├ Cipher: `{data['tls_info']['cipher']}`\n"
        msg += f"└ Bits: `{data['tls_info']['bits']}`\n"
    elif data['is_https']:
        msg += f"\n⚠️ **TLS**: Analysis error\n"
    else:
        msg += f"\n⚠️ **INSECURE HTTP** - No encryption\n"
    
    # Security Headers
    if data['security_headers']:
        msg += f"\n✅ **SECURITY HEADERS PRESENT** ({len(data['security_headers'])})\n"
        for header in list(data['security_headers'].keys())[:3]:
            msg += f"├ {header}\n"
    
    if data['missing_security_headers']:
        msg += f"\n⚠️ **MISSING SECURITY HEADERS** ({len(data['missing_security_headers'])})\n"
        for header in data['missing_security_headers'][:3]:
            msg += f"├ {header}\n"
    
    # Anomalies
    if data['anomalies']:
        msg += f"\n🚨 **ANOMALIES DETECTED**\n"
        for anomaly in data['anomalies']:
            msg += f"├ {anomaly}\n"
    else:
        msg += f"\n✅ **No anomalies detected**\n"
    
    msg += f"\n━━━━━━━━━━━━━━━━━━━━"
    
    return msg

# Bot handlers
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handler for /start"""
    welcome_msg = """
🤖 **Advanced Website Monitoring Bot**

📋 **Available commands:**

/analyze <url> - Analyze a website
/monitor <url> <minutes> - Continuous monitoring
/stop_monitor <url> - Stop monitoring
/monitors - List active monitors
/history <url> - Analysis history
/help - Show this message

**Features:**
✅ DNS and IP resolution
✅ Response time analysis
✅ CDN/WAF detection
✅ TLS/SSL security checks
✅ Security headers
✅ Anomaly detection
✅ Continuous monitoring

Send a URL to get started!
"""
    await update.message.reply_text(welcome_msg, parse_mode='Markdown')

async def analyze_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handler for /analyze"""
    if not context.args:
        await update.message.reply_text("❌ Usage: /analyze <url>")
        return
    
    url = context.args[0]
    msg = await update.message.reply_text(f"🔍 Analyzing {url}...")
    
    data = await SiteAnalyzer.analyze_site(url)
    result = format_analysis_message(data)
    
    await msg.edit_text(result, parse_mode='Markdown')

async def monitor_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handler for /monitor"""
    if len(context.args) < 2:
        await update.message.reply_text("❌ Usage: /monitor <url> <minutes>")
        return
    
    url = context.args[0]
    try:
        interval = int(context.args[1])
        if interval < 1:
            raise ValueError
    except ValueError:
        await update.message.reply_text("❌ Interval must be >= 1 minute")
        return
    
    chat_id = update.effective_chat.id
    key = f"{chat_id}_{url}"
    
    if key in monitoring_tasks:
        await update.message.reply_text(f"⚠️ Monitoring already active for {url}")
        return
    
    async def monitor_loop():
        while key in monitoring_tasks:
            try:
                data = await SiteAnalyzer.analyze_site(url)
                result = format_analysis_message(data)
                
                # Send notification only if anomalies detected
                if data.get('anomalies'):
                    await context.bot.send_message(
                        chat_id=chat_id,
                        text=f"🚨 **MONITORING ALERT**\n\n{result}",
                        parse_mode='Markdown'
                    )
            except Exception as e:
                logger.error(f"Monitoring error: {e}")
            
            await asyncio.sleep(interval * 60)
    
    monitoring_tasks[key] = asyncio.create_task(monitor_loop())
    await update.message.reply_text(
        f"✅ Monitoring activated for `{url}`\n"
        f"📊 Interval: {interval} minutes\n"
        f"🔔 You'll receive notifications only for anomalies",
        parse_mode='Markdown'
    )

async def stop_monitor_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handler for /stop_monitor"""
    if not context.args:
        await update.message.reply_text("❌ Usage: /stop_monitor <url>")
        return
    
    url = context.args[0]
    chat_id = update.effective_chat.id
    key = f"{chat_id}_{url}"
    
    if key in monitoring_tasks:
        monitoring_tasks[key].cancel()
        del monitoring_tasks[key]
        await update.message.reply_text(f"✅ Monitoring stopped for `{url}`", parse_mode='Markdown')
    else:
        await update.message.reply_text(f"⚠️ No active monitoring for {url}")

async def monitors_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handler for /monitors"""
    chat_id = update.effective_chat.id
    active = [k.split('_', 1)[1] for k in monitoring_tasks.keys() if k.startswith(f"{chat_id}_")]
    
    if active:
        msg = "📊 **Active monitors:**\n\n"
        for url in active:
            msg += f"• `{url}`\n"
    else:
        msg = "ℹ️ No active monitors"
    
    await update.message.reply_text(msg, parse_mode='Markdown')

async def history_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handler for /history"""
    if not context.args:
        await update.message.reply_text("❌ Usage: /history <url>")
        return
    
    url = context.args[0]
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path
    
    history = list(site_history[domain])
    
    if not history:
        await update.message.reply_text(f"ℹ️ No history for {domain}")
        return
    
    msg = f"📊 **History for** `{domain}`\n\n"
    msg += f"Total analyses: {len(history)}\n\n"
    
    # Last 5 checks
    for data in reversed(list(history)[-5:]):
        status = data.get('status_code', 'N/A')
        rtt = data.get('rtt', 'N/A')
        timestamp = data.get('timestamp', '')[:19]
        anomalies = len(data.get('anomalies', []))
        
        msg += f"• {timestamp}\n"
        msg += f"  Status: {status} | RTT: {rtt}ms | Anomalies: {anomalies}\n\n"
    
    await update.message.reply_text(msg, parse_mode='Markdown')

async def message_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handler for generic messages (URLs)"""
    text = update.message.text
    
    # Check if it's a URL
    if text.startswith('http://') or text.startswith('https://') or '.' in text:
        msg = await update.message.reply_text(f"🔍 Analysis in progress...")
        data = await SiteAnalyzer.analyze_site(text)
        result = format_analysis_message(data)
        await msg.edit_text(result, parse_mode='Markdown')
    else:
        await update.message.reply_text(
            "❌ Send a valid URL or use /help to see commands"
        )

def main():
    """Starts the bot"""
    # INSERT YOUR TOKEN HERE
    TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN', '8503435544:AAGnEV-eT-R1p7519IM64FubVkDRbHHuxa8')
    
    if TOKEN == '8503435544:AAGnEV-eT-R1p7519IM64FubVkDRbHHuxa8E':
        print("❌ ERROR: Set the bot token!")
        print("Create a bot with @BotFather on Telegram and get the token")
        return
    
    # Create application
    application = Application.builder().token(TOKEN).build()
    
    # Handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", start))
    application.add_handler(CommandHandler("analyze", analyze_command))
    application.add_handler(CommandHandler("monitor", monitor_command))
    application.add_handler(CommandHandler("stop_monitor", stop_monitor_command))
    application.add_handler(CommandHandler("monitors", monitors_command))
    application.add_handler(CommandHandler("history", history_command))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, message_handler))
    
    # Start bot
    print("🤖 Bot started!")
    application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == '__main__':
    main()