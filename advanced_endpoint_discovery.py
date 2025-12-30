#!/usr/bin/env python3
"""
Advanced Endpoint Discovery Script with Proxy & mitmproxy Integration
========================================================================
Automatically discovers Stripe API endpoints through proxy-based traffic interception.
Targets 20 merchants with validated PK LIVE keys and successful PM creation.

Features:
- mitmproxy integration with custom addon for HTTPS interception
- Rotating proxy support (HTTP/HTTPS/SOCKS5)
- Playwright automation with stealth mode
- Deep form analysis and donation flow simulation
- Network traffic capture and HAR export
- CSRF token extraction and session management
- PaymentIntent/PaymentMethod detection
- Rate limiting and anti-detection measures

Author: Endpoint Discovery Team
Date: 2025-12-30
"""

import asyncio
import json
import logging
import os
import re
import sys
import time
import random
import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urljoin
import subprocess
import signal
import tempfile

try:
    from playwright.async_api import async_playwright, Browser, Page, BrowserContext
    from mitmproxy import http, ctx
    from mitmproxy.tools import main as mitmproxy_main
    import requests
    from bs4 import BeautifulSoup
    import aiohttp
    import aiofiles
except ImportError as e:
    print(f"Missing required dependency: {e}")
    print("Install with: pip install playwright mitmproxy requests beautifulsoup4 aiohttp aiofiles")
    print("Then run: playwright install chromium")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'endpoint_discovery_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Merchant configurations with validated keys
MERCHANTS_TO_INVESTIGATE = {
    'charitywater': {
        'pk': 'pk_live_51049Hm4QFaGycgRKOIbupRw7rf65FJESmPqWZk9Jtpf2YCvxnjMAFX7dOPAgoxv9M2wwhi5OwFBx1EzuoTxNzLJD00ViBbMvkQ',
        'url': 'https://www.charitywater.org'
    },
    'rescue': {
        'pk': 'pk_live_CtkeS5ERFt8WFLOqLKPZUeOI00Djba6QdB',
        'url': 'https://www.rescue.org'
    },
    'salvationarmy': {
        'pk': 'pk_live_h5ocNWNpicLCfBJvLialXsb900SaJnJscz',
        'url': 'https://give.salvationarmyusa.org'
    },
    'waterkeeper': {
        'pk': 'pk_live_T0LDuJcnjhAGRKVhfmLnjclt',
        'url': 'https://waterkeeper.org'
    },
    'lupus': {
        'pk': 'pk_live_9RzCojmneCvL31GhYTknluXp',
        'url': 'https://www.lupus.org'
    },
    'alzheimers': {
        'pk': 'pk_live_9RzCojmneCvL31GhYTknluXp',
        'url': 'https://www.alz.org'
    },
    'smiletrain': {
        'pk': 'pk_live_9RzCojmneCvL31GhYTknluXp',
        'url': 'https://www.smiletrain.org'
    },
    'donorschoose': {
        'pk': 'pk_live_51H2kayClFZfiknz0ZOHZW5F4awL951srQfyibbHj6AhPsJJMeW8DvslUQ1BlvylhWPJ1R1YNMYHdpL3PyG6ymKEu00dNyHWgR7',
        'url': 'https://www.donorschoose.org'
    },
    'sightsavers': {
        'pk': 'pk_live_2JzaEfxjGJR5ny5WBoEt9Jlf',
        'url': 'https://www.sightsavers.org'
    },
    'foe': {
        'pk': 'pk_live_BylsKC4SVafxEmGLTeTiLXS900bmJ6Mhpq',
        'url': 'https://foe.org'
    },
    'panthera': {
        'pk': 'pk_live_9RzCojmneCvL31GhYTknluXp',
        'url': 'https://www.panthera.org'
    },
    'libreoffice': {
        'pk': 'pk_live_awU8f7I5z9qGzhA6AEtRMjGJ',
        'url': 'https://www.libreoffice.org'
    },
    'opencollective': {
        'pk': 'pk_live_qZ0OnX69UlIL6pRODicRzsZy',
        'url': 'https://opencollective.com'
    },
    'fightforthefuture': {
        'pk': 'pk_live_EafGxYVfzZHJF4aUSVUJ94e0',
        'url': 'https://www.fightforthefuture.org'
    },
    'butterflyconservation': {
        'pk': 'pk_live_KDSciXvV13Av4FsHnqzhjusq',
        'url': 'https://www.saveourmonarchs.org'
    },
    'farmsanctuary': {
        'pk': 'pk_live_CtkeS5ERFt8WFLOqLKPZUeOI00Djba6QdB',
        'url': 'https://www.farmsanctuary.org'
    },
    'bumblebee': {
        'pk': 'pk_live_51JaLjfEDkZv2MuTmP21MEBqP48meMvvdBzlUtU8bPRUMUzUMcPjwPPcqlN5qvcz7aIp7iHbhQjJOomUGdyrDZOME00NHk9X4ci',
        'url': 'https://www.bumblebeeconservation.org'
    },
    'batsconservation': {
        'pk': 'pk_live_9RzCojmneCvL31GhYTknluXp',
        'url': 'https://www.batcon.org'
    },
    'mercyforanimals': {
        'pk': 'pk_live_CtkeS5ERFt8WFLOqLKPZUeOI00Djba6QdB',
        'url': 'https://mercyforanimals.org'
    },
    'monarchwatch': {
        'pk': 'pk_live_51Q7vDkDYIZnmBnvYoovSN2foPGDD19AeIzHfYe6ggoNPJInF0ZuZKhCAFQxHks843awqm8uyRbmnTo3C33jdVyeo00cgGNrNOB',
        'url': 'https://monarchwatch.org'
    },
    'texastribune': {
        'pk': 'pk_live_oWRzKZVrLxfbSSWJrWgxuVWc',
        'url': 'https://www.texastribune.org'
    }
}

# Stripe API patterns
STRIPE_PATTERNS = {
    'payment_intents': r'(/v1/payment_intents|/payment_intents/[a-zA-Z0-9_]+)',
    'payment_methods': r'(/v1/payment_methods|/payment_methods/[a-zA-Z0-9_]+)',
    'tokens': r'/v1/tokens',
    'sources': r'/v1/sources',
    'setup_intents': r'/v1/setup_intents',
    'customers': r'/v1/customers',
    'charges': r'/v1/charges',
}

# Configuration
MITMPROXY_PORT = 8080
MITMPROXY_HOST = 'localhost'
OUTPUT_DIR = Path('./endpoint_discovery_results')
OUTPUT_DIR.mkdir(exist_ok=True)

# Test card data
TEST_CARD = {
    'number': '4242424242424242',
    'exp_month': '12',
    'exp_year': '2029',
    'cvc': '123',
    'name': 'Test Donor',
    'email': 'donor@example.com',
    'address_line1': '123 Test St',
    'address_city': 'Test City',
    'address_state': 'CA',
    'address_zip': '90210',
    'address_country': 'US'
}

# Proxy configuration (example proxies - replace with real rotating proxy service)
PROXY_LIST = [
    # Format: {"server": "http://proxy:port", "username": "user", "password": "pass"}
    # Add your rotating proxies here
]


@dataclass
class EndpointDiscovery:
    """Captured endpoint information"""
    merchant: str
    url: str
    method: str
    endpoint: str
    headers: Dict[str, str]
    request_body: Optional[str]
    response_body: Optional[str]
    status_code: int
    timestamp: str
    pk_used: str
    endpoint_type: str
    csrf_token: Optional[str] = None
    payment_intent_id: Optional[str] = None
    payment_method_id: Optional[str] = None
    client_secret: Optional[str] = None


class StripeInterceptorAddon:
    """mitmproxy addon to intercept and analyze Stripe API calls"""
    
    def __init__(self, output_file: str):
        self.output_file = output_file
        self.discoveries = []
        self.current_merchant = None
        self.current_pk = None
        
    def set_merchant_context(self, merchant: str, pk: str):
        """Set current merchant context for tracking"""
        self.current_merchant = merchant
        self.current_pk = pk
        
    def request(self, flow: http.HTTPFlow) -> None:
        """Intercept and log requests"""
        url = flow.request.pretty_url
        
        # Check if this is a Stripe API call
        if 'stripe.com' in url or 'api.stripe.com' in url:
            logger.info(f"🔍 Intercepted Stripe API call: {flow.request.method} {url}")
            
            # Extract endpoint type
            endpoint_type = self._classify_endpoint(url)
            
            # Log request details
            logger.debug(f"Headers: {dict(flow.request.headers)}")
            if flow.request.content:
                logger.debug(f"Body: {flow.request.content.decode('utf-8', errors='ignore')[:500]}")
    
    def response(self, flow: http.HTTPFlow) -> None:
        """Intercept and analyze responses"""
        url = flow.request.pretty_url
        
        # Only process Stripe API calls
        if 'stripe.com' not in url and 'api.stripe.com' not in url:
            return
            
        try:
            # Extract request body
            request_body = None
            if flow.request.content:
                request_body = flow.request.content.decode('utf-8', errors='ignore')
            
            # Extract response body
            response_body = None
            if flow.response and flow.response.content:
                response_body = flow.response.content.decode('utf-8', errors='ignore')
            
            # Classify endpoint
            endpoint_type = self._classify_endpoint(url)
            
            # Extract Stripe IDs from response
            payment_intent_id = None
            payment_method_id = None
            client_secret = None
            
            if response_body:
                try:
                    response_json = json.loads(response_body)
                    payment_intent_id = response_json.get('id') if 'pi_' in response_json.get('id', '') else None
                    payment_method_id = response_json.get('id') if 'pm_' in response_json.get('id', '') else None
                    client_secret = response_json.get('client_secret')
                except json.JSONDecodeError:
                    pass
            
            # Create discovery record
            discovery = EndpointDiscovery(
                merchant=self.current_merchant or 'unknown',
                url=flow.request.pretty_url,
                method=flow.request.method,
                endpoint=flow.request.path,
                headers=dict(flow.request.headers),
                request_body=request_body,
                response_body=response_body,
                status_code=flow.response.status_code if flow.response else 0,
                timestamp=datetime.now().isoformat(),
                pk_used=self.current_pk or 'unknown',
                endpoint_type=endpoint_type,
                payment_intent_id=payment_intent_id,
                payment_method_id=payment_method_id,
                client_secret=client_secret
            )
            
            self.discoveries.append(discovery)
            
            # Save incrementally
            self._save_discoveries()
            
            logger.info(f"✅ Captured {endpoint_type} endpoint for {self.current_merchant}")
            logger.info(f"   Status: {flow.response.status_code if flow.response else 'N/A'}")
            
        except Exception as e:
            logger.error(f"Error processing response: {e}")
    
    def _classify_endpoint(self, url: str) -> str:
        """Classify the type of Stripe endpoint"""
        for endpoint_type, pattern in STRIPE_PATTERNS.items():
            if re.search(pattern, url):
                return endpoint_type
        return 'other'
    
    def _save_discoveries(self):
        """Save discoveries to file"""
        try:
            with open(self.output_file, 'w') as f:
                json.dump([asdict(d) for d in self.discoveries], f, indent=2)
        except Exception as e:
            logger.error(f"Error saving discoveries: {e}")
    
    def get_discoveries(self) -> List[EndpointDiscovery]:
        """Get all discoveries"""
        return self.discoveries


class ProxyRotator:
    """Manages proxy rotation"""
    
    def __init__(self, proxies: List[Dict[str, str]]):
        self.proxies = proxies
        self.current_index = 0
        
    def get_next_proxy(self) -> Optional[Dict[str, str]]:
        """Get next proxy in rotation"""
        if not self.proxies:
            return None
            
        proxy = self.proxies[self.current_index]
        self.current_index = (self.current_index + 1) % len(self.proxies)
        return proxy
    
    def get_random_proxy(self) -> Optional[Dict[str, str]]:
        """Get random proxy"""
        if not self.proxies:
            return None
        return random.choice(self.proxies)


class MitmproxyManager:
    """Manages mitmproxy subprocess"""
    
    def __init__(self, port: int = MITMPROXY_PORT):
        self.port = port
        self.process = None
        self.addon_file = None
        self.output_file = OUTPUT_DIR / f'mitmproxy_flows_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        
    async def start(self) -> StripeInterceptorAddon:
        """Start mitmproxy with custom addon"""
        logger.info(f"🚀 Starting mitmproxy on port {self.port}...")
        
        # Create addon script
        addon_code = f'''
import json
from mitmproxy import http
from datetime import datetime

class StripeInterceptor:
    def __init__(self):
        self.discoveries = []
        self.output_file = "{self.output_file}"
        
    def response(self, flow: http.HTTPFlow):
        url = flow.request.pretty_url
        if "stripe.com" in url or "api.stripe.com" in url:
            discovery = {{
                "url": url,
                "method": flow.request.method,
                "headers": dict(flow.request.headers),
                "status": flow.response.status_code if flow.response else 0,
                "timestamp": datetime.now().isoformat()
            }}
            self.discoveries.append(discovery)
            with open(self.output_file, 'w') as f:
                json.dump(self.discoveries, f, indent=2)

addons = [StripeInterceptor()]
'''
        
        # Write addon to temp file
        self.addon_file = tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False)
        self.addon_file.write(addon_code)
        self.addon_file.close()
        
        # Start mitmproxy in background
        cmd = [
            'mitmdump',
            '-p', str(self.port),
            '-s', self.addon_file.name,
            '--set', 'block_global=false',
            '--ssl-insecure'
        ]
        
        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid if hasattr(os, 'setsid') else None
            )
            
            # Wait for mitmproxy to start
            await asyncio.sleep(3)
            logger.info(f"✅ mitmproxy started successfully on port {self.port}")
            
        except Exception as e:
            logger.error(f"Failed to start mitmproxy: {e}")
            raise
        
        # Return addon instance
        return StripeInterceptorAddon(str(self.output_file))
    
    def stop(self):
        """Stop mitmproxy"""
        if self.process:
            logger.info("🛑 Stopping mitmproxy...")
            try:
                if hasattr(os, 'killpg'):
                    os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
                else:
                    self.process.terminate()
                self.process.wait(timeout=5)
            except Exception as e:
                logger.error(f"Error stopping mitmproxy: {e}")
                if self.process:
                    self.process.kill()
        
        # Clean up addon file
        if self.addon_file and os.path.exists(self.addon_file.name):
            os.unlink(self.addon_file.name)


class AdvancedEndpointDiscovery:
    """Main endpoint discovery orchestrator"""
    
    def __init__(self):
        self.proxy_rotator = ProxyRotator(PROXY_LIST)
        self.mitm_manager = MitmproxyManager()
        self.addon = None
        self.all_discoveries = []
        self.browser = None
        self.playwright = None
        
    async def initialize(self):
        """Initialize the discovery system"""
        logger.info("🔧 Initializing Advanced Endpoint Discovery System...")
        
        # Start mitmproxy
        self.addon = await self.mitm_manager.start()
        
        # Initialize Playwright
        self.playwright = await async_playwright().start()
        
        logger.info("✅ Initialization complete")
    
    async def cleanup(self):
        """Cleanup resources"""
        logger.info("🧹 Cleaning up resources...")
        
        if self.browser:
            await self.browser.close()
        
        if self.playwright:
            await self.playwright.stop()
        
        self.mitm_manager.stop()
        
        logger.info("✅ Cleanup complete")
    
    async def create_browser_context(self, proxy: Optional[Dict[str, str]] = None) -> BrowserContext:
        """Create browser context with proxy configuration"""
        launch_options = {
            'headless': True,
            'args': [
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',
                '--disable-blink-features=AutomationControlled',
                f'--proxy-server={MITMPROXY_HOST}:{MITMPROXY_PORT}'
            ]
        }
        
        # Launch browser if not already running
        if not self.browser:
            self.browser = await self.playwright.chromium.launch(**launch_options)
        
        # Create context with stealth settings
        context_options = {
            'viewport': {'width': 1920, 'height': 1080},
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'ignore_https_errors': True,
            'java_script_enabled': True,
        }
        
        # Add external proxy if provided
        if proxy:
            context_options['proxy'] = proxy
        
        context = await self.browser.new_context(**context_options)
        
        # Inject stealth scripts
        await context.add_init_script("""
            Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
            Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3]});
            Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
        """)
        
        return context
    
    async def discover_donation_page(self, merchant: str, base_url: str) -> Optional[str]:
        """Discover donation/payment page for merchant"""
        logger.info(f"🔍 Searching for donation page: {merchant}")
        
        common_paths = [
            '/donate', '/donation', '/give', '/support', '/contribute',
            '/help', '/join', '/membership', '/checkout', '/cart'
        ]
        
        try:
            async with aiohttp.ClientSession() as session:
                for path in common_paths:
                    url = urljoin(base_url, path)
                    try:
                        async with session.get(url, timeout=10, allow_redirects=True) as response:
                            if response.status == 200:
                                text = await response.text()
                                # Check for payment forms or Stripe elements
                                if any(keyword in text.lower() for keyword in ['stripe', 'payment', 'card', 'donate']):
                                    logger.info(f"✅ Found donation page: {url}")
                                    return str(response.url)
                    except Exception as e:
                        logger.debug(f"Path {path} not found: {e}")
                        continue
                
                # Try homepage as fallback
                logger.warning(f"⚠️  No specific donation page found, using homepage: {base_url}")
                return base_url
                
        except Exception as e:
            logger.error(f"Error discovering donation page: {e}")
            return base_url
    
    async def analyze_page(self, page: Page, merchant: str, pk: str) -> Dict[str, Any]:
        """Analyze page for payment forms and Stripe integration"""
        logger.info(f"📊 Analyzing page for {merchant}...")
        
        analysis = {
            'forms': [],
            'stripe_elements': [],
            'payment_buttons': [],
            'csrf_tokens': [],
            'api_endpoints': []
        }
        
        try:
            # Wait for page load
            await page.wait_for_load_state('networkidle', timeout=30000)
            
            # Extract all forms
            forms = await page.query_selector_all('form')
            for form in forms:
                form_data = await self._extract_form_data(form)
                analysis['forms'].append(form_data)
            
            # Look for Stripe Elements
            stripe_elements = await page.query_selector_all('[class*="stripe"], [id*="stripe"], [class*="payment"], [id*="payment"]')
            for element in stripe_elements:
                element_info = await self._extract_element_info(element)
                analysis['stripe_elements'].append(element_info)
            
            # Find payment buttons
            buttons = await page.query_selector_all('button, input[type="submit"], a[class*="donate"], a[class*="payment"]')
            for button in buttons:
                button_text = await button.inner_text() if await button.is_visible() else ''
                if any(keyword in button_text.lower() for keyword in ['donate', 'pay', 'contribute', 'give', 'submit']):
                    analysis['payment_buttons'].append({
                        'text': button_text,
                        'selector': await self._get_selector(button)
                    })
            
            # Extract CSRF tokens
            csrf_inputs = await page.query_selector_all('input[name*="csrf"], input[name*="token"], meta[name*="csrf"]')
            for csrf in csrf_inputs:
                token_value = await csrf.get_attribute('value') or await csrf.get_attribute('content')
                if token_value:
                    analysis['csrf_tokens'].append(token_value)
            
            # Capture network requests
            analysis['api_endpoints'] = await self._capture_network_activity(page)
            
        except Exception as e:
            logger.error(f"Error analyzing page: {e}")
        
        return analysis
    
    async def simulate_donation_flow(self, page: Page, merchant: str, pk: str, analysis: Dict[str, Any]):
        """Simulate donation flow to trigger API calls"""
        logger.info(f"🎭 Simulating donation flow for {merchant}...")
        
        try:
            # Set merchant context for addon
            if self.addon:
                self.addon.set_merchant_context(merchant, pk)
            
            # Random wait to appear human
            await asyncio.sleep(random.uniform(2, 5))
            
            # Try to find and fill amount field
            amount_filled = await self._fill_amount_field(page)
            
            # Try to find and click donation button
            if analysis['payment_buttons']:
                button_selector = analysis['payment_buttons'][0]['selector']
                try:
                    await page.click(button_selector, timeout=5000)
                    await page.wait_for_load_state('networkidle', timeout=15000)
                    logger.info(f"✅ Clicked donation button")
                except Exception as e:
                    logger.debug(f"Could not click button: {e}")
            
            # Wait for Stripe Elements to load
            await asyncio.sleep(3)
            
            # Try to fill card information
            await self._fill_payment_form(page, pk)
            
            # Look for submit button
            await self._try_submit_payment(page)
            
            # Wait for API calls to complete
            await asyncio.sleep(5)
            
        except Exception as e:
            logger.error(f"Error simulating donation flow: {e}")
    
    async def _fill_amount_field(self, page: Page) -> bool:
        """Fill donation amount field"""
        amount_selectors = [
            'input[name*="amount"]',
            'input[id*="amount"]',
            'input[type="number"]',
            'input[placeholder*="amount"]'
        ]
        
        for selector in amount_selectors:
            try:
                element = await page.query_selector(selector)
                if element and await element.is_visible():
                    await element.fill('25')
                    logger.info(f"✅ Filled amount field: $25")
                    return True
            except Exception:
                continue
        
        # Try clicking preset amount button
        preset_buttons = await page.query_selector_all('button:has-text("$"), a:has-text("$")')
        for button in preset_buttons:
            try:
                if await button.is_visible():
                    await button.click()
                    logger.info(f"✅ Selected preset amount")
                    return True
            except Exception:
                continue
        
        return False
    
    async def _fill_payment_form(self, page: Page, pk: str):
        """Fill payment form with test data"""
        logger.info("💳 Filling payment form...")
        
        try:
            # Try to find Stripe iframe
            frames = page.frames
            stripe_frame = None
            
            for frame in frames:
                if 'stripe' in frame.url.lower():
                    stripe_frame = frame
                    break
            
            # Fill card number
            card_selectors = [
                'input[name="cardnumber"]',
                'input[placeholder*="card number"]',
                'input[id*="card-number"]',
                '#card-number',
                '[data-elements-stable-field-name="cardNumber"]'
            ]
            
            for selector in card_selectors:
                try:
                    if stripe_frame:
                        element = await stripe_frame.query_selector(selector)
                    else:
                        element = await page.query_selector(selector)
                    
                    if element and await element.is_visible():
                        await element.fill(TEST_CARD['number'])
                        logger.info("✅ Filled card number")
                        break
                except Exception:
                    continue
            
            # Fill expiry
            exp_selectors = [
                'input[name="exp-date"]',
                'input[placeholder*="MM"]',
                'input[id*="expiry"]'
            ]
            
            for selector in exp_selectors:
                try:
                    element = await page.query_selector(selector)
                    if element and await element.is_visible():
                        await element.fill(f"{TEST_CARD['exp_month']}{TEST_CARD['exp_year'][-2:]}")
                        break
                except Exception:
                    continue
            
            # Fill CVC
            cvc_selectors = [
                'input[name="cvc"]',
                'input[placeholder*="CVC"]',
                'input[id*="cvc"]'
            ]
            
            for selector in cvc_selectors:
                try:
                    element = await page.query_selector(selector)
                    if element and await element.is_visible():
                        await element.fill(TEST_CARD['cvc'])
                        break
                except Exception:
                    continue
            
            # Fill name and email
            await self._fill_text_field(page, ['input[name="name"]', 'input[id*="name"]'], TEST_CARD['name'])
            await self._fill_text_field(page, ['input[type="email"]', 'input[name="email"]'], TEST_CARD['email'])
            
        except Exception as e:
            logger.error(f"Error filling payment form: {e}")
    
    async def _fill_text_field(self, page: Page, selectors: List[str], value: str):
        """Fill text field with value"""
        for selector in selectors:
            try:
                element = await page.query_selector(selector)
                if element and await element.is_visible():
                    await element.fill(value)
                    return True
            except Exception:
                continue
        return False
    
    async def _try_submit_payment(self, page: Page):
        """Try to submit payment form"""
        submit_selectors = [
            'button[type="submit"]',
            'input[type="submit"]',
            'button:has-text("Donate")',
            'button:has-text("Pay")',
            'button:has-text("Submit")',
            'button:has-text("Complete")'
        ]
        
        for selector in submit_selectors:
            try:
                element = await page.query_selector(selector)
                if element and await element.is_visible():
                    logger.info(f"🎯 Found submit button: {selector}")
                    # Don't actually submit to avoid charges, just trigger validation
                    await element.hover()
                    await asyncio.sleep(2)
                    return True
            except Exception:
                continue
        
        return False
    
    async def _extract_form_data(self, form) -> Dict[str, Any]:
        """Extract form data"""
        try:
            action = await form.get_attribute('action')
            method = await form.get_attribute('method')
            inputs = await form.query_selector_all('input, select, textarea')
            
            fields = []
            for inp in inputs:
                name = await inp.get_attribute('name')
                input_type = await inp.get_attribute('type')
                if name:
                    fields.append({'name': name, 'type': input_type})
            
            return {
                'action': action,
                'method': method,
                'fields': fields
            }
        except Exception:
            return {}
    
    async def _extract_element_info(self, element) -> Dict[str, Any]:
        """Extract element information"""
        try:
            tag = await element.evaluate('el => el.tagName')
            classes = await element.get_attribute('class')
            id_attr = await element.get_attribute('id')
            
            return {
                'tag': tag,
                'class': classes,
                'id': id_attr
            }
        except Exception:
            return {}
    
    async def _get_selector(self, element) -> str:
        """Get CSS selector for element"""
        try:
            selector = await element.evaluate('''
                el => {
                    if (el.id) return '#' + el.id;
                    if (el.className) return '.' + el.className.split(' ')[0];
                    return el.tagName.toLowerCase();
                }
            ''')
            return selector
        except Exception:
            return 'unknown'
    
    async def _capture_network_activity(self, page: Page) -> List[str]:
        """Capture network requests"""
        endpoints = []
        
        def handle_request(request):
            url = request.url
            if 'stripe' in url or 'api' in url:
                endpoints.append(url)
        
        page.on('request', handle_request)
        await asyncio.sleep(2)
        
        return endpoints
    
    async def process_merchant(self, merchant: str, config: Dict[str, str]):
        """Process a single merchant"""
        logger.info(f"\n{'='*80}")
        logger.info(f"🎯 Processing Merchant: {merchant.upper()}")
        logger.info(f"{'='*80}")
        
        pk = config['pk']
        base_url = config['url']
        
        context = None
        page = None
        
        try:
            # Get proxy
            proxy = self.proxy_rotator.get_random_proxy()
            if proxy:
                logger.info(f"🔄 Using proxy: {proxy['server']}")
            
            # Create browser context
            context = await self.create_browser_context(proxy)
            page = await context.new_page()
            
            # Discover donation page
            donation_url = await self.discover_donation_page(merchant, base_url)
            
            # Navigate to donation page
            logger.info(f"🌐 Navigating to: {donation_url}")
            await page.goto(donation_url, wait_until='networkidle', timeout=60000)
            
            # Analyze page
            analysis = await self.analyze_page(page, merchant, pk)
            logger.info(f"📊 Found {len(analysis['forms'])} forms, {len(analysis['payment_buttons'])} payment buttons")
            
            # Simulate donation flow
            await self.simulate_donation_flow(page, merchant, pk, analysis)
            
            # Wait for all network activity to complete
            await asyncio.sleep(5)
            
            logger.info(f"✅ Completed processing {merchant}")
            
        except Exception as e:
            logger.error(f"❌ Error processing {merchant}: {e}")
            
        finally:
            if page:
                await page.close()
            if context:
                await context.close()
            
            # Rate limiting
            await asyncio.sleep(random.uniform(5, 10))
    
    async def run(self):
        """Run the endpoint discovery process"""
        logger.info("\n" + "="*80)
        logger.info("🚀 ADVANCED ENDPOINT DISCOVERY - STARTING")
        logger.info("="*80 + "\n")
        
        try:
            await self.initialize()
            
            # Process each merchant
            for merchant, config in MERCHANTS_TO_INVESTIGATE.items():
                await self.process_merchant(merchant, config)
            
            # Generate reports
            await self.generate_reports()
            
            logger.info("\n" + "="*80)
            logger.info("✅ ENDPOINT DISCOVERY COMPLETED SUCCESSFULLY")
            logger.info("="*80 + "\n")
            
        except Exception as e:
            logger.error(f"❌ Fatal error: {e}")
            raise
            
        finally:
            await self.cleanup()
    
    async def generate_reports(self):
        """Generate comprehensive reports"""
        logger.info("\n📊 Generating reports...")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Get all discoveries from addon
        if self.addon:
            discoveries = self.addon.get_discoveries()
            
            # Save full endpoint details
            endpoint_file = OUTPUT_DIR / f'DISCOVERED_ENDPOINTS_{timestamp}.json'
            with open(endpoint_file, 'w') as f:
                json.dump([asdict(d) for d in discoveries], f, indent=2)
            logger.info(f"✅ Saved endpoint details: {endpoint_file}")
            
            # Generate working configs
            working_configs = self._generate_working_configs(discoveries)
            config_file = OUTPUT_DIR / f'WORKING_CONFIGS_{timestamp}.json'
            with open(config_file, 'w') as f:
                json.dump(working_configs, f, indent=2)
            logger.info(f"✅ Saved working configs: {config_file}")
            
            # Generate summary report
            summary = self._generate_summary(discoveries)
            summary_file = OUTPUT_DIR / f'DISCOVERY_SUMMARY_{timestamp}.txt'
            with open(summary_file, 'w') as f:
                f.write(summary)
            logger.info(f"✅ Saved summary report: {summary_file}")
            
            logger.info(f"\n📈 Discovery Statistics:")
            logger.info(f"   Total Endpoints Discovered: {len(discoveries)}")
            logger.info(f"   Merchants with Endpoints: {len(set(d.merchant for d in discoveries))}")
            logger.info(f"   PaymentIntents Created: {sum(1 for d in discoveries if d.payment_intent_id)}")
            logger.info(f"   PaymentMethods Created: {sum(1 for d in discoveries if d.payment_method_id)}")
    
    def _generate_working_configs(self, discoveries: List[EndpointDiscovery]) -> Dict[str, Any]:
        """Generate ready-to-use configurations"""
        configs = {}
        
        for discovery in discoveries:
            if discovery.merchant not in configs:
                configs[discovery.merchant] = {
                    'merchant': discovery.merchant,
                    'pk': discovery.pk_used,
                    'endpoints': [],
                    'working_flows': []
                }
            
            endpoint_config = {
                'type': discovery.endpoint_type,
                'url': discovery.url,
                'method': discovery.method,
                'headers': discovery.headers,
                'success': discovery.status_code in [200, 201, 202],
                'timestamp': discovery.timestamp
            }
            
            if discovery.payment_intent_id:
                endpoint_config['payment_intent_id'] = discovery.payment_intent_id
            if discovery.client_secret:
                endpoint_config['client_secret'] = discovery.client_secret
            
            configs[discovery.merchant]['endpoints'].append(endpoint_config)
        
        return configs
    
    def _generate_summary(self, discoveries: List[EndpointDiscovery]) -> str:
        """Generate summary report"""
        summary = []
        summary.append("="*80)
        summary.append("ENDPOINT DISCOVERY SUMMARY REPORT")
        summary.append("="*80)
        summary.append(f"\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        summary.append(f"Total Discoveries: {len(discoveries)}")
        summary.append("\n" + "-"*80)
        
        # Group by merchant
        by_merchant = {}
        for d in discoveries:
            if d.merchant not in by_merchant:
                by_merchant[d.merchant] = []
            by_merchant[d.merchant].append(d)
        
        for merchant, merchant_discoveries in sorted(by_merchant.items()):
            summary.append(f"\n🏪 {merchant.upper()}")
            summary.append(f"   Endpoints Discovered: {len(merchant_discoveries)}")
            summary.append(f"   PK Used: {merchant_discoveries[0].pk_used}")
            
            # Endpoint types
            types = {}
            for d in merchant_discoveries:
                types[d.endpoint_type] = types.get(d.endpoint_type, 0) + 1
            
            summary.append("   Endpoint Types:")
            for endpoint_type, count in sorted(types.items()):
                summary.append(f"      - {endpoint_type}: {count}")
            
            # Success rate
            successful = sum(1 for d in merchant_discoveries if 200 <= d.status_code < 300)
            success_rate = (successful / len(merchant_discoveries) * 100) if merchant_discoveries else 0
            summary.append(f"   Success Rate: {success_rate:.1f}%")
            
            # Payment IDs
            pi_count = sum(1 for d in merchant_discoveries if d.payment_intent_id)
            pm_count = sum(1 for d in merchant_discoveries if d.payment_method_id)
            if pi_count:
                summary.append(f"   PaymentIntents: {pi_count}")
            if pm_count:
                summary.append(f"   PaymentMethods: {pm_count}")
        
        summary.append("\n" + "="*80)
        summary.append("END OF REPORT")
        summary.append("="*80)
        
        return "\n".join(summary)


async def main():
    """Main entry point"""
    print("""
    ╔═══════════════════════════════════════════════════════════════════╗
    ║     ADVANCED ENDPOINT DISCOVERY SYSTEM                            ║
    ║     Proxy-Based HTTPS Traffic Interception & Analysis             ║
    ║     Version 2.0                                                    ║
    ╚═══════════════════════════════════════════════════════════════════╝
    """)
    
    # Check dependencies
    try:
        import mitmproxy
        import playwright
        logger.info("✅ All dependencies found")
    except ImportError as e:
        logger.error(f"❌ Missing dependency: {e}")
        logger.error("Install with: pip install mitmproxy playwright aiohttp aiofiles beautifulsoup4")
        logger.error("Then run: playwright install chromium")
        sys.exit(1)
    
    # Create and run discovery system
    discovery = AdvancedEndpointDiscovery()
    
    try:
        await discovery.run()
    except KeyboardInterrupt:
        logger.info("\n⚠️  Interrupted by user")
        await discovery.cleanup()
    except Exception as e:
        logger.error(f"❌ Fatal error: {e}")
        await discovery.cleanup()
        raise


if __name__ == "__main__":
    asyncio.run(main())
