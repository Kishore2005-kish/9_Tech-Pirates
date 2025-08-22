from fastapi import FastAPI, APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timezone, timedelta
import hashlib
import jwt
import ssl
import socket
import requests
import time
from urllib.parse import urlparse
import re
import asyncio
import aiohttp
from bs4 import BeautifulSoup
import json

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app without a prefix
app = FastAPI()

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# JWT Secret
JWT_SECRET = "website_audit_secret_key_2024"
security = HTTPBearer()

# Models
class User(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    email: EmailStr
    password_hash: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class Website(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    url: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class WebsiteCreate(BaseModel):
    url: str

class AuditReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    website_id: str
    audit_type: str  # 'Security', 'Performance', 'SEO', 'Accessibility', 'All'
    score: int
    issues: List[Dict[str, Any]]
    recommendations: List[str]
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class AuditRequest(BaseModel):
    website_id: str
    audit_type: str = "All"  # 'Security', 'Performance', 'SEO', 'Accessibility', 'All'

# Utility functions
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password: str, hashed: str) -> bool:
    return hash_password(password) == hashed

def create_token(user_id: str) -> str:
    payload = {
        "user_id": user_id,
        "exp": datetime.now(timezone.utc) + timedelta(days=7)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=["HS256"])
        user_id = payload.get("user_id")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        user = await db.users.find_one({"id": user_id})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        
        return User(**user)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Audit Scripts
class WebsiteAuditor:
    @staticmethod
    async def audit_security(url: str) -> Dict[str, Any]:
        """Perform comprehensive security audit"""
        try:
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname
            port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
            
            issues = []
            score = 100
            
            # Check HTTPS
            if parsed_url.scheme != 'https':
                issues.append({
                    "severity": "critical",
                    "issue": "Website does not use HTTPS",
                    "description": "The website is not secured with SSL/TLS encryption",
                    "impact": "Data transmission is unencrypted and vulnerable to interception"
                })
                score -= 50
            else:
                try:
                    # Check SSL certificate
                    context = ssl.create_default_context()
                    with socket.create_connection((hostname, port), timeout=10) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            cert = ssock.getpeercert()
                            
                            # Check certificate expiry
                            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                            days_until_expiry = (not_after - datetime.now()).days
                            
                            if days_until_expiry < 30:
                                issues.append({
                                    "severity": "high" if days_until_expiry < 7 else "medium",
                                    "issue": "SSL certificate expires soon",
                                    "description": f"Certificate expires in {days_until_expiry} days",
                                    "impact": "Website will become inaccessible when certificate expires"
                                })
                                score -= 30 if days_until_expiry < 7 else 15
                except Exception as e:
                    issues.append({
                        "severity": "high",
                        "issue": "SSL certificate validation failed",
                        "description": f"Could not validate SSL certificate: {str(e)}",
                        "impact": "Unable to verify SSL security"
                    })
                    score -= 30
            
            # Check security headers
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=30) as response:
                    headers = response.headers
                    
                    # Check for security headers
                    security_headers = {
                        'Strict-Transport-Security': 'HSTS header missing - forces HTTPS',
                        'X-Content-Type-Options': 'MIME type sniffing protection missing',
                        'X-Frame-Options': 'Clickjacking protection missing',
                        'X-XSS-Protection': 'XSS protection header missing',
                        'Content-Security-Policy': 'Content Security Policy missing',
                        'Referrer-Policy': 'Referrer policy not configured'
                    }
                    
                    for header, description in security_headers.items():
                        if header not in headers:
                            severity = "high" if header in ['Strict-Transport-Security', 'Content-Security-Policy'] else "medium"
                            issues.append({
                                "severity": severity,
                                "issue": f"Missing {header} header",
                                "description": description,
                                "impact": "Reduced protection against various web attacks"
                            })
                            score -= 15 if severity == "high" else 8
                    
                    # Check for insecure headers
                    server_header = headers.get('Server', '')
                    if server_header:
                        issues.append({
                            "severity": "low",
                            "issue": "Server header reveals software information",
                            "description": f"Server: {server_header}",
                            "impact": "Information disclosure may help attackers"
                        })
                        score -= 5
                    
                    # Check content for potential vulnerabilities
                    content = await response.text()
                    soup = BeautifulSoup(content, 'html.parser')
                    
                    # Check for inline JavaScript (potential XSS risk)
                    inline_scripts = soup.find_all('script', src=False)
                    if len(inline_scripts) > 2:
                        issues.append({
                            "severity": "medium",
                            "issue": "Multiple inline JavaScript blocks detected",
                            "description": f"Found {len(inline_scripts)} inline script blocks",
                            "impact": "Increased XSS attack surface"
                        })
                        score -= 10
                    
                    # Check for forms without CSRF protection indicators
                    forms = soup.find_all('form')
                    for form in forms:
                        if not form.find('input', {'name': re.compile(r'csrf|token', re.I)}):
                            issues.append({
                                "severity": "medium",
                                "issue": "Form potentially missing CSRF protection",
                                "description": "Form found without apparent CSRF token",
                                "impact": "Vulnerable to Cross-Site Request Forgery attacks"
                            })
                            score -= 12
                            break  # Only report once
                    
                    # Check for mixed content
                    if parsed_url.scheme == 'https':
                        http_resources = re.findall(r'http://[^\s"\'<>]+', content)
                        if http_resources:
                            issues.append({
                                "severity": "medium",
                                "issue": "Mixed content detected",
                                "description": f"Found {len(http_resources)} HTTP resources on HTTPS page",
                                "impact": "Browsers may block insecure content"
                            })
                            score -= 15
            
            return {
                "score": max(0, score),
                "issues": issues,
                "recommendations": [
                    "Enable HTTPS for all pages and resources",
                    "Implement security headers (HSTS, CSP, X-Frame-Options)",
                    "Use CSRF tokens in all forms",
                    "Remove or obscure server information headers",
                    "Implement Content Security Policy",
                    "Regular security updates and vulnerability scanning",
                    "Use secure coding practices to prevent XSS"
                ]
            }
            
        except Exception as e:
            return {
                "score": 0,
                "issues": [{
                    "severity": "critical",
                    "issue": "Security audit failed",
                    "description": f"Could not perform security audit: {str(e)}",
                    "impact": "Unable to assess security posture"
                }],
                "recommendations": ["Ensure website is accessible and try again"]
            }

    @staticmethod
    async def audit_performance(url: str) -> Dict[str, Any]:
        """Perform comprehensive performance audit"""
        try:
            issues = []
            score = 100
            
            # Measure page load time and collect metrics
            start_time = time.time()
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=30) as response:
                    content = await response.text()
                    load_time = time.time() - start_time
                    
                    # Response time analysis
                    if load_time > 5:
                        issues.append({
                            "severity": "critical",
                            "issue": "Very slow page load time",
                            "description": f"Page took {load_time:.2f} seconds to load (should be under 3s)",
                            "impact": "Users likely to abandon page, poor search rankings"
                        })
                        score -= 40
                    elif load_time > 3:
                        issues.append({
                            "severity": "high",
                            "issue": "Slow page load time",
                            "description": f"Page took {load_time:.2f} seconds to load (should be under 3s)",
                            "impact": "Reduced user experience and SEO ranking"
                        })
                        score -= 25
                    elif load_time > 1.5:
                        issues.append({
                            "severity": "medium",
                            "issue": "Moderate page load time",
                            "description": f"Page took {load_time:.2f} seconds to load (optimal is under 1.5s)",
                            "impact": "Room for improvement in user experience"
                        })
                        score -= 10
                    
                    # Check response size and compression
                    content_size = len(content.encode('utf-8'))
                    content_length = response.headers.get('content-length')
                    
                    if content_size > 2 * 1024 * 1024:  # 2MB
                        issues.append({
                            "severity": "high", 
                            "issue": "Very large page size",
                            "description": f"Page size is {content_size // 1024}KB (should be under 1MB)",
                            "impact": "Slow loading on mobile networks, high bandwidth usage"
                        })
                        score -= 25
                    elif content_size > 1024 * 1024:  # 1MB
                        issues.append({
                            "severity": "medium",
                            "issue": "Large page size",
                            "description": f"Page size is {content_size // 1024}KB (consider optimization)",
                            "impact": "Slower loading times, especially on mobile"
                        })
                        score -= 15
                    
                    # Check compression
                    if 'gzip' not in response.headers.get('content-encoding', '') and 'br' not in response.headers.get('content-encoding', ''):
                        issues.append({
                            "severity": "medium",
                            "issue": "No compression detected",
                            "description": "Content is not compressed (gzip/brotli)",
                            "impact": "Larger file sizes and slower load times"
                        })
                        score -= 15
                    
                    # Check caching headers
                    cache_control = response.headers.get('cache-control', '')
                    expires = response.headers.get('expires', '')
                    etag = response.headers.get('etag', '')
                    
                    if not cache_control and not expires and not etag:
                        issues.append({
                            "severity": "medium",
                            "issue": "No caching headers detected",
                            "description": "Missing Cache-Control, Expires, or ETag headers",
                            "impact": "Resources downloaded every visit, slower repeat visits"
                        })
                        score -= 12
                    
                    # Analyze HTML content for performance issues
                    soup = BeautifulSoup(content, 'html.parser')
                    
                    # Check for render-blocking resources
                    css_links = soup.find_all('link', rel='stylesheet')
                    blocking_css = [link for link in css_links if not link.get('media') or link.get('media') == 'all']
                    
                    if len(blocking_css) > 5:
                        issues.append({
                            "severity": "medium",
                            "issue": "Multiple render-blocking CSS files",
                            "description": f"Found {len(blocking_css)} CSS files that block rendering",
                            "impact": "Delayed page rendering and First Contentful Paint"
                        })
                        score -= 12
                    
                    # Check for synchronous JavaScript
                    script_tags = soup.find_all('script', src=True)
                    blocking_scripts = [script for script in script_tags if not script.get('async') and not script.get('defer')]
                    
                    if len(blocking_scripts) > 3:
                        issues.append({
                            "severity": "medium",
                            "issue": "Multiple render-blocking JavaScript files",
                            "description": f"Found {len(blocking_scripts)} JS files without async/defer",
                            "impact": "Blocked HTML parsing and delayed page rendering"
                        })
                        score -= 12
                    
                    # Check images for optimization opportunities
                    images = soup.find_all('img')
                    
                    # Check for missing lazy loading
                    images_without_lazy = [img for img in images if not img.get('loading') == 'lazy']
                    if len(images_without_lazy) > 5:
                        issues.append({
                            "severity": "medium",
                            "issue": "Images not optimized for lazy loading",
                            "description": f"Found {len(images_without_lazy)} images without lazy loading",
                            "impact": "Unnecessary bandwidth usage and slower initial load"
                        })
                        score -= 10
                    
                    # Check for missing alt attributes (affects accessibility but also SEO performance)
                    images_without_alt = [img for img in images if not img.get('alt')]
                    if len(images_without_alt) > 0:
                        issues.append({
                            "severity": "low",
                            "issue": "Images missing alt attributes",
                            "description": f"{len(images_without_alt)} images lack alt text",
                            "impact": "Poor accessibility and SEO performance"
                        })
                        score -= 5
                    
                    # Check for modern image formats
                    webp_images = [img for img in images if img.get('src', '').endswith('.webp')]
                    total_images = len(images)
                    if total_images > 3 and len(webp_images) == 0:
                        issues.append({
                            "severity": "low",
                            "issue": "No modern image formats detected",
                            "description": "Consider using WebP or AVIF for better compression",
                            "impact": "Larger image file sizes than necessary"
                        })
                        score -= 8
                    
                    # Check for excessive DOM size
                    all_elements = soup.find_all()
                    dom_size = len(all_elements)
                    
                    if dom_size > 3000:
                        issues.append({
                            "severity": "medium",
                            "issue": "Large DOM size",
                            "description": f"Page has {dom_size} DOM elements (recommended: under 1500)",
                            "impact": "Slower rendering and increased memory usage"
                        })
                        score -= 12
                    elif dom_size > 1500:
                        issues.append({
                            "severity": "low",
                            "issue": "Moderate DOM size",
                            "description": f"Page has {dom_size} DOM elements (optimal: under 1500)",
                            "impact": "Potential performance impact on slower devices"
                        })
                        score -= 6
                    
                    # Check for inline CSS and JS (performance anti-pattern)
                    inline_styles = soup.find_all('style')
                    inline_scripts = soup.find_all('script', src=False)
                    
                    if len(inline_styles) > 2 or len(inline_scripts) > 2:
                        issues.append({
                            "severity": "low",
                            "issue": "Excessive inline CSS/JavaScript",
                            "description": f"Found {len(inline_styles)} inline styles and {len(inline_scripts)} inline scripts",
                            "impact": "Prevents caching and increases page size"
                        })
                        score -= 8
                    
                    # Check for HTTP/2 server push opportunities (if HTTP/1.1)
                    if response.version.major == 1:
                        issues.append({
                            "severity": "low",
                            "issue": "Using HTTP/1.1 instead of HTTP/2",
                            "description": "Server does not support HTTP/2",
                            "impact": "Missing multiplexing and performance benefits"
                        })
                        score -= 5
            
            return {
                "score": max(0, score),
                "issues": issues,
                "recommendations": [
                    "Optimize images (compress, use WebP/AVIF formats)",
                    "Enable Gzip/Brotli compression on server",
                    "Implement browser caching with appropriate headers",
                    "Minify CSS, JavaScript, and HTML",
                    "Use lazy loading for images below the fold",
                    "Add async/defer attributes to non-critical JavaScript",
                    "Reduce DOM complexity and nesting",
                    "Use a Content Delivery Network (CDN)",
                    "Enable HTTP/2 on your server",
                    "Eliminate render-blocking resources in critical path",
                    "Implement resource hints (preload, prefetch, preconnect)"
                ]
            }
            
        except Exception as e:
            return {
                "score": 0,
                "issues": [{
                    "severity": "critical",
                    "issue": "Performance audit failed",
                    "description": f"Could not perform performance audit: {str(e)}",
                    "impact": "Unable to assess performance bottlenecks"
                }],
                "recommendations": ["Ensure website is accessible and try again"]
            }

    @staticmethod
    async def audit_seo(url: str) -> Dict[str, Any]:
        """Perform comprehensive SEO audit"""
        try:
            issues = []
            score = 100
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    content = await response.text()
                    soup = BeautifulSoup(content, 'html.parser')
                    
                    # Check title tag
                    title = soup.find('title')
                    if not title or not title.text.strip():
                        issues.append({
                            "severity": "critical",
                            "issue": "Missing or empty title tag",
                            "description": "Page title is crucial for SEO and user experience",
                            "impact": "Poor search engine rankings and click-through rates"
                        })
                        score -= 25
                    else:
                        title_length = len(title.text)
                        if title_length > 60:
                            issues.append({
                                "severity": "medium",
                                "issue": "Title tag too long",
                                "description": f"Title is {title_length} characters (recommended: 50-60)",
                                "impact": "Title may be truncated in search results"
                            })
                            score -= 10
                        elif title_length < 30:
                            issues.append({
                                "severity": "medium",
                                "issue": "Title tag too short",
                                "description": f"Title is {title_length} characters (recommended: 50-60)",
                                "impact": "Missing opportunities for keyword optimization"
                            })
                            score -= 8
                    
                    # Check meta description
                    meta_desc = soup.find('meta', attrs={'name': 'description'})
                    if not meta_desc or not meta_desc.get('content', '').strip():
                        issues.append({
                            "severity": "high",
                            "issue": "Missing meta description",
                            "description": "Meta description helps search engines understand page content",
                            "impact": "Reduced click-through rates from search results"
                        })
                        score -= 20
                    else:
                        desc_length = len(meta_desc.get('content', ''))
                        if desc_length > 160:
                            issues.append({
                                "severity": "medium",
                                "issue": "Meta description too long",
                                "description": f"Meta description is {desc_length} characters (recommended: 150-160)",
                                "impact": "Description may be truncated in search results"
                            })
                            score -= 8
                        elif desc_length < 120:
                            issues.append({
                                "severity": "low",
                                "issue": "Meta description could be longer",
                                "description": f"Meta description is {desc_length} characters (optimal: 150-160)",
                                "impact": "Missing opportunities to attract clicks"
                            })
                            score -= 5
                    
                    # Check meta keywords (deprecated but some still use)
                    meta_keywords = soup.find('meta', attrs={'name': 'keywords'})
                    if meta_keywords:
                        issues.append({
                            "severity": "low",
                            "issue": "Meta keywords tag detected",
                            "description": "Meta keywords are ignored by search engines",
                            "impact": "Wasted effort - remove to clean up code"
                        })
                        score -= 3
                    
                    # Check heading structure
                    h1_tags = soup.find_all('h1')
                    if len(h1_tags) == 0:
                        issues.append({
                            "severity": "high",
                            "issue": "Missing H1 tag",
                            "description": "H1 tag is important for SEO and content structure",
                            "impact": "Reduced search engine understanding of page topic"
                        })
                        score -= 18
                    elif len(h1_tags) > 1:
                        issues.append({
                            "severity": "medium",
                            "issue": "Multiple H1 tags",
                            "description": f"Found {len(h1_tags)} H1 tags (recommended: 1 per page)",
                            "impact": "Confusing content hierarchy for search engines"
                        })
                        score -= 10
                    
                    # Check heading hierarchy
                    h2_tags = soup.find_all('h2')
                    h3_tags = soup.find_all('h3')
                    h4_tags = soup.find_all('h4')
                    
                    if len(h1_tags) > 0 and len(h2_tags) == 0 and len(h3_tags) > 0:
                        issues.append({
                            "severity": "medium",
                            "issue": "Poor heading hierarchy",
                            "description": "H3 tags found without H2 tags",
                            "impact": "Confusing content structure for search engines"
                        })
                        score -= 8
                    
                    # Check for images without alt text
                    images = soup.find_all('img')
                    images_without_alt = [img for img in images if not img.get('alt', '').strip()]
                    if images_without_alt:
                        issues.append({
                            "severity": "medium",
                            "issue": "Images missing alt text",
                            "description": f"{len(images_without_alt)} of {len(images)} images are missing alt text",
                            "impact": "Poor accessibility and missed SEO opportunities"
                        })
                        score -= 12
                    
                    # Check for images with generic alt text
                    generic_alt_texts = ['image', 'photo', 'picture', 'img', 'logo']
                    generic_alt_images = [img for img in images if img.get('alt', '').lower().strip() in generic_alt_texts]
                    if generic_alt_images:
                        issues.append({
                            "severity": "low",
                            "issue": "Generic alt text detected",
                            "description": f"{len(generic_alt_images)} images have generic alt text",
                            "impact": "Missed opportunities for descriptive content"
                        })
                        score -= 5
                    
                    # Check for mobile viewport meta tag
                    viewport = soup.find('meta', attrs={'name': 'viewport'})
                    if not viewport:
                        issues.append({
                            "severity": "high",
                            "issue": "Missing viewport meta tag",
                            "description": "Viewport meta tag is essential for mobile responsiveness",
                            "impact": "Poor mobile search rankings and user experience"
                        })
                        score -= 20
                    
                    # Check for canonical URL
                    canonical = soup.find('link', attrs={'rel': 'canonical'})
                    if not canonical:
                        issues.append({
                            "severity": "medium",
                            "issue": "Missing canonical URL",
                            "description": "Canonical URL helps prevent duplicate content issues",
                            "impact": "Potential duplicate content penalties"
                        })
                        score -= 8
                    
                    # Check for Open Graph tags
                    og_title = soup.find('meta', attrs={'property': 'og:title'})
                    og_description = soup.find('meta', attrs={'property': 'og:description'})
                    og_image = soup.find('meta', attrs={'property': 'og:image'})
                    
                    if not og_title or not og_description:
                        issues.append({
                            "severity": "medium",
                            "issue": "Missing Open Graph tags",
                            "description": "OG tags improve social media sharing appearance",
                            "impact": "Poor social media preview and sharing"
                        })
                        score -= 10
                    
                    # Check for Twitter Card tags
                    twitter_card = soup.find('meta', attrs={'name': 'twitter:card'})
                    if not twitter_card:
                        issues.append({
                            "severity": "low",
                            "issue": "Missing Twitter Card tags",
                            "description": "Twitter Card tags enhance Twitter sharing",
                            "impact": "Suboptimal Twitter sharing experience"
                        })
                        score -= 5
                    
                    # Check internal linking
                    internal_links = soup.find_all('a', href=True)
                    internal_count = len([link for link in internal_links if urlparse(link['href']).netloc == '' or urlparse(url).netloc in link['href']])
                    external_count = len(internal_links) - internal_count
                    
                    if internal_count < 3:
                        issues.append({
                            "severity": "medium",
                            "issue": "Few internal links",
                            "description": f"Found only {internal_count} internal links",
                            "impact": "Poor site navigation and link equity distribution"
                        })
                        score -= 8
                    
                    # Check for external links without rel attributes
                    external_links_no_rel = [link for link in internal_links 
                                           if urlparse(link['href']).netloc != '' 
                                           and urlparse(url).netloc not in link['href'] 
                                           and not link.get('rel')]
                    if external_links_no_rel:
                        issues.append({
                            "severity": "low",
                            "issue": "External links without rel attributes",
                            "description": f"{len(external_links_no_rel)} external links missing rel='noopener' or rel='nofollow'",
                            "impact": "Potential security and SEO link equity issues"
                        })
                        score -= 5
                    
                    # Check for structured data (JSON-LD)
                    json_ld_scripts = soup.find_all('script', type='application/ld+json')
                    if not json_ld_scripts:
                        issues.append({
                            "severity": "low",
                            "issue": "No structured data detected",
                            "description": "Structured data helps search engines understand content",
                            "impact": "Missing rich snippet opportunities"
                        })
                        score -= 8
                    
                    # Check page loading speed impact on SEO
                    # This is already covered in performance audit, but we'll note it for SEO
                    
                    # Check for robots meta tag
                    robots_meta = soup.find('meta', attrs={'name': 'robots'})
                    if robots_meta and 'noindex' in robots_meta.get('content', '').lower():
                        issues.append({
                            "severity": "critical",
                            "issue": "Page set to noindex",
                            "description": "Page has robots meta tag with noindex directive",
                            "impact": "Page will not appear in search results"
                        })
                        score -= 30
                    
                    # Check content length
                    # Remove script and style content for accurate text count
                    for script in soup(["script", "style"]):
                        script.decompose()
                    text_content = soup.get_text()
                    word_count = len(text_content.split())
                    
                    if word_count < 300:
                        issues.append({
                            "severity": "medium",
                            "issue": "Thin content detected",
                            "description": f"Page has only {word_count} words (recommended: 300+)",
                            "impact": "Insufficient content for good search rankings"
                        })
                        score -= 15
                    
                    # Check for HTTPS (SEO ranking factor)
                    parsed_url = urlparse(url)
                    if parsed_url.scheme != 'https':
                        issues.append({
                            "severity": "high",
                            "issue": "Not using HTTPS",
                            "description": "HTTPS is a ranking factor for search engines",
                            "impact": "Lower search rankings and user trust"
                        })
                        score -= 20
            
            return {
                "score": max(0, score),
                "issues": issues,
                "recommendations": [
                    "Optimize title tags (50-60 characters, include primary keywords)",
                    "Write compelling meta descriptions (150-160 characters)",
                    "Use proper heading hierarchy (H1, H2, H3) with keywords",
                    "Add descriptive alt text to all images",
                    "Ensure mobile responsiveness with viewport meta tag",
                    "Implement canonical URLs to prevent duplicate content",
                    "Add Open Graph and Twitter Card meta tags",
                    "Create internal linking strategy for better navigation",
                    "Add structured data markup for rich snippets",
                    "Create substantial, valuable content (300+ words)",
                    "Use HTTPS for security and SEO benefits",
                    "Optimize page loading speed (affects SEO rankings)",
                    "Use descriptive, keyword-rich URLs",
                    "Create and submit XML sitemap",
                    "Optimize for local SEO if applicable"
                ]
            }
            
        except Exception as e:
            return {
                "score": 0,
                "issues": [{
                    "severity": "critical",
                    "issue": "SEO audit failed",
                    "description": f"Could not perform SEO audit: {str(e)}",
                    "impact": "Unable to assess SEO optimization"
                }],
                "recommendations": ["Ensure website is accessible and try again"]
            }

    @staticmethod
    async def audit_accessibility(url: str) -> Dict[str, Any]:
        """Perform comprehensive accessibility audit"""
        try:
            issues = []
            score = 100
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    content = await response.text()
                    soup = BeautifulSoup(content, 'html.parser')
                    
                    # Check for alt text on images
                    images = soup.find_all('img')
                    images_without_alt = [img for img in images if not img.get('alt')]
                    decorative_images = [img for img in images if img.get('alt') == '']
                    
                    if images_without_alt:
                        issues.append({
                            "severity": "high",
                            "issue": "Images missing alt attributes",
                            "description": f"{len(images_without_alt)} of {len(images)} images lack alt attributes",
                            "impact": "Screen readers cannot describe images to visually impaired users"
                        })
                        score -= 20
                    
                    # Check for form labels
                    form_inputs = soup.find_all('input', type=lambda x: x not in ['hidden', 'submit', 'button'])
                    inputs_without_labels = []
                    
                    for input_elem in form_inputs:
                        input_id = input_elem.get('id')
                        input_name = input_elem.get('name')
                        
                        # Check for associated label
                        label_found = False
                        if input_id:
                            label = soup.find('label', attrs={'for': input_id})
                            if label:
                                label_found = True
                        
                        # Check for aria-label
                        if not label_found and not input_elem.get('aria-label'):
                            # Check for aria-labelledby
                            if not input_elem.get('aria-labelledby'):
                                # Check if wrapped in label
                                parent_label = input_elem.find_parent('label')
                                if not parent_label:
                                    inputs_without_labels.append(input_elem)
                    
                    if inputs_without_labels:
                        issues.append({
                            "severity": "high",
                            "issue": "Form inputs missing labels",
                            "description": f"{len(inputs_without_labels)} form inputs lack proper labels",
                            "impact": "Screen readers cannot identify form field purposes"
                        })
                        score -= 18
                    
                    # Check for proper heading hierarchy
                    headings = soup.find_all(['h1', 'h2', 'h3', 'h4', 'h5', 'h6'])
                    if headings:
                        heading_levels = [int(h.name[1]) for h in headings]
                        
                        # Check if starts with h1
                        if heading_levels and heading_levels[0] != 1:
                            issues.append({
                                "severity": "medium",
                                "issue": "Page doesn't start with H1",
                                "description": f"First heading is H{heading_levels[0]}",
                                "impact": "Confusing content structure for screen readers"
                            })
                            score -= 12
                        
                        # Check for skipped heading levels
                        for i in range(1, len(heading_levels)):
                            if heading_levels[i] > heading_levels[i-1] + 1:
                                issues.append({
                                    "severity": "medium",
                                    "issue": "Skipped heading levels",
                                    "description": f"H{heading_levels[i-1]} followed by H{heading_levels[i]}",
                                    "impact": "Broken content hierarchy for assistive technologies"
                                })
                                score -= 10
                                break
                    else:
                        issues.append({
                            "severity": "high",
                            "issue": "No headings found",
                            "description": "Page lacks heading structure",
                            "impact": "Poor navigation for screen reader users"
                        })
                        score -= 15
                    
                    # Check for color contrast (basic check for common patterns)
                    # This is a simplified check - real contrast requires color analysis
                    style_tags = soup.find_all('style')
                    inline_styles = [elem.get('style', '') for elem in soup.find_all(style=True)]
                    
                    low_contrast_patterns = [
                        'color:#ccc', 'color:#ddd', 'color:#eee',
                        'color:lightgray', 'color:lightgrey'
                    ]
                    
                    has_potential_contrast_issues = False
                    for style in style_tags:
                        for pattern in low_contrast_patterns:
                            if pattern in style.get_text().lower():
                                has_potential_contrast_issues = True
                                break
                    
                    for style in inline_styles:
                        for pattern in low_contrast_patterns:
                            if pattern in style.lower():
                                has_potential_contrast_issues = True
                                break
                    
                    if has_potential_contrast_issues:
                        issues.append({
                            "severity": "medium",
                            "issue": "Potential color contrast issues",
                            "description": "Light colors detected that may have poor contrast",
                            "impact": "Text may be difficult to read for users with visual impairments"
                        })
                        score -= 12
                    
                    # Check for keyboard navigation support
                    interactive_elements = soup.find_all(['a', 'button', 'input', 'select', 'textarea'])
                    elements_without_tabindex = [elem for elem in interactive_elements 
                                               if elem.get('tabindex') == '-1']
                    
                    if len(elements_without_tabindex) > len(interactive_elements) * 0.5:
                        issues.append({
                            "severity": "medium",
                            "issue": "Many elements may not be keyboard accessible",
                            "description": f"{len(elements_without_tabindex)} interactive elements have tabindex='-1'",
                            "impact": "Keyboard users cannot navigate to these elements"
                        })
                        score -= 15
                    
                    # Check for ARIA landmarks
                    landmarks = soup.find_all(attrs={'role': ['main', 'navigation', 'banner', 'contentinfo', 'complementary']})
                    semantic_landmarks = soup.find_all(['main', 'nav', 'header', 'footer', 'aside'])
                    
                    total_landmarks = len(landmarks) + len(semantic_landmarks)
                    if total_landmarks == 0:
                        issues.append({
                            "severity": "medium",
                            "issue": "No ARIA landmarks found",
                            "description": "Page lacks navigation landmarks",
                            "impact": "Screen reader users cannot easily navigate page sections"
                        })
                        score -= 12
                    
                    # Check for skip links
                    skip_links = soup.find_all('a', href=lambda x: x and x.startswith('#'))
                    skip_to_main = [link for link in skip_links if 'main' in link.get_text().lower() or 'content' in link.get_text().lower()]
                    
                    if not skip_to_main:
                        issues.append({
                            "severity": "medium",
                            "issue": "Missing skip to main content link",
                            "description": "No skip link found for keyboard navigation",
                            "impact": "Keyboard users must tab through all navigation"
                        })
                        score -= 10
                    
                    # Check for language declaration
                    lang_attr = soup.find('html').get('lang') if soup.find('html') else None
                    if not lang_attr:
                        issues.append({
                            "severity": "medium",
                            "issue": "Missing language declaration",
                            "description": "HTML element lacks lang attribute",
                            "impact": "Screen readers may use incorrect pronunciation"
                        })
                        score -= 10
                    
                    # Check for table headers
                    tables = soup.find_all('table')
                    for table in tables:
                        headers = table.find_all('th')
                        if not headers:
                            # Check if table has header row
                            first_row = table.find('tr')
                            if first_row and not first_row.find('th'):
                                issues.append({
                                    "severity": "medium",
                                    "issue": "Data table missing headers",
                                    "description": "Table found without proper header cells",
                                    "impact": "Screen readers cannot associate data with headers"
                                })
                                score -= 12
                                break
                    
                    # Check for video/audio accessibility
                    videos = soup.find_all('video')
                    audios = soup.find_all('audio')
                    
                    for video in videos:
                        if not video.find('track', kind='captions') and not video.find('track', kind='subtitles'):
                            issues.append({
                                "severity": "high",
                                "issue": "Video missing captions",
                                "description": "Video content lacks captions or subtitles",
                                "impact": "Deaf and hard-of-hearing users cannot access content"
                            })
                            score -= 20
                            break
                    
                    # Check for focus indicators (basic check)
                    focus_styles = []
                    for style_tag in soup.find_all('style'):
                        if ':focus' in style_tag.get_text():
                            focus_styles.append(True)
                    
                    if not focus_styles and not soup.find_all(attrs={'style': lambda x: x and ':focus' in x}):
                        issues.append({
                            "severity": "medium",
                            "issue": "No custom focus styles detected",
                            "description": "Page may rely only on browser default focus indicators",
                            "impact": "Focus may be hard to see for keyboard users"
                        })
                        score -= 8
                    
                    # Check for descriptive link text
                    links = soup.find_all('a', href=True)
                    generic_link_texts = ['click here', 'read more', 'more', 'here', 'link']
                    generic_links = [link for link in links 
                                   if link.get_text().strip().lower() in generic_link_texts]
                    
                    if generic_links:
                        issues.append({
                            "severity": "low",
                            "issue": "Generic link text found",
                            "description": f"{len(generic_links)} links have non-descriptive text",
                            "impact": "Screen reader users cannot understand link purpose"
                        })
                        score -= 8
                    
                    # Check for empty links or buttons
                    empty_links = [link for link in soup.find_all('a') if not link.get_text().strip() and not link.find('img')]
                    empty_buttons = [btn for btn in soup.find_all('button') if not btn.get_text().strip() and not btn.find('img')]
                    
                    if empty_links or empty_buttons:
                        issues.append({
                            "severity": "high",
                            "issue": "Empty interactive elements",
                            "description": f"Found {len(empty_links)} empty links and {len(empty_buttons)} empty buttons",
                            "impact": "Screen readers cannot describe element purpose"
                        })
                        score -= 15
            
            return {
                "score": max(0, score),
                "issues": issues,
                "recommendations": [
                    "Add alt text to all informative images (empty alt for decorative)",
                    "Associate labels with all form inputs",
                    "Use proper heading hierarchy (H1, H2, H3...)",
                    "Ensure sufficient color contrast (4.5:1 for normal text)",
                    "Add ARIA landmarks for page navigation",
                    "Include skip links for keyboard navigation",
                    "Declare page language in HTML element",
                    "Use descriptive text for links and buttons",
                    "Provide captions for video content",
                    "Ensure all interactive elements are keyboard accessible",
                    "Test with screen readers and keyboard-only navigation",
                    "Use semantic HTML elements when possible",
                    "Provide focus indicators for interactive elements"
                ]
            }
            
        except Exception as e:
            return {
                "score": 0,
                "issues": [{
                    "severity": "critical",
                    "issue": "Accessibility audit failed",
                    "description": f"Could not perform accessibility audit: {str(e)}",
                    "impact": "Unable to assess accessibility compliance"
                }],
                "recommendations": ["Ensure website is accessible and try again"]
            }

# API Routes
@api_router.post("/signup")
async def signup(user_data: UserCreate):
    # Check if user already exists
    existing_user = await db.users.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create new user
    user = User(
        name=user_data.name,
        email=user_data.email,
        password_hash=hash_password(user_data.password)
    )
    
    await db.users.insert_one(user.dict())
    token = create_token(user.id)
    
    return {"message": "User created successfully", "token": token, "user": {"id": user.id, "name": user.name, "email": user.email}}

@api_router.post("/login")
async def login(login_data: UserLogin):
    user = await db.users.find_one({"email": login_data.email})
    if not user or not verify_password(login_data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_token(user["id"])
    return {"message": "Login successful", "token": token, "user": {"id": user["id"], "name": user["name"], "email": user["email"]}}

@api_router.post("/websites")
async def create_website(website_data: WebsiteCreate, current_user: User = Depends(get_current_user)):
    # Validate URL format
    if not website_data.url.startswith(('http://', 'https://')):
        website_data.url = 'https://' + website_data.url
    
    website = Website(
        user_id=current_user.id,
        url=website_data.url
    )
    
    await db.websites.insert_one(website.dict())
    return {"message": "Website added successfully", "website": website}

@api_router.get("/websites")
async def get_websites(current_user: User = Depends(get_current_user)):
    websites = await db.websites.find({"user_id": current_user.id}).to_list(1000)
    return [Website(**website) for website in websites]

@api_router.post("/audit/run")
async def run_audit(audit_request: AuditRequest, current_user: User = Depends(get_current_user)):
    # Verify website belongs to user
    website = await db.websites.find_one({"id": audit_request.website_id, "user_id": current_user.id})
    if not website:
        raise HTTPException(status_code=404, detail="Website not found")
    
    website_obj = Website(**website)
    auditor = WebsiteAuditor()
    
    try:
        if audit_request.audit_type == "All":
            # Run all audits
            ssl_result = await auditor.audit_security(website_obj.url)
            performance_result = await auditor.audit_performance(website_obj.url)
            seo_result = await auditor.audit_seo(website_obj.url)
            
            # Combine results
            all_issues = ssl_result["issues"] + performance_result["issues"] + seo_result["issues"]
            avg_score = (ssl_result["score"] + performance_result["score"] + seo_result["score"]) // 3
            all_recommendations = list(set(ssl_result["recommendations"] + performance_result["recommendations"] + seo_result["recommendations"]))
            
            audit_report = AuditReport(
                website_id=audit_request.website_id,
                audit_type="All",
                score=avg_score,
                issues=all_issues,
                recommendations=all_recommendations
            )
            
            # Also save individual reports
            for audit_type, result in [("Security", ssl_result), ("Performance", performance_result), ("SEO", seo_result)]:
                individual_report = AuditReport(
                    website_id=audit_request.website_id,
                    audit_type=audit_type,
                    score=result["score"],
                    issues=result["issues"],
                    recommendations=result["recommendations"]
                )
                await db.audit_reports.insert_one(individual_report.dict())
            
        else:
            # Run specific audit
            if audit_request.audit_type == "Security":
                result = await auditor.audit_security(website_obj.url)
            elif audit_request.audit_type == "Performance":
                result = await auditor.audit_performance(website_obj.url)
            elif audit_request.audit_type == "SEO":
                result = await auditor.audit_seo(website_obj.url)
            else:
                raise HTTPException(status_code=400, detail="Invalid audit type")
            
            audit_report = AuditReport(
                website_id=audit_request.website_id,
                audit_type=audit_request.audit_type,
                score=result["score"],
                issues=result["issues"],
                recommendations=result["recommendations"]
            )
        
        await db.audit_reports.insert_one(audit_report.dict())
        return {"message": "Audit completed successfully", "report": audit_report}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Audit failed: {str(e)}")

@api_router.get("/audit/reports")
async def get_audit_reports(current_user: User = Depends(get_current_user)):
    # Get all websites for the user
    websites = await db.websites.find({"user_id": current_user.id}).to_list(1000)
    website_ids = [w["id"] for w in websites]
    
    # Get all reports for user's websites
    reports = await db.audit_reports.find({"website_id": {"$in": website_ids}}).to_list(1000)
    return [AuditReport(**report) for report in reports]

@api_router.get("/audit/report/{report_id}")
async def get_audit_report(report_id: str, current_user: User = Depends(get_current_user)):
    report = await db.audit_reports.find_one({"id": report_id})
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    # Verify report belongs to user's website
    website = await db.websites.find_one({"id": report["website_id"], "user_id": current_user.id})
    if not website:
        raise HTTPException(status_code=403, detail="Access denied")
    
    return AuditReport(**report)

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()