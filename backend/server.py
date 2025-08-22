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
    audit_type: str  # 'Security', 'Performance', 'SEO', 'All'
    score: int
    issues: List[Dict[str, Any]]
    recommendations: List[str]
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class AuditRequest(BaseModel):
    website_id: str
    audit_type: str = "All"  # 'Security', 'Performance', 'SEO', 'All'

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
        """Perform performance audit"""
        try:
            issues = []
            score = 100
            
            # Measure page load time
            start_time = time.time()
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=30) as response:
                    content = await response.text()
                    load_time = time.time() - start_time
                    
                    # Check response time
                    if load_time > 3:
                        issues.append({
                            "severity": "high",
                            "issue": "Slow page load time",
                            "description": f"Page took {load_time:.2f} seconds to load (should be under 3s)"
                        })
                        score -= 30
                    elif load_time > 1.5:
                        issues.append({
                            "severity": "medium",
                            "issue": "Moderate page load time",
                            "description": f"Page took {load_time:.2f} seconds to load (optimal is under 1.5s)"
                        })
                        score -= 15
                    
                    # Check response size
                    content_size = len(content.encode('utf-8'))
                    if content_size > 1024 * 1024:  # 1MB
                        issues.append({
                            "severity": "medium",
                            "issue": "Large page size",
                            "description": f"Page size is {content_size // 1024}KB (consider optimization)"
                        })
                        score -= 20
                    
                    # Check for optimization opportunities
                    if 'text/css' not in response.headers.get('content-type', ''):
                        soup = BeautifulSoup(content, 'html.parser')
                        
                        # Check for unoptimized images
                        images = soup.find_all('img')
                        large_images = [img for img in images if not img.get('loading') == 'lazy']
                        if len(large_images) > 5:
                            issues.append({
                                "severity": "low",
                                "issue": "Images not optimized for lazy loading",
                                "description": f"Found {len(large_images)} images without lazy loading"
                            })
                            score -= 10
                        
                        # Check for inline CSS/JS
                        inline_styles = soup.find_all('style')
                        inline_scripts = soup.find_all('script', src=False)
                        if len(inline_styles) > 3 or len(inline_scripts) > 3:
                            issues.append({
                                "severity": "low",
                                "issue": "Excessive inline CSS/JavaScript",
                                "description": "Consider moving inline styles and scripts to external files"
                            })
                            score -= 10
            
            return {
                "score": max(0, score),
                "issues": issues,
                "recommendations": [
                    "Optimize images and use modern formats (WebP, AVIF)",
                    "Enable browser caching and compression",
                    "Minify CSS, JavaScript, and HTML",
                    "Use a Content Delivery Network (CDN)",
                    "Implement lazy loading for images",
                    "Reduce server response time"
                ]
            }
            
        except Exception as e:
            return {
                "score": 0,
                "issues": [{
                    "severity": "high",
                    "issue": "Performance audit failed",
                    "description": f"Could not perform performance audit: {str(e)}"
                }],
                "recommendations": ["Ensure website is accessible and try again"]
            }

    @staticmethod
    async def audit_seo(url: str) -> Dict[str, Any]:
        """Perform SEO audit"""
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
                            "severity": "high",
                            "issue": "Missing or empty title tag",
                            "description": "Page title is crucial for SEO"
                        })
                        score -= 20
                    elif len(title.text) > 60:
                        issues.append({
                            "severity": "medium",
                            "issue": "Title tag too long",
                            "description": f"Title is {len(title.text)} characters (should be under 60)"
                        })
                        score -= 10
                    
                    # Check meta description
                    meta_desc = soup.find('meta', attrs={'name': 'description'})
                    if not meta_desc or not meta_desc.get('content', '').strip():
                        issues.append({
                            "severity": "high",
                            "issue": "Missing meta description",
                            "description": "Meta description helps search engines understand page content"
                        })
                        score -= 20
                    elif len(meta_desc.get('content', '')) > 160:
                        issues.append({
                            "severity": "medium",
                            "issue": "Meta description too long",
                            "description": f"Meta description is {len(meta_desc.get('content', ''))} characters (should be under 160)"
                        })
                        score -= 10
                    
                    # Check heading structure
                    h1_tags = soup.find_all('h1')
                    if len(h1_tags) == 0:
                        issues.append({
                            "severity": "medium",
                            "issue": "Missing H1 tag",
                            "description": "H1 tag is important for SEO and accessibility"
                        })
                        score -= 15
                    elif len(h1_tags) > 1:
                        issues.append({
                            "severity": "low",
                            "issue": "Multiple H1 tags",
                            "description": f"Found {len(h1_tags)} H1 tags (recommended: 1 per page)"
                        })
                        score -= 5
                    
                    # Check for images without alt text
                    images = soup.find_all('img')
                    images_without_alt = [img for img in images if not img.get('alt', '').strip()]
                    if images_without_alt:
                        issues.append({
                            "severity": "medium",
                            "issue": "Images missing alt text",
                            "description": f"{len(images_without_alt)} images are missing alt text"
                        })
                        score -= 15
                    
                    # Check for mobile viewport meta tag
                    viewport = soup.find('meta', attrs={'name': 'viewport'})
                    if not viewport:
                        issues.append({
                            "severity": "high",
                            "issue": "Missing viewport meta tag",
                            "description": "Viewport meta tag is essential for mobile responsiveness"
                        })
                        score -= 20
                    
                    # Check for canonical URL
                    canonical = soup.find('link', attrs={'rel': 'canonical'})
                    if not canonical:
                        issues.append({
                            "severity": "low",
                            "issue": "Missing canonical URL",
                            "description": "Canonical URL helps prevent duplicate content issues"
                        })
                        score -= 5
                    
                    # Check internal linking
                    internal_links = soup.find_all('a', href=True)
                    internal_count = len([link for link in internal_links if urlparse(link['href']).netloc == ''])
                    if internal_count < 3:
                        issues.append({
                            "severity": "low",
                            "issue": "Few internal links",
                            "description": "Internal linking helps with site navigation and SEO"
                        })
                        score -= 5
            
            return {
                "score": max(0, score),
                "issues": issues,
                "recommendations": [
                    "Optimize title tags (50-60 characters)",
                    "Write compelling meta descriptions (150-160 characters)",
                    "Use proper heading hierarchy (H1, H2, H3)",
                    "Add alt text to all images",
                    "Ensure mobile responsiveness with viewport meta tag",
                    "Implement internal linking strategy",
                    "Use canonical URLs to prevent duplicate content"
                ]
            }
            
        except Exception as e:
            return {
                "score": 0,
                "issues": [{
                    "severity": "high",
                    "issue": "SEO audit failed",
                    "description": f"Could not perform SEO audit: {str(e)}"
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