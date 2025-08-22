import requests
import sys
import time
from datetime import datetime

class WebsiteAuditAPITester:
    def __init__(self, base_url="https://webaudit-app-1.preview.emergentagent.com/api"):
        self.base_url = base_url
        self.token = None
        self.user_id = None
        self.tests_run = 0
        self.tests_passed = 0
        self.test_websites = []
        self.test_reports = []

    def run_test(self, name, method, endpoint, expected_status, data=None, headers=None):
        """Run a single API test"""
        url = f"{self.base_url}/{endpoint}"
        test_headers = {'Content-Type': 'application/json'}
        
        if self.token:
            test_headers['Authorization'] = f'Bearer {self.token}'
        
        if headers:
            test_headers.update(headers)

        self.tests_run += 1
        print(f"\n🔍 Testing {name}...")
        print(f"   URL: {url}")
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=test_headers, timeout=30)
            elif method == 'POST':
                response = requests.post(url, json=data, headers=test_headers, timeout=30)
            elif method == 'PUT':
                response = requests.put(url, json=data, headers=test_headers, timeout=30)
            elif method == 'DELETE':
                response = requests.delete(url, headers=test_headers, timeout=30)

            success = response.status_code == expected_status
            if success:
                self.tests_passed += 1
                print(f"✅ Passed - Status: {response.status_code}")
                try:
                    response_data = response.json()
                    print(f"   Response: {response_data}")
                    return True, response_data
                except:
                    return True, {}
            else:
                print(f"❌ Failed - Expected {expected_status}, got {response.status_code}")
                try:
                    error_data = response.json()
                    print(f"   Error: {error_data}")
                except:
                    print(f"   Error: {response.text}")
                return False, {}

        except Exception as e:
            print(f"❌ Failed - Error: {str(e)}")
            return False, {}

    def test_signup(self):
        """Test user signup"""
        timestamp = datetime.now().strftime('%H%M%S')
        test_user_data = {
            "name": f"Test User {timestamp}",
            "email": f"testuser{timestamp}@example.com",
            "password": "TestPass123!"
        }
        
        success, response = self.run_test(
            "User Signup",
            "POST",
            "signup",
            200,
            data=test_user_data
        )
        
        if success and 'token' in response:
            self.token = response['token']
            self.user_id = response['user']['id']
            print(f"   User ID: {self.user_id}")
            return True
        return False

    def test_login(self):
        """Test user login with existing credentials"""
        # First create a user, then try to login
        timestamp = datetime.now().strftime('%H%M%S')
        test_user_data = {
            "name": f"Login Test User {timestamp}",
            "email": f"logintest{timestamp}@example.com",
            "password": "LoginTest123!"
        }
        
        # Create user first
        success, _ = self.run_test(
            "Create User for Login Test",
            "POST",
            "signup",
            200,
            data=test_user_data
        )
        
        if not success:
            return False
            
        # Now test login
        login_data = {
            "email": test_user_data["email"],
            "password": test_user_data["password"]
        }
        
        success, response = self.run_test(
            "User Login",
            "POST",
            "login",
            200,
            data=login_data
        )
        
        return success and 'token' in response

    def test_add_website(self, url):
        """Test adding a website"""
        success, response = self.run_test(
            f"Add Website ({url})",
            "POST",
            "websites",
            200,
            data={"url": url}
        )
        
        if success and 'website' in response:
            website_id = response['website']['id']
            self.test_websites.append(website_id)
            print(f"   Website ID: {website_id}")
            return website_id
        return None

    def test_get_websites(self):
        """Test getting user's websites"""
        success, response = self.run_test(
            "Get Websites",
            "GET",
            "websites",
            200
        )
        
        if success:
            print(f"   Found {len(response)} websites")
            return True
        return False

    def test_run_audit(self, website_id, audit_type="All"):
        """Test running an audit"""
        success, response = self.run_test(
            f"Run {audit_type} Audit",
            "POST",
            "audit/run",
            200,
            data={"website_id": website_id, "audit_type": audit_type}
        )
        
        if success and 'report' in response:
            report_id = response['report']['id']
            self.test_reports.append(report_id)
            print(f"   Report ID: {report_id}")
            print(f"   Score: {response['report']['score']}/100")
            print(f"   Issues: {len(response['report']['issues'])}")
            return report_id
        return None

    def test_get_reports(self):
        """Test getting audit reports"""
        success, response = self.run_test(
            "Get Audit Reports",
            "GET",
            "audit/reports",
            200
        )
        
        if success:
            print(f"   Found {len(response)} reports")
            return True
        return False

    def test_get_specific_report(self, report_id):
        """Test getting a specific audit report"""
        success, response = self.run_test(
            "Get Specific Report",
            "GET",
            f"audit/report/{report_id}",
            200
        )
        
        if success:
            print(f"   Report Score: {response['score']}/100")
            print(f"   Issues: {len(response['issues'])}")
            print(f"   Recommendations: {len(response['recommendations'])}")
            return True
        return False

    def test_invalid_token(self):
        """Test API with invalid token"""
        original_token = self.token
        self.token = "invalid_token_12345"
        
        success, _ = self.run_test(
            "Invalid Token Test",
            "GET",
            "websites",
            401  # Should return unauthorized
        )
        
        self.token = original_token
        return success

    def test_no_token(self):
        """Test protected endpoint without token"""
        original_token = self.token
        self.token = None
        
        success, _ = self.run_test(
            "No Token Test",
            "GET",
            "websites",
            403  # Should return forbidden
        )
        
        self.token = original_token
        return success

def main():
    print("🚀 Starting Website Audit Tool API Tests")
    print("=" * 50)
    
    tester = WebsiteAuditAPITester()
    
    # Test 1: User Signup
    if not tester.test_signup():
        print("❌ Signup failed, stopping tests")
        return 1

    # Test 2: User Login (separate user)
    if not tester.test_login():
        print("❌ Login test failed")

    # Test 3: Add websites
    test_urls = ["https://google.com", "https://github.com", "https://example.com"]
    website_ids = []
    
    for url in test_urls:
        website_id = tester.test_add_website(url)
        if website_id:
            website_ids.append(website_id)

    if not website_ids:
        print("❌ No websites added successfully, stopping audit tests")
        return 1

    # Test 4: Get websites
    if not tester.test_get_websites():
        print("❌ Failed to get websites")

    # Test 5: Run different types of audits
    audit_types = ["SSL", "Performance", "SEO", "All"]
    report_ids = []
    
    # Use first website for audit tests
    test_website_id = website_ids[0]
    
    for audit_type in audit_types:
        print(f"\n⏳ Running {audit_type} audit (this may take a few seconds)...")
        report_id = tester.test_run_audit(test_website_id, audit_type)
        if report_id:
            report_ids.append(report_id)
        # Small delay between audits
        time.sleep(2)

    # Test 6: Get all reports
    if not tester.test_get_reports():
        print("❌ Failed to get audit reports")

    # Test 7: Get specific report
    if report_ids:
        if not tester.test_get_specific_report(report_ids[0]):
            print("❌ Failed to get specific report")

    # Test 8: Authentication tests
    if not tester.test_invalid_token():
        print("❌ Invalid token test failed")
    
    if not tester.test_no_token():
        print("❌ No token test failed")

    # Print final results
    print("\n" + "=" * 50)
    print("📊 TEST RESULTS")
    print("=" * 50)
    print(f"Tests run: {tester.tests_run}")
    print(f"Tests passed: {tester.tests_passed}")
    print(f"Success rate: {(tester.tests_passed/tester.tests_run)*100:.1f}%")
    
    if tester.tests_passed == tester.tests_run:
        print("🎉 All tests passed!")
        return 0
    else:
        print(f"⚠️  {tester.tests_run - tester.tests_passed} tests failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())