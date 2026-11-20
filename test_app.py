import unittest
import json
from app import app
from database import init_db, get_direct_connection
from seed_data import seed_database

class ShadowPreventerComprehensiveTestCase(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()
        seed_database()

    def test_01_login_page_renders(self):
        """Verify login page renders with branding and demo case indicators."""
        response = self.client.get('/login')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'SHADOW PREVENTER', response.data)
        self.assertIn(b'SAVEETHA', response.data)
        self.assertIn(b'r.menon', response.data)

    def test_02_admin_authentication_and_dashboard(self):
        """Verify admin authentication and dashboard access."""
        response = self.client.post('/login', data={
            'username': 'admin',
            'password': 'Admin@2026'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'SOC Defense Command Center', response.data)
        self.assertIn(b'Rohan Menon', response.data)
        self.assertIn(b'172.16.8.44', response.data)

    def test_03_rbac_employee_denied_admin_access(self):
        """Verify employee role is strictly denied access to admin routes (HTTP 403)."""
        self.client.post('/login', data={
            'username': 'a.sharma',
            'password': 'Employee@2026'
        }, follow_redirects=True)

        response = self.client.get('/admin/dashboard')
        self.assertEqual(response.status_code, 403)
        self.assertIn(b'403 ACCESS DENIED', response.data)
        self.assertIn(b'RBAC', response.data)

    def test_04_rohan_menon_demo_case_verification(self):
        """Verify Rohan Menon is identified as a critical shadow risk."""
        self.client.post('/login', data={
            'username': 'admin',
            'password': 'Admin@2026'
        }, follow_redirects=True)

        response = self.client.get('/admin/monitoring')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'r.menon', response.data)
        self.assertIn(b'SIMULATED BREACH CASE', response.data)
        self.assertIn(b'172.16.8.44', response.data)

    def test_05_employee_crud_lifecycle(self):
        """Verify adding, editing, and deleting an employee."""
        self.client.post('/login', data={
            'username': 'admin',
            'password': 'Admin@2026'
        }, follow_redirects=True)

        # Add employee
        response = self.client.post('/admin/employees/add', data={
            'username': 't.tester',
            'full_name': 'Test User',
            'email': 't.tester@saveetha.sec',
            'position': 'Security Tester',
            'department': 'IT Security',
            'role': 'employee',
            'employment_status': 'Active',
            'mfa_enabled': '1',
            'password': 'TestPass#2026'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Test User', response.data)

        # Retrieve new user id
        conn = get_direct_connection()
        user_row = conn.execute("SELECT id FROM users WHERE username = 't.tester'").fetchone()
        t_id = user_row['id']
        conn.close()

        # Edit employee
        edit_resp = self.client.post(f'/admin/employees/edit/{t_id}', data={
            'full_name': 'Test User Edited',
            'email': 't.tester.edited@saveetha.sec',
            'position': 'Senior Security Tester',
            'department': 'IT Security',
            'role': 'employee',
            'employment_status': 'Active',
            'account_status': 'Active',
            'mfa_enabled': '1'
        }, follow_redirects=True)
        self.assertEqual(edit_resp.status_code, 200)
        self.assertIn(b'Test User Edited', edit_resp.data)

        # Delete employee
        del_resp = self.client.post(f'/admin/employees/delete/{t_id}', follow_redirects=True)
        self.assertEqual(del_resp.status_code, 200)

    def test_06_account_suspension_and_reactivation(self):
        """Verify suspension blocks authentication and reactivation restores it."""
        conn = get_direct_connection()
        k_id = conn.execute("SELECT id FROM users WHERE username = 'k.patel'").fetchone()['id']
        conn.close()

        # Log in as admin to suspend k.patel
        self.client.post('/login', data={'username': 'admin', 'password': 'Admin@2026'}, follow_redirects=True)

        # Suspend
        suspend_resp = self.client.post(f'/admin/account/suspend/{k_id}', data={'reason': 'Dormancy policy violation.'}, follow_redirects=True)
        self.assertEqual(suspend_resp.status_code, 200)

        # Log out
        self.client.get('/logout')

        # Try to login as k.patel (should fail with SUSPENDED error)
        login_resp = self.client.post('/login', data={'username': 'k.patel', 'password': 'Employee@2026'}, follow_redirects=True)
        self.assertIn(b'SUSPENDED', login_resp.data)

        # Re-login as admin to reactivate k.patel
        self.client.post('/login', data={'username': 'admin', 'password': 'Admin@2026'}, follow_redirects=True)
        reactivate_resp = self.client.post(f'/admin/account/reactivate/{k_id}', data={'reason': 'Verification cleared.'}, follow_redirects=True)
        self.assertEqual(reactivate_resp.status_code, 200)

        # Log out
        self.client.get('/logout')

        # Login again as k.patel (should succeed)
        login_success_resp = self.client.post('/login', data={'username': 'k.patel', 'password': 'Employee@2026'}, follow_redirects=True)
        self.assertEqual(login_success_resp.status_code, 200)
        self.assertIn(b'Employee Security & Credential Hub', login_success_resp.data)

    def test_07_alert_management_resolve_and_dismiss(self):
        """Verify resolving and dismissing security alerts."""
        self.client.post('/login', data={'username': 'admin', 'password': 'Admin@2026'}, follow_redirects=True)

        # Resolve alert #2
        resolve_resp = self.client.post('/admin/alerts/resolve/2', data={'notes': 'Reviewed with supervisor and verified.'}, follow_redirects=True)
        self.assertEqual(resolve_resp.status_code, 200)
        self.assertIn(b'Resolved', resolve_resp.data)

        # Dismiss alert #3
        dismiss_resp = self.client.post('/admin/alerts/reject/3', data={'reason': 'Employee approved leave exemption.'}, follow_redirects=True)
        self.assertEqual(dismiss_resp.status_code, 200)
        self.assertIn(b'Dismissed', dismiss_resp.data)

    def test_08_approval_system_workflow(self):
        """Verify admin approval and rejection workflows."""
        self.client.post('/login', data={'username': 'admin', 'password': 'Admin@2026'}, follow_redirects=True)

        # Approve request #1
        approve_resp = self.client.post('/admin/approvals/approve/1', data={'notes': 'Identity verified via video call.'}, follow_redirects=True)
        self.assertEqual(approve_resp.status_code, 200)
        self.assertIn(b'Approved', approve_resp.data)

        # Reject request #2
        reject_resp = self.client.post('/admin/approvals/reject/2', data={'reason': 'Corporate ID card re-verification required.'}, follow_redirects=True)
        self.assertEqual(reject_resp.status_code, 200)
        self.assertIn(b'Rejected', reject_resp.data)

    def test_09_api_threat_scan(self):
        """Verify API automated threat scan endpoint."""
        self.client.post('/login', data={'username': 'admin', 'password': 'Admin@2026'}, follow_redirects=True)

        scan_resp = self.client.post('/admin/api/scan')
        self.assertEqual(scan_resp.status_code, 200)
        data = json.loads(scan_resp.data)
        self.assertTrue(data['success'])
        self.assertIn('Scan complete', data['message'])

    def test_10_audit_log_export_csv(self):
        """Verify audit log CSV export."""
        self.client.post('/login', data={'username': 'admin', 'password': 'Admin@2026'}, follow_redirects=True)

        response = self.client.get('/admin/audit-logs/export')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, 'text/csv')
        self.assertIn(b'Log ID,Timestamp,Admin Username', response.data)

    def test_11_employee_portal_interactions(self):
        """Verify employee portal features (MFA toggle, request submission, suspicious reporting)."""
        # Log in as active employee (Ananya Sharma)
        self.client.post('/login', data={'username': 'a.sharma', 'password': 'Employee@2026'}, follow_redirects=True)

        # Check portal view
        portal_resp = self.client.get('/employee/portal')
        self.assertEqual(portal_resp.status_code, 200)
        self.assertIn(b'Ananya Sharma', portal_resp.data)

        # Toggle MFA
        mfa_resp = self.client.post('/employee/toggle-mfa', follow_redirects=True)
        self.assertEqual(mfa_resp.status_code, 200)

        # Submit security request
        req_resp = self.client.post('/employee/request', data={
            'request_type': 'Planned Leave Notification',
            'urgency': 'Low',
            'reason': 'Attending Crimathon symposium for 4 days.'
        }, follow_redirects=True)
        self.assertEqual(req_resp.status_code, 200)
        self.assertIn(b'submitted', req_resp.data)

        # Report suspicious activity
        incident_resp = self.client.post('/employee/report-suspicious', data={
            'description': 'Received unrecognized password reset notification via email.'
        }, follow_redirects=True)
        self.assertEqual(incident_resp.status_code, 200)
        self.assertIn(b'dispatched', incident_resp.data)

if __name__ == '__main__':
    unittest.main()
