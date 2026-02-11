import unittest
import json
import os
import sys
import tempfile
import sqlite3
from unittest.mock import patch, MagicMock

# Add parent directory to path to import server
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import server

class TestServer(unittest.TestCase):
    def setUp(self):
        # Reset global state
        server.is_scanning = False
        server.scan_error = None

        # Create a temporary file for the database
        self.db_fd, self.db_path = tempfile.mkstemp()

        # Patch the DB_FILE in the server module
        self.patcher = patch('server.DB_FILE', self.db_path)
        self.mock_db_file = self.patcher.start()

        # Initialize the database
        server.init_db()

        # Create a test client
        self.app = server.app.test_client()
        self.app.testing = True

    def tearDown(self):
        # Stop the patcher
        self.patcher.stop()
        
        # Close and remove the temporary database
        os.close(self.db_fd)
        try:
            os.remove(self.db_path)
        except PermissionError:
            pass  # Windows may hold file locks briefly; ignore cleanup failure

    def test_status(self):
        """Test the status endpoint."""
        response = self.app.get('/api/status')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertFalse(data['scanning'])

    def test_config(self):
        """Test the config endpoint."""
        response = self.app.get('/api/config')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('version', data)
        self.assertIn('gemini_enabled', data)

    @patch('server.threading.Thread')
    def test_scan_start(self, mock_thread):
        """Test starting a scan."""
        # Mock the thread start so we don't actually run a scan in background
        mock_thread_instance = MagicMock()
        mock_thread.return_value = mock_thread_instance
        
        # Ensure is_scanning is False initially (reset global state if needed)
        server.is_scanning = False

        payload = {
            'subnet': '192.168.1.0/24',
            'options': {'discovery': True}
        }
        response = self.app.post('/api/scan', json=payload)
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['status'], 'success')
        
        # Verify thread was started
        mock_thread.assert_called_once()
        mock_thread_instance.start.assert_called_once()

    def test_scan_start_missing_subnet(self):
        """Test starting a scan without subnet."""
        response = self.app.post('/api/scan', json={})
        self.assertEqual(response.status_code, 400)

    @patch('server.is_scanning', True)
    def test_scan_start_already_in_progress(self):
        """Test starting a scan when one is already running."""
        # Note: server.is_scanning is a global variable.
        # Patching it directly here might be tricky because it's imported in the module scope.
        # A better way is to set it and unset it, or use patch.object if it were in a class.
        # Since it's a global in 'server', we need to set it on the module.
        
        original_state = server.is_scanning
        server.is_scanning = True
        try:
            response = self.app.post('/api/scan', json={'subnet': '1.2.3.4'})
            self.assertEqual(response.status_code, 409)
        finally:
            server.is_scanning = original_state

    def test_history_empty(self):
        """Test fetching history when empty."""
        response = self.app.get('/api/history')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data, [])

    def test_history_operations(self):
        """Test adding, retrieving, and deleting history."""
        # Manually insert a record into the temp db
        unique_subnet = "10.0.0.0/24"
        summary = {"total": 5, "compliant": 5}
        report = {"timestamp": "2023-01-01", "targetRange": unique_subnet, "summary": summary}
        
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''
            INSERT INTO scan_history (timestamp, target_range, summary, full_report)
            VALUES (?, ?, ?, ?)
        ''', ("2023-01-01", unique_subnet, json.dumps(summary), json.dumps(report)))
        scan_id = c.lastrowid
        conn.commit()
        conn.close()

        # 1. Test List
        response = self.app.get('/api/history')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['target_range'], unique_subnet)
        self.assertEqual(data[0]['id'], scan_id)

        # 2. Test Detail
        response = self.app.get(f'/api/history/{scan_id}')
        self.assertEqual(response.status_code, 200)
        detail = json.loads(response.data)
        self.assertEqual(detail['targetRange'], unique_subnet)

        # 3. Test Delete
        response = self.app.delete(f'/api/history/{scan_id}')
        self.assertEqual(response.status_code, 200)
        
        # Verify it's gone
        response = self.app.get(f'/api/history/{scan_id}')
        self.assertEqual(response.status_code, 404)
        
    def test_scan_invalid_subnet_format(self):
        """Test that invalid subnet formats are rejected."""
        response = self.app.post('/api/scan', json={'subnet': 'DROP TABLE; --'})
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertIn('Invalid subnet format', data['message'])

    def test_scan_no_json_body(self):
        """Test that non-JSON requests are rejected."""
        response = self.app.post('/api/scan', data='not json',
                                 content_type='text/plain')
        # Flask returns 415 Unsupported Media Type for non-JSON Content-Type
        self.assertIn(response.status_code, [400, 415])

    def test_get_latest_report(self):
        """Test retrieving the latest report."""
        report = {"timestamp": "2023-01-01", "targetRange": "10.0.0.0/24",
                  "devices": [], "summary": {"total": 0}}
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''INSERT INTO scan_history (timestamp, target_range, summary, full_report)
                     VALUES (?, ?, ?, ?)''',
                  ("2023-01-01", "10.0.0.0/24", json.dumps(report['summary']),
                   json.dumps(report)))
        conn.commit()
        conn.close()

        response = self.app.get('/api/report')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['targetRange'], '10.0.0.0/24')

    def test_get_latest_report_empty(self):
        """Test latest report when no scans exist."""
        response = self.app.get('/api/report')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIsNone(data)

    def test_history_search(self):
        """Test history search filtering by target range."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        for subnet in ["10.0.0.0/24", "192.168.1.0/24", "172.16.0.0/16"]:
            summary = json.dumps({"total": 1})
            report = json.dumps({"targetRange": subnet})
            c.execute('''INSERT INTO scan_history (timestamp, target_range, summary, full_report)
                         VALUES (?, ?, ?, ?)''',
                      ("2023-01-01", subnet, summary, report))
        conn.commit()
        conn.close()

        response = self.app.get('/api/history?search=192.168')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['target_range'], '192.168.1.0/24')

    def test_history_sort(self):
        """Test history sort by target_range ascending."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        for i, subnet in enumerate(["192.168.1.0/24", "10.0.0.0/24"]):
            summary = json.dumps({"total": 1})
            report = json.dumps({"targetRange": subnet})
            c.execute('''INSERT INTO scan_history (timestamp, target_range, summary, full_report)
                         VALUES (?, ?, ?, ?)''',
                      (f"2023-01-0{i+1}", subnet, summary, report))
        conn.commit()
        conn.close()

        response = self.app.get('/api/history?sort_by=target&order=asc')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(len(data), 2)
        self.assertEqual(data[0]['target_range'], '10.0.0.0/24')
        self.assertEqual(data[1]['target_range'], '192.168.1.0/24')

if __name__ == '__main__':
    unittest.main()
