import unittest
import json
import os
import shutil
import sys
import tempfile
import sqlite3
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add parent directory to path to import server
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import server

class TestServer(unittest.TestCase):
    def setUp(self):
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

    @patch('server._detect_default_subnet', return_value='192.168.1.0/24')
    def test_network_default_success(self, _mock_detect):
        """Test default subnet endpoint when detection succeeds."""
        response = self.app.get('/api/network/default')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['subnet'], '192.168.1.0/24')
        self.assertEqual(data['source'], 'auto')

    @patch('server._detect_default_subnet', return_value=None)
    def test_network_default_not_found(self, _mock_detect):
        """Test default subnet endpoint fallback behavior when detection fails."""
        response = self.app.get('/api/network/default')
        self.assertEqual(response.status_code, 404)
        data = json.loads(response.data)
        self.assertIsNone(data['subnet'])
        self.assertEqual(data['source'], 'fallback-required')

    def test_logs_endpoint(self):
        """Test logs endpoint returns bounded list payload."""
        response = self.app.get('/api/logs?limit=10')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('logs', data)
        self.assertIsInstance(data['logs'], list)
        self.assertLessEqual(len(data['logs']), 10)

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

    @patch('server.threading.Thread')
    def test_scan_start_ipv6_subnet(self, mock_thread):
        """Test starting a scan with an IPv6 CIDR subnet."""
        mock_thread_instance = MagicMock()
        mock_thread.return_value = mock_thread_instance

        payload = {
            'subnet': '2001:db8::/64',
            'options': {'discovery': True}
        }
        response = self.app.post('/api/scan', json=payload)
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['status'], 'success')

        mock_thread.assert_called_once()
        mock_thread_instance.start.assert_called_once()

    def test_scan_start_missing_subnet(self):
        """Test starting a scan without subnet."""
        response = self.app.post('/api/scan', json={})
        self.assertEqual(response.status_code, 400)

    def test_scan_start_already_in_progress(self):
        """Test starting a scan when one is already running."""
        # Set scan state to in-progress in the DB
        conn = sqlite3.connect(self.db_path)
        conn.execute('UPDATE scan_state SET is_scanning = 1 WHERE id = 1')
        conn.commit()
        conn.close()

        response = self.app.post('/api/scan', json={'subnet': '1.2.3.4/32'})
        self.assertEqual(response.status_code, 409)

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

    def test_scan_invalid_ipv6_prefix_rejected(self):
        """Test that invalid IPv6 CIDR prefixes are rejected."""
        response = self.app.post('/api/scan', json={'subnet': '2001:db8::/129'})
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

    def test_zombie_state_reset(self):
        """Test that scan state is reset on startup (zombie prevention)."""
        # Simulate a zombie state: is_scanning stuck at 1
        conn = sqlite3.connect(self.db_path)
        conn.execute('UPDATE scan_state SET is_scanning = 1 WHERE id = 1')
        conn.commit()
        conn.close()

        # Verify it's stuck
        response = self.app.get('/api/status')
        data = json.loads(response.data)
        self.assertTrue(data['scanning'])

        # Call reset (simulating app restart)
        server.reset_scan_state()

        # Verify it's cleared
        response = self.app.get('/api/status')
        data = json.loads(response.data)
        self.assertFalse(data['scanning'])

    def test_atomic_scan_lock(self):
        """Test that try_claim_scan is atomic - second claim fails."""
        # First claim should succeed
        self.assertTrue(server.try_claim_scan())

        # Second claim should fail (scan already running)
        self.assertFalse(server.try_claim_scan())

        # Status should show scanning
        response = self.app.get('/api/status')
        data = json.loads(response.data)
        self.assertTrue(data['scanning'])

        # Release
        server.set_scan_state(False)

        # Now claim should succeed again
        self.assertTrue(server.try_claim_scan())


class TestServerPersistence(unittest.TestCase):
    def test_resolve_data_dir_prefers_env_var(self):
        with patch.dict('os.environ', {'CRA_DATA_DIR': '/tmp/cra-data'}, clear=False):
            resolved = server._resolve_data_dir()
        self.assertEqual(resolved, Path('/tmp/cra-data'))

    def test_migrate_data_moves_legacy_db_to_target(self):
        tmp = tempfile.mkdtemp()
        try:
            base = Path(tmp)
            legacy_db = base / 'scans.db'
            target_db = base / 'data' / 'scans.db'

            with sqlite3.connect(legacy_db) as conn:
                conn.execute('CREATE TABLE scan_history (id INTEGER PRIMARY KEY, timestamp TEXT, target_range TEXT, summary TEXT, full_report TEXT)')
                conn.execute(
                    'INSERT INTO scan_history (timestamp, target_range, summary, full_report) VALUES (?, ?, ?, ?)',
                    ('2026-02-17T00:00:00', '10.0.0.0/24', '{}', '{}')
                )
                conn.commit()

            old_legacy = server.LEGACY_DB_FILE
            old_data_dir = server.DATA_DIR
            old_db_file = server.DB_FILE
            try:
                server.LEGACY_DB_FILE = legacy_db
                server.DATA_DIR = base / 'data'
                server.DB_FILE = str(target_db)

                server.migrate_data()

                self.assertTrue(target_db.exists())
                with sqlite3.connect(target_db) as conn:
                    row_count = conn.execute('SELECT COUNT(*) FROM scan_history').fetchone()[0]
                self.assertEqual(row_count, 1)
            finally:
                server.LEGACY_DB_FILE = old_legacy
                server.DATA_DIR = old_data_dir
                server.DB_FILE = old_db_file
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestNetworkHelpers(unittest.TestCase):
    def test_subnet_from_ip_ipv4(self):
        subnet = server._subnet_from_ip('192.168.10.42', prefix=24)
        self.assertEqual(subnet, '192.168.10.0/24')

    def test_subnet_from_ip_invalid(self):
        subnet = server._subnet_from_ip('not-an-ip', prefix=24)
        self.assertIsNone(subnet)

    @patch('server._extract_candidate_ipv4_addresses', return_value=['10.0.5.12'])
    def test_detect_default_subnet_uses_private_candidate(self, _mock_candidates):
        subnet = server._detect_default_subnet()
        self.assertEqual(subnet, '10.0.5.0/24')

    @patch('server._extract_candidate_ipv4_addresses', return_value=[])
    def test_detect_default_subnet_no_candidates(self, _mock_candidates):
        subnet = server._detect_default_subnet()
        self.assertIsNone(subnet)

if __name__ == '__main__':
    unittest.main()
