"""
Tests for the detector module.
"""

import unittest
from pathlib import Path
import tempfile
import json
import os

from prototype_pollution_detector.detector import PrototypePollutionDetector


class TestPrototypePollutionDetector(unittest.TestCase):
    """Test cases for the main detector."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.detector = PrototypePollutionDetector()
    
    def test_detector_initialization(self):
        """Test detector can be initialized."""
        detector = PrototypePollutionDetector(verbose=True)
        self.assertTrue(detector.verbose)
        self.assertIsNotNone(detector.parser)
        self.assertIsNotNone(detector.analyzer)
    
    def test_analyze_single_file(self):
        """Test analyzing a single JavaScript file."""
        # Create a temporary JavaScript file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
            f.write('const x = {};')
            temp_path = Path(f.name)
        
        try:
            result = self.detector.analyze(temp_path)
            
            # Check expected structure
            self.assertIn('file', result)
            self.assertIn('vulnerabilities', result)
            self.assertIn('vulnerability_count', result)
            
            # Check types
            self.assertIsInstance(result['vulnerabilities'], list)
            self.assertIsInstance(result['vulnerability_count'], int)
        finally:
            temp_path.unlink()
    
    def test_analyze_directory(self):
        """Test analyzing a directory of JavaScript files."""
        # Create a temporary directory with JavaScript files
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Create some test JS files
            (temp_path / 'test1.js').write_text('const x = 1;')
            (temp_path / 'test2.js').write_text('const y = 2;')
            
            result = self.detector.analyze(temp_path)
            
            # Check expected structure
            self.assertIn('directory', result)
            self.assertIn('files', result)
            self.assertIn('total_vulnerabilities', result)
            
            # Should have analyzed 2 files
            self.assertGreaterEqual(len(result['files']), 2)
    
    def test_analyze_non_js_file_skipped(self):
        """Test that non-JavaScript files are skipped."""
        # Create a temporary non-JS file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('Not JavaScript')
            temp_path = Path(f.name)
        
        try:
            result = self.detector.analyze(temp_path)
            
            # Should be marked as skipped
            self.assertTrue(result.get('skipped', False))
            self.assertIn('reason', result)
        finally:
            temp_path.unlink()
    
    def test_save_results(self):
        """Test saving results to a JSON file."""
        results = {
            'file': 'test.js',
            'vulnerabilities': [],
            'vulnerability_count': 0,
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_path = Path(f.name)
        
        try:
            self.detector.save_results(results, temp_path)
            
            # Check file was created and contains valid JSON
            self.assertTrue(temp_path.exists())
            
            with open(temp_path, 'r') as f:
                loaded = json.load(f)
                self.assertEqual(loaded['file'], 'test.js')
                self.assertEqual(loaded['vulnerability_count'], 0)
        finally:
            if temp_path.exists():
                temp_path.unlink()
    
    def test_print_results_file(self):
        """Test printing results for a single file."""
        results = {
            'file': 'test.js',
            'vulnerabilities': [],
            'vulnerability_count': 0,
        }
        
        # Should not raise an exception
        import io
        import sys
        
        captured_output = io.StringIO()
        sys.stdout = captured_output
        
        try:
            self.detector.print_results(results)
            output = captured_output.getvalue()
            self.assertIn('test.js', output)
        finally:
            sys.stdout = sys.__stdout__
    
    def test_print_results_directory(self):
        """Test printing results for a directory."""
        results = {
            'directory': '/test/dir',
            'files': [
                {'file': 'test1.js', 'vulnerability_count': 0, 'vulnerabilities': []},
                {'file': 'test2.js', 'vulnerability_count': 1, 'vulnerabilities': [
                    {'severity': 'high', 'line': 10, 'message': 'Test', 'type': 'pollution'}
                ]},
            ],
            'total_vulnerabilities': 1,
        }
        
        # Should not raise an exception
        import io
        import sys
        
        captured_output = io.StringIO()
        sys.stdout = captured_output
        
        try:
            self.detector.print_results(results)
            output = captured_output.getvalue()
            self.assertIn('/test/dir', output)
            self.assertIn('test1.js', output)
            self.assertIn('test2.js', output)
        finally:
            sys.stdout = sys.__stdout__


if __name__ == '__main__':
    unittest.main()
