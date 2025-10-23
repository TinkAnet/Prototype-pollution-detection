"""
Tests for the CLI module.
"""

import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock
import sys
import io

from prototype_pollution_detector.cli import main


class TestCLI(unittest.TestCase):
    """Test cases for the command-line interface."""
    
    def test_version_argument(self):
        """Test that --version flag works."""
        with self.assertRaises(SystemExit) as cm:
            with patch('sys.stdout', new_callable=io.StringIO):
                main(['--version'])
        self.assertEqual(cm.exception.code, 0)
    
    def test_help_argument(self):
        """Test that --help flag works."""
        with self.assertRaises(SystemExit) as cm:
            with patch('sys.stdout', new_callable=io.StringIO):
                main(['--help'])
        self.assertEqual(cm.exception.code, 0)
    
    def test_nonexistent_path(self):
        """Test error handling for non-existent paths."""
        with patch('sys.stderr', new_callable=io.StringIO) as mock_stderr:
            exit_code = main(['/nonexistent/path/to/file.js'])
            self.assertEqual(exit_code, 1)
            self.assertIn("does not exist", mock_stderr.getvalue())
    
    def test_valid_file_path(self):
        """Test analysis of a valid file path."""
        # Create a temporary test file
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
            f.write('const x = {};')
            temp_path = f.name
        
        try:
            with patch('sys.stdout', new_callable=io.StringIO) as mock_stdout:
                exit_code = main([temp_path])
                self.assertEqual(exit_code, 0)
                output = mock_stdout.getvalue()
                # Should contain analysis results
                self.assertTrue(len(output) > 0)
        finally:
            Path(temp_path).unlink()
    
    def test_verbose_flag(self):
        """Test that verbose flag is properly passed."""
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
            f.write('const x = {};')
            temp_path = f.name
        
        try:
            with patch('sys.stdout', new_callable=io.StringIO):
                exit_code = main([temp_path, '--verbose'])
                self.assertEqual(exit_code, 0)
        finally:
            Path(temp_path).unlink()


if __name__ == '__main__':
    unittest.main()
