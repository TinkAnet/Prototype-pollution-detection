"""
Tests for the parser module.
"""

import unittest
from pathlib import Path
import tempfile

from prototype_pollution_detector.parser import JavaScriptParser


class TestJavaScriptParser(unittest.TestCase):
    """Test cases for the JavaScript parser."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.parser = JavaScriptParser()
    
    def test_parser_initialization(self):
        """Test parser can be initialized."""
        parser = JavaScriptParser(verbose=True)
        self.assertTrue(parser.verbose)
    
    def test_parse_file_not_found(self):
        """Test parsing a non-existent file raises error."""
        with self.assertRaises(FileNotFoundError):
            self.parser.parse_file(Path('/nonexistent/file.js'))
    
    def test_parse_file_structure(self):
        """Test that parse_file returns expected structure."""
        # Create a temporary JavaScript file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
            f.write('const x = 1;')
            temp_path = Path(f.name)
        
        try:
            result = self.parser.parse_file(temp_path)
            
            # Check expected keys in result
            self.assertIn('file', result)
            self.assertIn('ast', result)
            self.assertIn('functions', result)
            self.assertIn('assignments', result)
            self.assertIn('property_accesses', result)
            
            # Check file path is correct
            self.assertEqual(result['file'], str(temp_path))
        finally:
            temp_path.unlink()
    
    def test_parse_code_from_string(self):
        """Test parsing JavaScript code from a string."""
        code = 'const x = 1;'
        result = self.parser.parse_code(code, 'test.js')
        
        # Check expected keys
        self.assertIn('file', result)
        self.assertIn('ast', result)
        self.assertEqual(result['file'], 'test.js')
    
    def test_extract_property_assignments(self):
        """Test extracting property assignments from AST."""
        ast = {'file': 'test.js', 'ast': None}
        result = self.parser.extract_property_assignments(ast)
        
        # Should return a list (even if empty for stub)
        self.assertIsInstance(result, list)
    
    def test_extract_function_calls(self):
        """Test extracting function calls from AST."""
        ast = {'file': 'test.js', 'ast': None}
        result = self.parser.extract_function_calls(ast)
        
        # Should return a list (even if empty for stub)
        self.assertIsInstance(result, list)


if __name__ == '__main__':
    unittest.main()
