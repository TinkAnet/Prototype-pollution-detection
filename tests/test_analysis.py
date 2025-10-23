"""
Tests for the analysis module.
"""

import unittest
from prototype_pollution_detector.analysis import (
    PrototypePollutionAnalyzer,
    Vulnerability,
)


class TestPrototypePollutionAnalyzer(unittest.TestCase):
    """Test cases for the prototype pollution analyzer."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.analyzer = PrototypePollutionAnalyzer()
    
    def test_analyzer_initialization(self):
        """Test analyzer can be initialized."""
        analyzer = PrototypePollutionAnalyzer(verbose=True)
        self.assertTrue(analyzer.verbose)
        self.assertEqual(len(analyzer.vulnerabilities), 0)
    
    def test_dangerous_properties_defined(self):
        """Test that dangerous properties are defined."""
        self.assertIn('__proto__', self.analyzer.DANGEROUS_PROPERTIES)
        self.assertIn('prototype', self.analyzer.DANGEROUS_PROPERTIES)
        self.assertIn('constructor', self.analyzer.DANGEROUS_PROPERTIES)
    
    def test_pollution_patterns_defined(self):
        """Test that pollution patterns are defined."""
        self.assertGreater(len(self.analyzer.POLLUTION_PATTERNS), 0)
    
    def test_analyze_ast(self):
        """Test analyzing an AST."""
        ast = {
            'file': 'test.js',
            'ast': None,
            'functions': [],
            'assignments': [],
        }
        
        result = self.analyzer.analyze_ast(ast)
        self.assertIsInstance(result, list)
    
    def test_check_property_assignment(self):
        """Test checking property assignments."""
        node = {'type': 'assignment', 'property': 'test'}
        result = self.analyzer.check_property_assignment(node)
        self.assertIsInstance(result, bool)
    
    def test_check_merge_operation(self):
        """Test checking merge operations."""
        node = {'type': 'call', 'function': 'merge'}
        result = self.analyzer.check_merge_operation(node)
        self.assertIsInstance(result, bool)
    
    def test_check_user_controlled_access(self):
        """Test checking user-controlled access."""
        node = {'type': 'member_access'}
        result = self.analyzer.check_user_controlled_access(node)
        self.assertIsInstance(result, bool)
    
    def test_get_vulnerability_report(self):
        """Test generating vulnerability report."""
        report = self.analyzer.get_vulnerability_report()
        
        # Check expected keys
        self.assertIn('total_vulnerabilities', report)
        self.assertIn('by_severity', report)
        self.assertIn('vulnerabilities', report)
        
        # Check severity breakdown
        self.assertIn('high', report['by_severity'])
        self.assertIn('medium', report['by_severity'])
        self.assertIn('low', report['by_severity'])
    
    def test_vulnerability_dataclass(self):
        """Test Vulnerability dataclass."""
        vuln = Vulnerability(
            severity='high',
            line=10,
            column=5,
            message='Test vulnerability',
            code_snippet='test code',
            vulnerability_type='prototype_pollution',
        )
        
        self.assertEqual(vuln.severity, 'high')
        self.assertEqual(vuln.line, 10)
        self.assertEqual(vuln.column, 5)
        self.assertEqual(vuln.message, 'Test vulnerability')


if __name__ == '__main__':
    unittest.main()
