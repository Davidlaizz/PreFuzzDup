import unittest
from unittest.mock import patch

from run_full_lookup_experiment import parse_arguments


class PortabilityTests(unittest.TestCase):
    def test_default_results_stay_outside_versioned_tools(self):
        with patch('sys.argv', ['runner']):
            args = parse_arguments()
        self.assertEqual(args.output, args.repo / 'results-local/enron-full/lookup-experiment')
        self.assertTrue((args.repo / 'PreFuzzDup/src/main.cpp').is_file())
