import os
import sys
import unittest

from samples.caesar_cipher import main as caesar_cipher_sample
from samples.substitution_cipher import main as substitution_cipher_sample


class TestSamples(unittest.TestCase):
    def test_caesar_cipher_sample_runs_without_blowing_up(self):
        with open(os.devnull, 'w') as devnull:
            stdout = sys.stdout
            sys.stdout = devnull

            try:
                return_code = -1
                return_code = caesar_cipher_sample(filename='data/hello_world.txt')
            finally:
                sys.stdout = stdout
                self.assertEqual(return_code, 0, 'Main function returned non-zero exit code.')

    def test_substitution_cipher_sample_runs_without_blowing_up(self):
        with open(os.devnull, 'w') as devnull:
            stdout = sys.stdout
            sys.stdout = devnull

            try:
                return_code = -1
                return_code = substitution_cipher_sample(filename='data/hello_world.txt')
            finally:
                sys.stdout = stdout
                self.assertEqual(return_code, 0, 'Main function returned non-zero exit code.')



if __name__ == '__main__':
    unittest.main()
