import os
import sys
import unittest

from samples.caesar_cipher import main


class TestSamples(unittest.TestCase):
    def test_caesar_cipher_sample_runs_without_blowing_up(self):
        with open(os.devnull, 'w') as devnull:
            stdout = sys.stdout
            sys.stdout = devnull

            try:
                return_code = main(filename='data/hello_world.txt')
            finally:
                sys.stdout = stdout

        self.assertEqual(return_code, 0)


if __name__ == '__main__':
    unittest.main()
