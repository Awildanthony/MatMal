# TODO: does a static analysis on a binary in the test_malware directory

import sys

if __name__ == "__main__":

    arguments = sys.argv

    virus_hash = arguments[0]

    objdump -