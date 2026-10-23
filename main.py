"""
main.py
=======
Application entrypoint for "Secure Image Steganography with AES Encryption".

Run normally:
    python main.py

Run test suite:
    python main.py --test
"""

import sys
import argparse


def run_gui():
    """Launches the Tkinter desktop GUI application."""
    from gui import SteganographyApp

    app = SteganographyApp()
    app.mainloop()


def run_tests():
    """Runs automated unit tests and reports results."""
    import unittest
    import test_stego

    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(test_stego)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)


def main():
    parser = argparse.ArgumentParser(
        description="Secure Image Steganography with AES-256 Encryption (Tkinter GUI)."
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Run the automated test suite instead of launching the GUI.",
    )
    args = parser.parse_args()

    if args.test:
        run_tests()
    else:
        run_gui()


if __name__ == "__main__":
    main()
