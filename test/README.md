# PAM module testing

1. Download and unpack googletest https://github.com/google/googletest/archive/release-1.8.1.tar.gz.
2. Edit Makefile, change GTEST_DIR to point to the googletest directory, e.g. `./googletest-release-1.8.1/googletest/`.
3. Run mock server `./mock_server.py`.
4. In a new terminal window execute `make` to run the tests.
