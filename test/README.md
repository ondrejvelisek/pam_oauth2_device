# PAM module testing

1. Download and unpack googletest https://github.com/google/googletest/archive/refs/tags/release-1.10.0.tar.gz
2. If you downloaded a different version, edit Makefile.
   Change GTEST_DIR to point to the googletest directory,
   e.g. `googletest-release-1.10.0/googletest/`.
3. Run mock server `./mock_server.py`.
4. In a new terminal window execute `make` to run the tests.
