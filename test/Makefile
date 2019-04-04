GTEST_DIR = ./googletest-release-1.8.1/googletest

SRC_DIR = ../src

CPPFLAGS += -isystem $(GTEST_DIR)/include

CXXFLAGS += -g -Wall -Wextra -Wno-unused-parameter -pthread

LDLIBS=-lpam -lcurl -lldap -llber

TESTS = test_config test_pam_oauth2_device 

GTEST_HEADERS = $(GTEST_DIR)/include/gtest/*.h \
                $(GTEST_DIR)/include/gtest/internal/*.h


all: $(TESTS)
	for test in $(TESTS); do ./$${test}; done

clean:
	rm -f gtest.a gtest_main.a *.o

distclean: clean
	rm -f $(TESTS)

GTEST_SRCS_ = $(GTEST_DIR)/src/*.cc $(GTEST_DIR)/src/*.h $(GTEST_HEADERS)

gtest-all.o : $(GTEST_SRCS_)
	$(CXX) $(CPPFLAGS) -I$(GTEST_DIR) $(CXXFLAGS) -c \
            $(GTEST_DIR)/src/gtest-all.cc

gtest_main.o : $(GTEST_SRCS_)
	$(CXX) $(CPPFLAGS) -I$(GTEST_DIR) $(CXXFLAGS) -c \
            $(GTEST_DIR)/src/gtest_main.cc

gtest.a : gtest-all.o
	$(AR) $(ARFLAGS) $@ $^

gtest_main.a : gtest-all.o gtest_main.o
	$(AR) $(ARFLAGS) $@ $^

config.o: $(SRC_DIR)/include/config.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $(SRC_DIR)/include/config.cpp

ldapquery.o: $(SRC_DIR)/include/ldapquery.c
	g++ $(CPPFLAGS) $(CXXFLAGS) -c $(SRC_DIR)/include/ldapquery.c

pam_oauth2_device.o: $(SRC_DIR)/pam_oauth2_device.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $(SRC_DIR)/pam_oauth2_device.cpp

test_config.o: test_config.cpp $(GTEST_HEADERS) $(SRC_DIR)/include/config.h
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -I$(SRC_DIR) -c test_config.cpp

test_config: test_config.o gtest_main.a config.o
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -lpthread $^ -o $@

test_pam_oauth2_device.o: test_pam_oauth2_device.cpp $(GTEST_HEADERS) $(SRC_DIR)/include/config.h $(SRC_DIR)/pam_oauth2_device.h
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -I$(SRC_DIR) -c test_pam_oauth2_device.cpp

test_pam_oauth2_device: test_pam_oauth2_device.o gtest_main.a config.o ldapquery.o pam_oauth2_device.o
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -lpthread $^ $(LDLIBS) -o $@

