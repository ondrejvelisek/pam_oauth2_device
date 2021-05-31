GTEST_DIR = ./googletest-release-1.10.0/googletest/

SRC_DIR = ../src

CPPFLAGS += -isystem $(GTEST_DIR)/include

CXXFLAGS += -g -Wall -Wextra -Wno-unused-parameter -pthread -std=c++11

LDLIBS=-lpam -lcurl -lldap -llber

TESTS = test_config test_pam_oauth2_device 

GTEST_HEADERS = $(GTEST_DIR)/include/gtest/*.h \
                $(GTEST_DIR)/include/gtest/internal/*.h

objects = $(SRC_DIR)/pam_oauth2_device.o \
		  $(SRC_DIR)/include/config.o \
		  $(SRC_DIR)/include/ldapquery.o \
		  $(SRC_DIR)/include/nayuki/BitBuffer.o \
		  $(SRC_DIR)/include/nayuki/QrCode.o \
		  $(SRC_DIR)/include/nayuki/QrSegment.o \
		  test_pam_oauth2_device.o

all: $(TESTS)
	for test in $(TESTS); do ./$${test}; done

clean:
	rm -f gtest.a gtest_main.a *.o $(objects)

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

%.o: %.c %.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

test_config.o: test_config.cpp $(GTEST_HEADERS) $(SRC_DIR)/include/config.hpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -I$(SRC_DIR) -c test_config.cpp

test_config: test_config.o gtest_main.a $(SRC_DIR)/include/config.o
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -lpthread $^ -o $@

test_pam_oauth2_device.o: test_pam_oauth2_device.cpp $(GTEST_HEADERS) $(SRC_DIR)/include/config.hpp $(SRC_DIR)/pam_oauth2_device.hpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -I$(SRC_DIR) -c test_pam_oauth2_device.cpp

test_pam_oauth2_device: gtest_main.a $(objects)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -lpthread $^ $(LDLIBS) -o $@
