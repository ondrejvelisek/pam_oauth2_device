CXXFLAGS=-Wall -fPIC

LDLIBS=-lpam -lcurl -lldap -llber

all: pam_oauth2_device.so

config.o: src/include/config.cpp src/include/config.h
	$(CXX) $(CXXFLAGS) -c src/include/config.cpp

ldapquery.o: src/include/ldapquery.c src/include/ldapquery.h
	$(CXX) $(CXXFLAGS) -c src/include/ldapquery.c

pam_oauth2_device.o: src/pam_oauth2_device.cpp src/include/config.h src/include/ldapquery.h src/pam_oauth2_device.h
	$(CXX) $(CXXFLAGS) -c src/pam_oauth2_device.cpp

pam_oauth2_device.so: config.o ldapquery.o pam_oauth2_device.o
	$(CXX) -shared $^ $(LDLIBS) -o $@

clean:
	rm -f config.o ldapquery.o pam_oauth2_device.o

distclean: clean
	rm -f pam_oauth2_device.so
