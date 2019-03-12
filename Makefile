CPPFLAGS=-Wall -fPIC
LDLIBS=-lpam -lcurl -lldap -llber

all: config.o ldapquery.o pam_oauth2_device.o
	g++ -shared -o pam_oauth2_device.so pam_oauth2_device.o config.o ldapquery.o $(LDLIBS)
pam_oauth2_device.o:
	g++ $(CPPFLAGS) -c src/pam_oauth2_device.cpp -o pam_oauth2_device.o
ldapquery.o:
	g++ $(CPPFLAGS) -c src/include/ldapquery.c -o ldapquery.o
config.o:
	g++ $(CPPFLAGS) -c src/include/config.cpp -o config.o
clean:
	rm -f config.o ldapquery.o pam_oauth2_device.o
distclean: clean
	rm -f pam_oauth2_device.so
