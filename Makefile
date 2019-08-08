CXXFLAGS=-Wall -fPIC -std=c++11

LDLIBS=-lpam -lcurl -lldap -llber

objects = src/pam_oauth2_device.o \
		  src/include/config.o \
		  src/include/ldapquery.o \
		  src/include/nayuki/BitBuffer.o \
		  src/include/nayuki/QrCode.o \
		  src/include/nayuki/QrSegment.o

all: pam_oauth2_device.so

%.o: %.c %.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

pam_oauth2_device.so: $(objects)
	$(CXX) -shared $^ $(LDLIBS) -o $@

clean:
	rm -f $(objects)

distclean: clean
	rm -f pam_oauth2_device.so

install: pam_oauth2_device.so
	install -D -t $(DESTDIR)$(PREFIX)/lib/security pam_oauth2_device.so
	install -m 600 -D config_template.json $(DESTDIR)$(PREFIX)/etc/pam_oauth2_device/config.json
