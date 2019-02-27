all:
	g++ -fPIC -c src/pam_oauth2_device.cpp
	g++ -shared -o pam_oauth2_device.so pam_oauth2_device.o -lpam -lcurl
clean:
	rm -f pam_oauth2_device.o pam_oauth2_device.so
