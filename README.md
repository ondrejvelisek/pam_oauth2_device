# PAM module for OAuth 2.0 Device flow 

## Instalation (Ubuntu 16.04)
Read before copy-paste
```
apt install python python-requests python-qrcode libpam-python python-pip
pip install pyyaml
mkdir /lib/security
cp src/pam_oauth2_device.py /lib/security/
vim /etc/pam_oauth2_device/config.yml
```
See `example_config.yml`

## Example Configuration (SSH, Ubuntu 16.04)
```
vim /etc/pam.d/sshd
```
edit
```
    auth required pam_python.so pam_oauth2_device.py /etc/pam_oauth2_device/config.yml
```
```
vim /etc/ssh/sshd_config
```
edit
```
    PermitRootLogin yes
    RSAAuthentication no
    PubkeyAuthentication no
    PasswordAuthentication no
    ChallengeResponseAuthentication yes
    UsePAM yes
```
```
systemctl restart sshd
```
## Development

### Instalation (Ubuntu 16.04)
```
apt install pamtester
```
### Configuration (Ubuntu 16.04)
```
vim /etc/pam.d/pamtester
```
create
```
    auth required pam_python.so pam_oauth2_device.py
```

### Deploy
```
cp src/pam_oauth2_device.py /lib/security/
```
### Test
```
pamtester -v pamtester username authenticate
```
