# PAM module for OAuth 2.0 Device flow 

## Instalation (Ubuntu 16.04)
mkdir /lib/security
cp src/pam_oauth2_device.so /lib/security/
vim /etc/pam_oauth2_device/config.yml
```
See `example_config.yml`

## Example Configuration (SSH, Ubuntu 16.04)
```
vim /etc/pam.d/sshd
```
edit
```
    auth required pam_oauth2_device.so /etc/pam_oauth2_device/config.yml
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
    auth required pam_oauth2_device.so
```

### Deploy
```
cp src/pam_oauth2_device.so/lib/security/
```
### Test
```
pamtester -v pamtester username authenticate
```
