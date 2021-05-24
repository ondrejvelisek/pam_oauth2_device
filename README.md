# PAM module for OAuth 2.0 Device flow

## Instalation (Ubuntu 18.04)

```
make
mkdir /lib/security
cp pam_oauth2_device.so /lib/security/
vim /etc/pam_oauth2_device/config.json
```

See `config_template.json` (LDAP section is optional).

## Example Configuration (SSH, Ubuntu 18.04)

Edit `/etc/pam.d/sshd` and comment out other common-auth sections

```
auth required pam_oauth2_device.so /etc/pam_oauth2_device/config.json
```

Edit `/etc/ssh/sshd_config`

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

## Configuration config.json

**qr** - allowed correction levels are

  * 0 - low
  * 1 - medium
  * 2 - high

**users** - user mapping. From claim configured in *username_attribute* to the local account name

**MFA** - under the **oauth** block, via setting ```"require_mfa": true```, the module will modify the requests to ask user 
to perform the MFA. For more info on the exact form, see the ```config_template.json``` file.

## Development

### Instalation (Ubuntu 18.04)

```
apt install pamtester
```

### Configuration (Ubuntu 18.04)

Edit `/etc/pam.d/pamtester`

```
auth required pam_oauth2_device.so
```

### Deploy

```
cp pam_oauth2_device.so /lib/security/
```

### Test

```
pamtester -v pamtester username authenticate
```
