import requests
import time
import qrcode
import yaml


def pam_sm_authenticate(pamh, flags, argv):

    try:
        args = parse_args(argv)

        config = load_config(args['config_file'])

        authorization = make_authorization_request(config)

        print_authentication_promt(pamh, config, authorization)

        token_response = poll_for_token(pamh, config, authorization)

        userinfo = make_userinfo_request(config, token_response)

        authorize_user(pamh, config, userinfo)

        return pamh.PAM_SUCCESS

    except BaseException as e:
        print e


def parse_args(argv):
    args = {
        'config_file': argv[1] if len(argv) > 1 else None
    }
    return args


def load_config(file_name):
    if file_name is None:
        file_name = '/etc/pam_oauth2_device/config.yml'
    with open(file_name, 'r') as stream:
        return yaml.safe_load(stream)


def make_authorization_request(config):
    device_response = requests.post(
        config['oauth']['device_endpoint'],
        data={
            'client_id': config['oauth']['client']['id'],
            'scope': ' '.join(config['oauth']['scope'])
        }
    )

    if 'error' in device_response.json():
        raise Oauth2Exception(device_response.json()['error'], device_response.json()['error_description'])
    return device_response.json()


def print_authentication_promt(pamh, config, authorization):
    user_code = str(authorization['user_code'])
    url = str(authorization['verification_uri'])
    url_complete = url
    if 'verification_uri_complete' in authorization:
        url_complete = str(authorization['verification_uri_complete'])
    qr_str = generate_qr(url_complete, config)

    prompt(pamh, config['texts']['prompt'].format(url=url_complete, url_short=url, code=user_code, qr=qr_str))


def poll_for_token(pamh, config, authorization):

    device_code = str(authorization['device_code'])

    timeout = 300
    interval = 1
    while True:
        time.sleep(interval)
        timeout -= interval

        token_response = requests.post(
            config['oauth']['token_endpoint'],
            auth=(
                config['oauth']['client']['id'],
                config['oauth']['client']['secret']
            ),
            data={
                'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
                'device_code': device_code,
                'client_id': config['oauth']['client']['id']
            }
        )
        if 'error' in token_response.json():

            if token_response.json()['error'] == 'authorization_pending':
                pass

            elif token_response.json()['error'] == 'slow_down':
                interval += 1
                pass

            else:
                raise Oauth2Exception(token_response.json()['error'], token_response.json()['error_description'])

        else:
            break

        if timeout < 0:
            send(pamh, 'Timeout, please try again')
            raise Oauth2Exception(token_response.json()['error'], token_response.json()['error_description'])

    return token_response.json()


def make_userinfo_request(config, token_response):
    userinfo_response = requests.get(
        config['oauth']['userinfo_endpoint'],
        headers={
            'Authorization': 'Bearer %s' % str(token_response['access_token'])
        }
    )

    if 'error' in userinfo_response.json():
        raise Oauth2Exception(userinfo_response.json()['error'], userinfo_response.json()['error_description'])

    return userinfo_response.json()


def authorize_user(pamh, config, userinfo):
    sub = userinfo['sub']

    if sub not in config['users']:
        raise Oauth2Exception(
            'User not found',
            'username is not found in configuration',
            sub
        )

    if pamh.user not in config['users'][sub]:
        raise Oauth2Exception(
            'Authorization failed',
            'Do not have sufficient permission',
            sub,
            pamh.user
        )


def generate_qr(str, config):
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_L)
    qr.add_data(str)
    qr.make()

    if config['qr']['big']:
        return generate_qr_big(qr.modules, config)
    else:
        return generate_qr_small(qr.modules, config)


def generate_qr_small(modules, config):
    before_line = config['qr']['before_line']
    after_line = config['qr']['after_line']

    qr_str = before_line
    qr_str += qr_half_char(False, False, config)
    for x in range(0, len(modules[0])):
        qr_str += qr_half_char(False, False, config)
    qr_str += qr_half_char(False, False, config) + after_line + '\n'

    for y in range(0, len(modules)//2+1):
        qr_str += before_line + qr_half_char(False, False, config)
        for x in range(0, len(modules[0])):
            qr_str += qr_half_char(
                modules[y*2][x],
                modules[y*2+1][x] if len(modules) > y*2+1 else False,
                config
            )
        qr_str += qr_half_char(False, False, config)
        if y != len(modules)//2:
            qr_str += after_line + '\n'

    return qr_str


def generate_qr_big(modules, config):
    before_line = config['qr']['before_line']
    after_line = config['qr']['after_line']

    qr_str = before_line

    qr_str += qr_full_char(False, config)
    for x in range(0, len(modules[0])):
        qr_str += qr_full_char(False, config)
    qr_str += qr_full_char(False, config) + after_line + '\n'

    for y in range(0, len(modules)):
        qr_str += before_line + qr_full_char(False, config)
        for x in range(0, len(modules[0])):
            qr_str += qr_full_char(modules[y][x], config)
        qr_str += qr_full_char(False, config) + after_line + '\n'

    qr_str += before_line + qr_full_char(False, config)
    for x in range(0, len(modules[0])):
        qr_str += qr_full_char(False, config)
    qr_str += qr_full_char(False, config) + after_line

    return qr_str


def qr_half_char(top, bot, config):
    if config['qr']['inverse']:
        if top and bot:
            return '\033[40;97m\xE2\x96\x88\033[0m'
        if not top and bot:
            return '\033[40;97m\xE2\x96\x84\033[0m'
        if top and not bot:
            return '\033[40;97m\xE2\x96\x80\033[0m'
        if not top and not bot:
            return '\033[40;97m\x20\033[0m'
    else:
        if top and bot:
            return '\033[40;97m\x20\033[0m'
        if not top and bot:
            return '\033[40;97m\xE2\x96\x80\033[0m'
        if top and not bot:
            return '\033[40;97m\xE2\x96\x84\033[0m'
        if not top and not bot:
            return '\033[40;97m\xE2\x96\x88\033[0m'


def qr_full_char(filled, config):
    if config['qr']['inverse']:
        if filled:
            return '\033[40;97m\xE2\x96\x88\xE2\x96\x88\033[0m'
        else:
            return '\033[40;97m\x20\x20\033[0m'
    else:
        if filled:
            return '\033[40;97m\x20\x20\033[0m'
        else:
            return '\033[40;97m\xE2\x96\x88\xE2\x96\x88\033[0m'


def send(pamh, msg):
    return pamh.conversation(pamh.Message(pamh.PAM_TEXT_INFO, msg))


def prompt(pamh, msg):
    return pamh.conversation(pamh.Message(pamh.PAM_PROMPT_ECHO_ON, msg))


class Oauth2Exception(Exception):
    pass


# Need to implement all methods to fulfill pam_python contract

def pam_sm_setcred(pamh, flags, argv):
    return pamh.PAM_SUCCESS


def pam_sm_acct_mgmt(pamh, flags, argv):
    return pamh.PAM_SUCCESS


def pam_sm_open_session(pamh, flags, argv):
    return pamh.PAM_SUCCESS


def pam_sm_close_session(pamh, flags, argv):
    return pamh.PAM_SUCCESS


def pam_sm_chauthtok(pamh, flags, argv):
    return pamh.PAM_SUCCESS

