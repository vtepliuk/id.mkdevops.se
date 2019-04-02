import jwt
from flask import Flask, render_template, request, session
import uuid
from base64 import b64encode
from requests import Request
import requests
from os import environ
from datetime import datetime
#from flask_oidc import OpenIDConnect

OAUTH2_AUTH_URL = environ.get('OAUTH2_AUTH_URL')
if not OAUTH2_AUTH_URL:
    raise AssertionError('OAUTH2_AUTH_URL missing!')
# OAUTH2_INFO_URL = environ.get('OAUTH2_INFO_URL')
# if not OAUTH2_INFO_URL:
#    raise AssertionError('OAUTH2_INFO_URL missing!')
OAUTH2_TOKEN_URL = environ.get('OAUTH2_TOKEN_URL')
if not OAUTH2_TOKEN_URL:
    raise AssertionError('OAUTH2_TOKEN_URL missing!')
OAUTH2_CLIENT_ID = environ.get('OAUTH2_CLIENT_ID')
if not OAUTH2_CLIENT_ID:
    raise AssertionError('OAUTH2_CLIENT_ID missing!')
OAUTH2_CLIENT_SECRET = environ.get('OAUTH2_CLIENT_SECRET')
if not OAUTH2_CLIENT_SECRET:
    raise AssertionError('OAUTH2_CLIENT_SECRET missing!')
OAUTH2_CLIENT_REDIRECT_URI = environ.get('OAUTH2_CLIENT_REDIRECT_URI')
if not OAUTH2_CLIENT_REDIRECT_URI:
    raise AssertionError('OAUTH2_CLIENT_REDIRECT_URI missing!')
APP_SECRET_KEY = environ.get('APP_SECRET_KEY')
if not APP_SECRET_KEY:
    raise AssertionError('APP_SECRET_KEY missing!')
OAUTH2_USERINFO_URL = environ.get('OAUTH2_USERINFO_URL')
if not OAUTH2_USERINFO_URL:
    raise AssertionError('OAUTH2_USERINFO_URL missing!')

app = Flask(__name__)
#app.config['OIDC_CLIENT_SECRETS'] = 'local-oauth2-client_secrets.json'
app.secret_key = APP_SECRET_KEY

#oidc = OpenIDConnect(app)


@app.route('/')
def index():
    req = Request(method='GET',
                  url=OAUTH2_AUTH_URL,
                  params={
                      'client_id': OAUTH2_CLIENT_ID,
                      'scope': 'openid email profile',
                      'state': uuid.uuid4().hex,
                      'response_type': 'code',
                      'redirect_uri': OAUTH2_CLIENT_REDIRECT_URI,
                      'max_age': 10
                      # 'approval_prompt': 'auto'
                  }).prepare()

    return render_template('main.html', authorize_url=req.url)


@app.route('/login')
#@oidc.require_login
def login():
    code = request.args.get('code')
    state = request.args.get('state')
    client_id = OAUTH2_CLIENT_ID
    client_secret = OAUTH2_CLIENT_SECRET
    # token_endpoint = OAUTH2_TOKEN_URL
    client_redirect_uri = OAUTH2_CLIENT_REDIRECT_URI
    credentials = '%s:%s' % (client_id, client_secret)
    auth_code = str(b64encode(credentials.encode()).decode())
    headers = {'Authorization': str('Basic ' + auth_code)}
    params = {'grant_type': 'authorization_code', 'code': code, 'redirect_uri': client_redirect_uri, 'client_secret': client_secret, 'client_id': client_id,}
    token_response = requests.post(params=params, headers=headers, url=OAUTH2_TOKEN_URL)
    access_token = token_response.json()['access_token']
    # refresh_token = token_response.json()['refresh_token']
    id_token = token_response.json()['id_token']
    token_type = token_response.json()['token_type']
    session['access_token'] = access_token
    session['id_token'] = id_token
    session['token_type'] = token_type
    # session['refresh_token'] = refresh_token
    return render_template('login.html', code=code, state=state, access_token=access_token, id_token=id_token, token_type=token_type)


@app.route('/profile')
def profile():
    access_token = session['access_token']
    verify_response = requests.get(url=OAUTH2_USERINFO_URL,
                                  headers={'Authorization': str('Bearer ' + access_token)})
    full_name = verify_response.json()['name']
    email = verify_response.json()['email']
    email_verified = verify_response.json()['email_verified']
    # id token parameters
    id_info = jwt.decode(session['id_token'], verify=False)
    iss = id_info['iss']
    sub_id = id_info['sub']
    aud = id_info['aud'][0]
    exp = '{:%Y-%m-%d %H:%M:%S}'.format(datetime.fromtimestamp(id_info['exp']))
    iat = '{:%Y-%m-%d %H:%M:%S}'.format(datetime.fromtimestamp(id_info['iat']))
    auth_time = '{:%Y-%m-%d %H:%M:%S}'.format(datetime.fromtimestamp(id_info['auth_time']))
    nonce = id_info['nonce']
    acr = id_info['acr']

    return render_template('profile.html', full_name=full_name, email=email, email_verified=email_verified, iss=iss,
                           exp=exp, sub_id=sub_id, acr=acr, auth_time=auth_time, iat=iat, aud=aud, nonce=nonce)


@app.route('/logout')
def logout():
    session.clear()
    return render_template('logout.html')
