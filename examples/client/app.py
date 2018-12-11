from flask import Flask, render_template, request, session
import uuid
from base64 import b64encode
from requests import Request
import requests
from os import environ

OAUTH2_BASE_URL = environ.get('OAUTH2_BASE_URL')
if not OAUTH2_BASE_URL:
    raise AssertionError('OAUTH2_BASE_URL missing!')
OAUTH2_CLIENT_ID = environ.get('OAUTH2_CLIENT_ID')
if not OAUTH2_CLIENT_ID:
    raise AssertionError('OAUTH2_CLIENT_ID missing!')
OAUTH2_CLIENT_SECRET = environ.get('OAUTH2_CLIENT_SECRET')
if not OAUTH2_CLIENT_SECRET:
    raise AssertionError('OAUTH2_CLIENT_SECRET missing!')
APP_SECRET_KEY = environ.get('APP_SECRET_KEY')
if not APP_SECRET_KEY:
    raise AssertionError('APP_SECRET_KEY missing!')

app = Flask(__name__)

app.secret_key = APP_SECRET_KEY


@app.route('/')
def index():
    req = Request(method='GET',
                  url=OAUTH2_BASE_URL + 'oauth/authorize',
                  params={
                      'client_id': OAUTH2_CLIENT_ID,
                      'scope': 'read write',
                      'state': uuid.uuid4().get_hex(),
                      'response_type': 'code',
                      'approval_prompt': 'auto'
                  }).prepare()

    return render_template('main.html', authorize_url=req.url)


@app.route('/login')
def login():
    code = request.args.get('code')
    state = request.args.get('state')
    client_id = OAUTH2_CLIENT_ID
    client_secret = OAUTH2_CLIENT_SECRET
    token_endpoint = OAUTH2_BASE_URL + 'oauth/token'
    client_redirect_uri = 'http://oauth2-client.mkdevops.se/login'
    credentials = '%s:%s' % (client_id, client_secret)
    auth_code = str(b64encode(credentials.encode()).decode())
    headers = {'Authorization': str('Basic ' + auth_code)}
    params = {'grant_type': 'authorization_code', 'code': code, 'redirect_uri': client_redirect_uri}
    token_response = requests.get(token_endpoint, params=params, headers=headers)
    access_token = token_response.json()['access_token']
    refresh_token = token_response.json()['refresh_token']
    session['access_token'] = access_token
    session['refresh_token'] = refresh_token
    return render_template('login.html', code=code, state=state, access_token=access_token,
                           refresh_token=refresh_token)


@app.route('/profile')
def profile():
    access_token = session['access_token']
    verify_response = requests.get(OAUTH2_BASE_URL + 'oauth/verify',
                                   headers={'Authorization': str('Bearer ' + access_token)})
    full_name = verify_response.json()['user']['full_name']
    email = verify_response.json()['user']['email']
    return render_template('profile.html', full_name=full_name, email=email)
