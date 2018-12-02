from flask import Flask, render_template, request, session
import uuid
from base64 import b64encode
from requests import Request
import requests

app = Flask(__name__)

app.secret_key = b'rehgejgbfkhjb'  # FIXME(vtepliuk): Remove in next version.


@app.route('/')
def index():
    req = Request(method='GET',
                  url='http://127.0.0.1:5000/oauth/authorize',
                  params={
                      'client_id': '7368b9a635413b2f153fa032b3de658c',
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
    client_id = '7368b9a635413b2f153fa032b3de658c'
    client_secret = ('458c9658bc138ebd752cfc7076bae60e4e27693d306901baf76be91627feff9390edf5c2542a1'
                     '6d07bc496207058ac4b46f2d0ac7dca76be620d4da4a0c8f6fb147607ec7049d04c4409e84940'
                     'e850ed6eaf4713b4c4c1ee6b20b60818b3539df9c57f631ba00aa5995edb1f943085258424edb'
                     '44343ec32d5fbbb897d4b65da')  # FIXME(vtepliuk): Remove in next version.
    token_endpoint = 'http://127.0.0.1:5000/oauth/token'
    client_redirect_uri = 'http://127.0.0.1:5001/login'
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
    verify_response = requests.get('http://127.0.0.1:5000/oauth/verify',
                                   headers={'Authorization': str('Bearer ' + access_token)})
    full_name = verify_response.json()['user']['full_name']
    email = verify_response.json()['user']['email']
    return render_template('profile.html', full_name=full_name, email=email)
