# -*- coding: utf-8 -*-
"""OAuth2 views."""

from __future__ import absolute_import, division, print_function, unicode_literals

from datetime import datetime, timedelta

from flask import Blueprint, current_app, jsonify, render_template, request
from flask_login import current_user, login_required

from ..extensions import csrf_protect, oauth_provider
from ..token.models import Token
from ..user.models import User
from .client.models import Client
from .forms import AuthorizeForm
from .grant.models import Grant

blueprint = Blueprint('oauth', __name__, url_prefix='/oauth', static_folder='../static')


@oauth_provider.clientgetter
def get_client(client_id):
    """Return Client object."""
    return Client.get_by_id(client_id)


@oauth_provider.grantsetter
def set_grant(client_id, code, request_, **_):
    """Create Grant object."""
    expires_at = None
    return Grant(
        client_id=client_id,
        code=code['code'],
        redirect_uri=request_.redirect_uri,
        scopes=request_.scopes,
        user_id=current_user.id,
        expires_at=expires_at
    ).save()


@oauth_provider.grantgetter
def get_grant(client_id, code):
    """Return Grant object."""
    return Grant.query.filter_by(client_id=client_id, code=code).first()


@oauth_provider.tokensetter
def set_token(new_token, request_, **_):
    """Create Token object."""
    expires_at = datetime.utcnow() + timedelta(seconds=new_token.get('expires_in'))
    request_params = dict((key, value) for key, value in request_.uri_query_params)
    if request_.body:
        request_params.update(request_.body)

    if 'grant_type' in request_params and request_params['grant_type'] == 'refresh_token':
        token = Token.query.filter_by(client_id=request_.client.client_id,
                                      user_id=request_.user.id,
                                      refresh_token=request_params['refresh_token']).first()
        token.access_token = new_token['access_token']
        token.refresh_token = new_token['refresh_token']
        token.expires_at = expires_at
    else:  # if request_params['grant_type'] == 'code':
        token = Token(
            access_token=new_token['access_token'],
            refresh_token=new_token['refresh_token'],
            token_type=new_token['token_type'],
            scopes=new_token['scope'],
            expires_at=expires_at,
            client_id=request_.client.client_id,
            user_id=request_.user.id
        )

    return token.save()


@oauth_provider.tokengetter
def get_token(access_token=None, refresh_token=None):
    """Return Token object."""
    if access_token:
        return Token.query.filter_by(access_token=access_token).first()
    if refresh_token:
        return Token.query.filter_by(refresh_token=refresh_token).first()
    return None


@oauth_provider.invalid_response
def require_oauth_invalid(req):
    """OAuth2 errors JSONified."""
    return jsonify(app_version=current_app.config['APP_VERSION'], message=req.error_message), 401


@blueprint.route('/authorize', methods=['GET', 'POST'])
@login_required
@oauth_provider.authorize_handler
def authorize(*_, **kwargs):
    """OAuth2'orize."""
    authorize_form = AuthorizeForm(request.form)
    if request.method == 'GET':
        client_id = kwargs.get('client_id')
        client = Client.query.filter_by(client_id=client_id).first()
        kwargs['client'] = client
        return render_template('oauth/authorize.html', authorize_form=authorize_form, **kwargs)

    confirm = authorize_form['confirm'].data == 'y'
    return confirm


@csrf_protect.exempt
@blueprint.route('/token', methods=['POST', 'GET'])
@oauth_provider.token_handler
def create_access_token():
    """Generate access token."""
    return {'app_version': current_app.config['APP_VERSION']}


@blueprint.route('/verify', methods=['GET'])
@oauth_provider.require_oauth('read', 'write')
def verify():
    """Verify access token is valid and return a bunch of user details."""
    # noinspection PyUnresolvedReferences
    oauth = request.oauth
    assert isinstance(oauth.user, User)

    return jsonify(
        app_version=current_app.config['APP_VERSION'],
        expires_at=oauth.access_token.expires_at.isoformat() + 'Z',
        user={
            'full_name': oauth.user.full_name,
            'email': oauth.user.email,
            'permissions': [{'code': permission.collection.code,
                             'friendly_name': permission.collection.friendly_name,
                             'cataloger': permission.cataloger,
                             'registrant': permission.registrant}
                            for permission in oauth.user.permissions]
        }
    )


@blueprint.route('/revoke', methods=['POST'])
@login_required
@oauth_provider.revoke_handler
def revoke_access_token():
    """Revoke access token."""
    pass


@blueprint.route('/errors', methods=['GET'])
def render_errors():
    """Render OAuth2 errors."""
    return render_template('oauth/errors.html', **request.args)
