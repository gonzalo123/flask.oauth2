import logging
import secrets
from urllib.parse import urlencode

import requests
from flask import Blueprint, abort
from flask import request, session, redirect

from settings import OAUTH

logger = logging.getLogger(__name__)

blueprint = Blueprint('oauth', __name__, url_prefix=f'/oauth')


@blueprint.get('/callback')
def callback():
    state = request.args.get('state')
    if 'state' not in session:
        return redirect(f"/")
    if state == session['state']:
        authorization_code = request.args.get('code')
        token_data = {
            'grant_type': OAUTH.get('GRANT_TYPE', 'authorization_code'),
            'code': authorization_code,
            'redirect_uri': OAUTH['REDIRECT_URL'],
            'client_id': OAUTH['CLIENT_ID'],
            'client_secret': OAUTH['CLIENT_SECRET']
        }
        response = requests.post(OAUTH['TOKEN_URL'],
                                 data=token_data,
                                 headers={'Accept': 'application/json'})
        response_data = response.json()
        headers = {
            "Authorization": f"Bearer {response_data.get('access_token')}",
            'Accept': 'application/json'
        }
        user_response = requests.get(OAUTH['USER_URL'],
                                     data=token_data,
                                     headers=headers)
        if user_response.ok:
            user_data = user_response.json()
            session['user'] = dict(
                username=user_data['login'],
                name=user_data['name'],
                email=user_data['email']
            )
            session.pop('state', default=None)
        else:
            abort(401)
        return redirect(f"/")
    else:
        abort(401)


def check_session():
    if not session.get("user"):
        state = secrets.token_urlsafe(32)
        session['state'] = state
        authorize = OAUTH['AUTHORIZE_URL']
        query_string = urlencode({
            'scope': OAUTH.get('SCOPE', 'read write'),
            'prompt': OAUTH.get('PROMPT', 'login'),
            'approval_prompt': OAUTH.get('APPROVAL_PROMPT', 'auto'),
            'state': state,
            'response_type': OAUTH.get('RESPONSE_TYPE', 'code'),
            'redirect_uri': OAUTH['REDIRECT_URL'],
            'client_id': OAUTH['CLIENT_ID']
        })
        return redirect(f"{authorize}?{query_string}")
