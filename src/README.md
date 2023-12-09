## Flask and OAuth 2


I typically use Flask for APIs and Django for web applications that utilize sessions and OAuth authentication. However, do I truly need Django for these functionalities? The answer is no. While Django provides pre-built components, similar capabilities are also accessible in Flask, and implementing them is quite straightforward. Additionally, I am a strong advocate of microframeworks. Today, we'll demonstrate how to employ OAuth2 authentication using Flask. Let's begin.

OAuth2 encompasses various flows, but today, we'll focus on the most common one for web applications. The concept involves checking for a valid session. If one exists, great, but if not, the application will generate a session with a state (a randomly generated string) and then redirect to the OAuth2 server login page. Subsequently, the user will perform the login on the login server. Following that, the OAuth2 server will redirect to a validated callback URL with an authorization code (while also returning the provided state). The callback URL will then verify whether the state provided by the OAuth2 server matches the one in the session. Next, the callback route on your server, utilizing the authorization code, will obtain an access token (via a POST request to the OAuth2 server). With this access token, you can retrieve user information from the OAuth2 server and establish a valid session.

First we create a Flask application with sessions

```python
from flask import Flask
from flask_session import Session

from settings import SECRET, SESSION


app = Flask(__name__)
app.secret_key = SECRET
app.config.update(SESSION)
Session(app)
```

Session configuration:
```python
SESSION = dict(
    SESSION_PERMANENT=False,
    SESSION_TYPE="filesystem",
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_DOMAIN=False,
)
```

I like to use blueprints to manage the Flask, so let's add our application:

```python
from modules.home.app import blueprint as home

...
app.register_blueprint(home, url_prefix=f'/')
```

I set up the blueprint in a __init__.py file

```python
from pathlib import Path

from flask import Blueprint

from lib.oauth import check_session

base = Path(__file__).resolve().parent
blueprint = Blueprint(
    'front_home', __name__,
    template_folder=base.joinpath('templates')
)


@blueprint.before_request
def auth():
    return check_session()
```

You can see that we're using a before_request middleware to check the session in every route of the blueprint.

```python
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
```

And the routes of the blueprint:

```python
from flask import render_template, session

from modules.home import blueprint


@blueprint.get(f"/")
def home():
    username = session['user']['username']
    return render_template('index.html',
                           username=username)
```

To do the login we need also to code our callback route. We will add a blueprint for that.

```python
from lib.oauth import blueprint as oauth

...
app.register_blueprint(oauth)
```

That's the OAuth2 callback:

```python
import logging

import requests
from flask import Blueprint, abort
from flask import request, session, redirect

from settings import OAUTH

logger = logging.getLogger(__name__)

blueprint = Blueprint('oauth', __name__, url_prefix=f'/oauth')


@blueprint.get('/callback')
def callback():
    # Obtain the state from the request
    state = request.args.get('state')
    if 'state' not in session:
        return redirect(f"/")
    # Check if provided state match wht the session saved one
    if state == session['state']:
        # Obtain the authorization code from the request
        authorization_code = request.args.get('code')
        token_data = {
            'grant_type': OAUTH.get('GRANT_TYPE', 'authorization_code'),
            'code': authorization_code,
            'redirect_uri': OAUTH['REDIRECT_URL'],
            'client_id': OAUTH['CLIENT_ID'],
            'client_secret': OAUTH['CLIENT_SECRET']
        }
        # POST to OAuth2 server to obtain the access_token
        response = requests.post(OAUTH['TOKEN_URL'],
                                 data=token_data,
                                 headers={'Accept': 'application/json'})
        response_data = response.json()
        headers = {
            "Authorization": f"Bearer {response_data.get('access_token')}",
            'Accept': 'application/json'
        }
        # With the access_token you can obtain the user information
        user_response = requests.get(OAUTH['USER_URL'],
                                     data=token_data,
                                     headers=headers)
        if user_response.ok:
            # Now you are able to create the session 
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
```

Mainly that's all. In this example we're using Github's OAuth2 server. You can use different ones, and also with 
your own OAuth2 server. Maybe, depending on the server, they way to obtain the user_data, can be different, and you 
should adapt it to your needs.

In my example I'm saving my OAuth2 credentials in a .env file. With this technique I can use different 
configurations depending on my environment (production, staging, ...)

```bash
CLIENT_ID=my_client_id
CLIENT_SECRET=my_client_secret
TOKEN_URL=https://github.com/login/oauth/access_token
AUTHORIZE_URL=https://github.com/login/oauth/authorize
USER_URL=https://api.github.com/user
REDIRECT_URL=http://localhost:5000/oauth/callback
```

And I load this conf in my settings.py

```python
import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
ENVIRONMENT = os.getenv('ENVIRONMENT', 'local')

load_dotenv(dotenv_path=Path(BASE_DIR).resolve().joinpath('env', ENVIRONMENT, '.env'))

OAUTH = dict(
    CLIENT_ID=os.getenv('CLIENT_ID'),
    CLIENT_SECRET=os.getenv('CLIENT_SECRET'),
    TOKEN_URL=os.getenv('TOKEN_URL'),
    AUTHORIZE_URL=os.getenv('AUTHORIZE_URL'),
    USER_URL=os.getenv('USER_URL'),
    REDIRECT_URL=os.getenv('REDIRECT_URL'),
)
```

