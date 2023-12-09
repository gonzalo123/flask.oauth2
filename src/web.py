from flask import Flask
from flask_session import Session

from lib.oauth import blueprint as oauth
from modules.home.app import blueprint as home
from settings import SECRET, SESSION


app = Flask(__name__)
app.secret_key = SECRET
app.config.update(SESSION)
Session(app)

app.register_blueprint(oauth)
app.register_blueprint(home, url_prefix=f'/')
