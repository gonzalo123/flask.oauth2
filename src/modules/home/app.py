from flask import render_template, session

from modules.home import blueprint


@blueprint.get(f"/")
def home():
    username = session['user']['username']
    return render_template('index.html',
                           username=username)
