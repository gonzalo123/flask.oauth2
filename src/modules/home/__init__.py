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
