from typing import Union
import logging
import os
import sys
import requests

from base64 import b64decode
from cryptography.hazmat.primitives import serialization

from flask import Response, session,  make_response, request, url_for

from mlflow.server.auth import store as auth_store
from werkzeug.datastructures import Authorization
import jwt

OIDC_ISSUER_URL = os.environ['OIDC_ISSUER_URL']
OIDC_CLIENT_ID = os.environ['OIDC_CLIENT_ID']
OIDC_USERNAME_CLAIM = os.environ.get('OIDC_USERNAME_CLAIM','email')
OIDC_USER_GROUPS = os.environ['OIDC_USER_GROUPS'].split(',') if 'OIDC_USER_GROUPS' in os.environ else ["mlfow-users", "mlflow-admins"]
OIDC_ADMIN_GROUP = "mlflow-admins"
BEARER_PREFIX = "Bearer "
_logger = logging.getLogger(__name__)

_logger.addHandler(logging.StreamHandler(sys.stdout))
_issuer_req = requests.get(OIDC_ISSUER_URL)
_public_key = serialization.load_der_public_key(b64decode(_issuer_req.json()["public_key"].encode()))
_redirect_uri = url_for('serve',_external=True)
def parse_token(token: dict = None) -> dict:
    userinfo = dict()
    userinfo["username"] = token[OIDC_USERNAME_CLAIM]
    groups = [g for g in token.get('groups') if g in OIDC_USER_GROUPS]
    userinfo["is_admin"] = False
    for group in groups:
        if group.lower() == OIDC_ADMIN_GROUP:
            userinfo["is_admin"] = True
            break
    return userinfo

def update_user(user_info: dict = None):
    if auth_store.has_user(user_info["username"]) is False:
        auth_store.create_user(user_info["username"],user_info["username"], user_info["is_admin"])
    else:
        auth_store.update_user(user_info["username"],user_info["username"],user_info["is_admin"])

def authenticate_request() -> Union[Authorization, Response]:
    if session.get("user_info", None) is not None:
        return Authorization(auth_type="jwt", data=session["user_info"])
    _logger.info(f"Got headers {dict(request.headers)}")
    resp = make_response()
    resp.status_code = 401
    resp.set_data(
        "You are not authenticated. Please provide a valid JWT Bearer Token"
    )
    resp.headers["WWW-Authenticate"] = 'Bearer error="invalid_token"'

    token = request.headers.get('Authorization', None)
    user_info = dict()
    if token is not None:
        if token.startswith(BEARER_PREFIX) or token.startswith(BEARER_PREFIX.lower()):
            token = token[len(BEARER_PREFIX):]
    try:
        jwt_token = jwt.decode(token,_public_key, algorithms=['HS256','RS256'], audience=OIDC_CLIENT_ID)
        if not jwt_token:
            _logger.warning("No JWT Returned")
            return resp
        user_info = parse_token(jwt_token)
        update_user(user_info)
        session["user_info"] = user_info
        return Authorization(auth_type="jwt",data=user_info)

    except jwt.exceptions.InvalidTokenError:
        return resp
