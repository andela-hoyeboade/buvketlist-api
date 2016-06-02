from app.models import User, BucketList, BucketListItem, db
from flask_restful import reqparse, abort
from functools import wraps
from app.helpers import *
from flask import request
from flask import jsonify, current_app
from datetime import datetime, timedelta
from flask.ext.sqlalchemy import sqlalchemy as S
from flask.ext.api.exceptions import AuthenticationFailed, PermissionDenied, \
    NotFound
import jwt
import hashlib


def valid_username(username):
    user = User.query.filter_by(username=username).first()
    if user:
        return True
    else:
        return False

def valid_password(username,password):
    password = hashlib.sha512(password).hexdigest()
    user = User.query.filter_by(username=username, password=password).first()
    if user:
        return True
    else:
        return False

def user_is_login(f):
    """
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            token = request.headers.get('Token')
            secret_key = current_app.config.get('SECRET_KEY')
            decoded = jwt.decode(token, secret_key)
        except:
            abort(401, message="Cannot authenticate user")
        return f(*args, **kwargs)
    return decorated


def bucketlist_exist(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        bucketlist_id = kwargs.get('id')
        token = request.headers.get('Token')
        current_user = get_current_user_id(token)
        bucketlist = BucketList.query.filter_by(id=bucketlist_id, created_by=current_user).first()
        try:
            assert bucketlist
        except:
            abort(400, message="Bucketlist does not exist")
        return f(*args, **kwargs)
    return decorated

def bucketlist_item_exist(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        bucketlist_id = kwargs.get('id')
        item_id = kwargs.get('item_id')
        bucketlist_item = BucketListItem.query.filter_by(id=item_id,bucketlist_id=bucketlist_id).first()
        try:
            assert bucketlist_item
        except:
            abort(400, message="Buckelist Item does not exist")
        return f(*args, **kwargs)
    return decorated