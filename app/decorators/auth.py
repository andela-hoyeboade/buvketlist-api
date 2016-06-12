import hashlib
import jwt

from flask import current_app, request
from flask_restful import abort
from functools import wraps

from app.helpers import get_current_user_id
from app.models import User, BucketList, BucketListItem


def valid_username(username):
    """
    Returns True if username exist in the database or False if it doesn't
    """
    return True if User.query.filter_by(username=username).first() else False


def valid_password(username, password):
    """Returns True if username and password exist and False if otherwise
    """
    return True if User.query.filter_by(username=username,
        password=hashlib.sha512(password).hexdigest()).first() else False


def user_is_login(f):
    """
    Authenticates that user is login by verifying the token supplied
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            decoded = jwt.decode(request.headers.get('Token'),
                current_app.config.get('SECRET_KEY'))
        except:
            abort(401, message='Cannot authenticate user. Invalid Token')
        return f(*args, **kwargs)
    return decorated


def bucketlist_exist(f):
    """
    Authenticates that Bucket List exists for the current User
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        current_user = get_current_user_id(request.headers.get('Token'))
        try:
            assert BucketList.query.filter_by(
                id=kwargs.get('id'), created_by=current_user).first()
        except:
            abort(400, message='Bucketlist does not exist')
        return f(*args, **kwargs)
    return decorated


def bucketlist_item_exist(f):
    """
    Authenticates that Item exist for a Bucket List
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            assert BucketListItem.query.filter_by(id=kwargs.get('item_id'),
                bucketlist_id=kwargs.get('id')).first()
        except:
            abort(400, message='Buckelist Item does not exist')
        return f(*args, **kwargs)
    return decorated
