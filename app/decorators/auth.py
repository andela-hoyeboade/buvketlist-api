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
            token = request.headers.get('Token')
            secret_key = current_app.config.get('SECRET_KEY')
            decoded = jwt.decode(token, secret_key)
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
        bucketlist_id = kwargs.get('id')
        token = request.headers.get('Token')
        current_user = get_current_user_id(token)
        bucketlist = BucketList.query.filter_by(
            id=bucketlist_id, created_by=current_user).first()
        try:
            assert bucketlist
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
        bucketlist_id = kwargs.get('id')
        item_id = kwargs.get('item_id')
        bucketlist_item = BucketListItem.query.filter_by(
            id=item_id, bucketlist_id=bucketlist_id).first()
        try:
            assert bucketlist_item
        except:
            abort(400, message='Buckelist Item does not exist')
        return f(*args, **kwargs)
    return decorated
