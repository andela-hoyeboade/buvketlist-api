import hashlib

from sqlalchemy import Column, String, Integer, ForeignKey
from flask.ext.sqlalchemy import SQLAlchemy
from flask_sqlalchemy import sqlalchemy
db = SQLAlchemy()
class_mapper = sqlalchemy.orm.class_mapper

class Base(db.Model):
    """Base model that other models inherit from.
       Initializes model with <id>, <date_created>
       and <date_modified>.
    """
    __abstract__ = True

    id = db.Column(db.Integer, primary_key=True)
    date_created = db.Column(db.DateTime,  default=db.func.current_timestamp())
    date_modified = db.Column(db.DateTime, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())

    

class User(Base):
    """User model that maps to user table.
    """
    __tablename__ = "user"
    username = db.Column(db.String(120), unique=True)
    password = db.Column(db.String(120))
    bucketlists = db.relationship("BucketList", order_by="BucketList.id")

    def __init__(self, username, password):
        """Initialize with <username> and <password>.
           Hashes password using hashlib
        """
        self.username = username
        self.password = hashlib.sha512(password).hexdigest()

class BucketList(Base):
    """Maps to the bucket_list table.
    """
    __tablename__ = 'bucket_list'
    name = db.Column(db.String(256), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey(User.id))
    user = db.relationship("User")
    bucketlistitems = db.relationship("BucketListItem")

    def __init__(self, name, created_by):
        """Initializes model with <name> and the <creator>.
        """
        self.name = name
        self.created_by = created_by

class BucketListItem(Base):
    """Maps to the bucket_list_item table.
    """
    __tablename__ = "bucket_list_item"
    name = db.Column(db.String(256), nullable=False)
    done = db.Column(db.Boolean, default=False)
    bucketlist_id = db.Column(db.Integer, db.ForeignKey(BucketList.id))

    def __init__(self, bucketlist_id, name, done=False):
        """Initializes model with <bucketlist_id> and <name>.
        <done> is an optional argument
        """
        self.bucketlist_id = bucketlist_id
        self.name = name
        self.done = done
