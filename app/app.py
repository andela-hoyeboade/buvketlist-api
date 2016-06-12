from flask import Flask
from flask_restful import Api

from .helpers import messages
from .resources import *


app = Flask(__name__)
app.config.from_object('config.DevelopmentConfig')
app.config['JSON_SORT_KEYS'] = False

api = Api(app=app, prefix='/api/v1/')
api.add_resource(LoginUser, 'auth/login')
api.add_resource(RegisterUser, 'auth/register')
api.add_resource(AllBucketLists, 'bucketlists/')
api.add_resource(SingleBucketList, 'bucketlists/<int:id>')
api.add_resource(AllBucketListItems, 'bucketlists/<int:id>/items/')
api.add_resource(SingleBucketListItem,
    'bucketlists/<int:id>/items/<int:item_id>')

@app.route('/', methods = ['GET','POST'])
def home_page():
    return 'Hello World! Welcome to BucketList Manager. \
        Please login/register to access our services'

@app.errorhandler(404)
def handle_error(message):
    return messages['resource_not_found'], 404
