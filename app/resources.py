import json

from flask import jsonify, request
from flask.ext.restful import Resource

from .decorators import auth
from .helpers import *
from .models import db, User, BucketList, BucketListItem


class LoginUser(Resource):
    '''
    Manage responses to user requests.
    URL:
        /api/v1/auth/login/
    Methods:
        POST
    '''

    def post(self):
        '''
        Authenticates a user.
        Returns:
            json: message indicating Authentication Token or an error message
        '''
        username = request.form.get('username')
        password = request.form.get('password')
        if username and password:
            if auth.valid_username(username):
                if auth.valid_password(username, password):
                    user_data = {'username': username, 'password': password}
                    secret_key = current_app.config.get('SECRET_KEY')
                    token = jwt.encode(user_data, secret_key)
                    return {'token': token}, 200
                else:
                    return messages['password_incorrect'], 406
            else:
                return messages['username_not_found'], 406
        else:
            return messages['user_pass_blank'], 406


class RegisterUser(Resource):
    '''
    Manage responses to user requests.
    URL:
        /api/v1/auth/register/
    Methods:
        POST
    '''

    def post(self):
        '''
        Register a user.
        Returns:
            json: message indicating the username has been registered or not
        '''
        username = request.form.get('username')
        password = request.form.get('password')
        if username and password:
            if not auth.valid_username(username):
                user = User(username, password)
                return (messages['registered'], 201) \
                    if save_model(user) else (messages['not_registered'], 400)
            else:
                return messages['user_exist'], 406
        else:
            return messages['user_pass_blank'], 406


class SingleBucketList(Resource):
    '''
    Manage responses to single bucketlists requests.
    URL:
        /api/v1/bucketlists/<id>/
    Methods:
        GET, PUT, DELETE
    '''

    @auth.user_is_login
    @auth.bucketlist_exist
    def get(self, id):
        '''
        Retrieve the bucketlist using an id.
        Args:
            id: The id of the bucketlist to be retrieved (required)
        Returns:
            json: The bucketlist with its content
        '''
        bucketlist = BucketList.query.filter_by(
            id=id).first()
        bucketlist_output = get_bucketlist(bucketlist)
        return jsonify({'data': bucketlist_output})

    @auth.user_is_login
    @auth.bucketlist_exist
    def put(self, id):
        '''
        Updates the bucketlist using an id.
        Args:
            id: The id of the bucketlist to be updated (required)
        Returns:
            json: message indicating Bucketlist has been updated
        '''
        name = request.form.get('name')
        token = request.headers.get('Token')
        current_user = get_current_user_id(token)
        check_bucketlist_name = BucketList.query.filter_by(
            name=name, created_by=current_user).first()
        if not check_bucketlist_name:
            bucketlist = BucketList.query.filter_by(id=id).first()
            bucketlist.name = name
            return (messages['bucketlist_updated'], 200) if update_database() \
                else (messages['bucketlist_not_updated'], 400)
        else:
            return messages['bucketlist_exist'], 406

    @auth.user_is_login
    @auth.bucketlist_exist
    def delete(self, id):
        '''
        Delete the bucketlist with the specified id.
        Args:
            id: The id of the bucketlist to be deleted (required)
        Returns:
            json: message indicating Bucketlist has been deleted
        '''
        bucketlist = BucketList.query.filter_by(id=id).first()
        return (messages['bucketlist_deleted'], 204) \
            if delete_model(bucketlist) \
            else (messages['bucketlist_not_deleted'], 400)


class AllBucketLists(Resource):
    '''
    Manage responses to bucketlists requests by a user.
    URL:
        /api/v1/bucketlists/
    Methods:
        GET, POST
    '''

    @auth.user_is_login
    def get(self):
        '''
        Retrieve all bucketlists for a particular user.
        Args:
            q: Searches bucketlists by name (optional)
            limit: Limit number of retrieved results per page (optional)
            page: Number of pages to contain retrieved results (optional)
        Returns:
            json: All bucketlists with their content
        '''
        limit = int(request.args.get('limit', 20))
        limit = 100 if int(limit) > 100 else limit
        limit = int(limit)
        search_by = request.args.get('q', '')
        page = int(request.args.get('page', 1))
        token = request.headers.get('Token')
        user_id = get_current_user_id(token)
        start_at = (page * limit) - limit;
        end_at = (page * limit);
        all_bucketlist = BucketList.query.filter_by(
            created_by=user_id).filter(BucketList.name.like('%{}%'.format(search_by))).all()[start_at:end_at]
        #all_bucketlist = all_bucketlist.paginate(page=page, per_page=limit, error_out=False)
        if all_bucketlist:
            bucketlist_output = [get_bucketlist(
                bucketlist) for bucketlist in all_bucketlist]
            result = jsonify({'data': bucketlist_output,})
        else:
            result = messages['no_bucketlist'], 200
        return result


    @auth.user_is_login
    def post(self):
        '''
        Create a new bucketlist for a particular user.
        Args:
            Params:
                name: Name for the bucketlist (required)
            Header:
                Token: Authentication Token for the User (required)
        Returns:
            json: message indicating bucketlist has been created or not
        '''
        name = request.form.get('name')
        token = request.headers.get('Token')
        current_user = get_current_user_id(token)
        bucketlist = BucketList.query.filter_by(
            name=name, created_by=current_user).first()
        if name:
            if bucketlist:
                return messages['bucketlist_exist'], 400
            else:
                bucketlist = BucketList(name, current_user)
                return {'message': 'Saved',
                        'name': name,
                        'created_by': current_user
                        } if save_model(bucketlist) \
                    else messages['bucketlist_not_saved'], 400
        else:
            return messages['no_bucketlist_name'], 400


class AllBucketListItems(Resource):
    '''
    Manage responses to bucketlistitem requests by a user.
    URL:
        /api/v1/bucketlists/<id>/items/
    Methods:
        GET, POST
    '''

    @auth.user_is_login
    @auth.bucketlist_exist
    def post(self, id):
        '''
        Create a new bucketlist item for a particular bucketlist.
        Args:
            id: The id of the bucketlist which an item is being added
        Parameters:
            name: Name for the bucketlist item (required)
        Header:
            Token: Authentication Token for the User (required)
        Returns:
            json: message indicating bucketlist item has been created or not
        '''
        name = request.form.get('name')
        bucketlist_item = BucketListItem.query.filter_by(
            name=name, bucketlist_id=id).first()
        if name:
            if bucketlist_item:
                return messages['bucketlist_item_exist'], 400
            else:
                bucketlist_item = BucketListItem(name=name, bucketlist_id=id)
                return {'message': 'Saved',
                        'name': name,
                        'bucketlist_id': id,
                        } if save_model(bucketlist_item) \
                    else messages['bucketlist_item_not_saved'], 400
        else:
            return messages['no_bucketlist_item_name'], 400

    @auth.user_is_login
    @auth.bucketlist_exist
    def get(self, id):
        '''
        Get all items for a particular bucketlist.
        Args:
            id: The id of the bucketlist whose items is to be retrieved (required)
        Header:
            Token: Authentication Token for the User (required)
        Returns:
            json: All items in the specified bucketlist and their content
        '''
        limit = int(request.args.get('limit', 20))
        limit = 100 if int(limit) > 100 else limit
        limit = int(limit)
        search_by = request.args.get('q', '')
        page = int(request.args.get('page', 1))
        start_at = (page * limit) - limit;
        end_at = (page * limit);
        all_bucketlist_item = BucketListItem.query.filter_by(
            bucketlist_id=id).filter(BucketListItem.name.like
            ('%{}%'.format(search_by))).all()[start_at:end_at]

        if all_bucketlist_item:
            bucketlist_item_output = [get_single_bucketlist_item(
                bucketlist_item) for bucketlist_item in all_bucketlist_item]
            return jsonify({'items': bucketlist_item_output})
        else:
            return messages['no_bucketlist_item'], 200


class SingleBucketListItem(Resource):
    '''
    Manage responses to single bucketlistitem requests by a user.
    URL:
        /api/v1/bucketlists/<id>/items/<item_id>
    Methods:
        GET, PUT, DELETE
    '''

    @auth.user_is_login
    @auth.bucketlist_exist
    @auth.bucketlist_item_exist
    def get(self, id, item_id):
        '''
        Get a single bucketlistitem given the item_id and the bucketlist_id.
        URL:
            /api/v1/bucketlists/<id>/items/<item_id>
        Args:
            item_id: The id of the bucketlist item to be retrieved (required)
            id: The id of the bucketlist whose item is being retrieved
        Header:
            Token: Authentication Token for the User (required)
        Returns:
            json: bucketlist item and its content
        '''
        bucketlist_item = BucketListItem.query.filter_by(
            id=item_id, bucketlist_id=id).first()
        if bucketlist_item:
            return jsonify({'items': get_single_bucketlist_item(bucketlist_item)})
        else:
            return messages['no_bucketlist_item'], 200

    @auth.user_is_login
    @auth.bucketlist_exist
    @auth.bucketlist_item_exist
    def put(self, id, item_id):
        '''
        Updates a single bucketlistitem given the item_id and the bucketlist_id.
        URL:
            /api/v1/bucketlists/<id>/items/<item_id>
        Args:
            item_id: The id of the bucketlist item to be updated (required)
            id: The id of the bucketlist whose item is being updated (required)
        Parameters:
            name: The name for the bucketlist item (optional)
            done: The status of the bucketlist item (optional)
        Header:
            Token: Authentication Token for the User (required)
        Returns:
            json: message indicating bucketlist_item has been updated or not
        '''
        bucketlist_item = BucketListItem.query.filter_by(
            id=item_id, bucketlist_id=id).first()
        name = request.form.get('name')
        done = request.form.get('done')
        done = True if str(done).lower() == 'true' else False
        check_bucketlist_item_details = BucketListItem.query.filter_by(
            name=name, id=item_id, bucketlist_id=id, done=done).first()
        if not check_bucketlist_item_details:
            bucketlist_item.name = name
            bucketlist_item.done = done
            return (messages['bucketlist_item_updated'], 200) if update_database() \
                else (messages['bucketlist_item_not_updated'], 400)
        else:
            return messages['bucketlist_item_exist'], 400

    @auth.user_is_login
    @auth.bucketlist_exist
    @auth.bucketlist_item_exist
    def delete(self, id, item_id):
        '''
        Deletes a single bucketlistitem given the item_id and the bucketlist_id.
        URL:
            /api/v1/bucketlists/<id>/items/<item_id>
        Args:
            item_id: The id of the bucketlist item to be deleted (required)
            id: The id of the bucketlist whose item is being deleted (required)
        Header:
            Token: Authentication Token for the User (required)
        Returns:
            json: message indicating bucketlist_item has been deleted or not
        '''
        bucketlist_item = BucketListItem.query.filter_by(
            id=item_id, bucketlist_id=id).first()
        return (messages['bucketlist_item_deleted'], 204) \
            if delete_model(bucketlist_item) else \
            (messages['bucketlist_item_not_deleted'], 400)
