from flask import request
from flask.ext.restful import Resource

from .decorators import auth
from .helpers import *
from .models import User, BucketList, BucketListItem


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
                return (get_user(user), 201) \
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
        return {'data': bucketlist_output}, 200

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
            return (get_bucketlist(bucketlist), 200) if update_database() \
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
            limit: Limit number of retrieved bucketlists per page (optional)
            page: Number of pages to contain retrieved bucketlists (optional)
        Returns:
            json: All bucketlists with their content
        '''
        params = request.args.to_dict()
        limit = int(params.get('limit', 20))
        limit = 100 if int(limit) > 100 else limit
        search_by = params.get('q', '')
        page = int(params.get('page', 1))
        token = request.headers.get('Token')
        user_id = get_current_user_id(token)
        search_results = BucketList.query.filter_by(
            created_by=user_id).filter(BucketList.name.like('%{}%'.format
                                                            (search_by)))
        all_bucketlist = search_results.paginate(
            page=page, per_page=limit, error_out=False)
        next_page = str(request.url_root) + 'api/v1/bucketlists?' + \
            'limit=' + str(limit) + '&page=' + str(page + 1) \
            if all_bucketlist.has_next else None
        previous_page = request.url_root + 'api/v1/bucketlists?' + \
            'limit=' + str(limit) + '&page=' + str(page - 1) \
            if all_bucketlist.has_prev else None
        bucketlist_output = [get_bucketlist(
            bucketlist) for bucketlist in all_bucketlist.items]

        return {'data': bucketlist_output,
                'pages': all_bucketlist.pages,
                'previous_page': previous_page,
                'next_page': next_page}, 200

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
                return messages['bucketlist_exist'], 406
            else:
                bucketlist = BucketList(name, current_user)
                return (get_bucketlist(bucketlist), 201) if \
                    save_model(bucketlist) \
                    else (messages['bucketlist_not_saved'], 400)
        else:
            return messages['no_bucketlist_name'], 406


class AllBucketListItems(Resource):
    '''
    Manage responses to bucketlistitem requests by a user.
    URL:
        /api/v1/bucketlists/<id>/items/
    Methods:
        POST
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
                return messages['bucketlist_item_exist'], 406
            else:
                bucketlist_item = BucketListItem(name=name, bucketlist_id=id)
                return (get_single_bucketlist_item(bucketlist_item), 201) \
                    if save_model(bucketlist_item) \
                    else (messages['bucketlist_item_not_saved'], 400)
        else:
            return messages['no_bucketlist_item_name'], 406


class SingleBucketListItem(Resource):
    '''
    Manage responses to single bucketlistitem requests by a user.
    URL:
        /api/v1/bucketlists/<id>/items/<item_id>
    Methods:
        PUT, DELETE
    '''
    @auth.user_is_login
    @auth.bucketlist_exist
    @auth.bucketlist_item_exist
    def put(self, id, item_id):
        '''
        Updates a single bucketlistitem given the item_id
        and the bucketlist_id
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
            return (get_single_bucketlist_item(bucketlist_item), 200) \
                if update_database() \
                else (messages['bucketlist_item_not_updated'], 400)
        else:
            return messages['bucketlist_item_exist'], 406

    @auth.user_is_login
    @auth.bucketlist_exist
    @auth.bucketlist_item_exist
    def delete(self, id, item_id):
        '''
        Deletes a single bucketlistitem given the item_id
        and the bucketlist_id.
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
