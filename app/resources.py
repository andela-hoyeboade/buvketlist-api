from models import BucketList, BucketListItem
from decorators import auth
from flask_restful import Resource
from flask import jsonify, request
from helpers import *
from models import db
import json


class LoginUser(Resource):
    def post(self):
        username = request.form.get("username")
        password = request.form.get("password")
        if username and password:
            if auth.valid_username(username):
                if auth.valid_password(username,password):
                    user_data = { 'username': username, 'password': password}
                    secret_key = current_app.config.get('SECRET_KEY')
                    token = jwt.encode(user_data, secret_key)
                    return {"message": "Succesful login. Please use this token for authentication",
                                    "token": token,
                                    #"user_id": get_current_user_id(token)
                                    }, 200
                else:
                    return messages["password_incorrect"], 406
            else:
                return messages["username_not_found"], 406
        else:
            return messages["user_pass_blank"], 406

class RegisterUser(Resource):
    def post(self):
        username = request.form.get("username")
        password = request.form.get("password")
        if username and password:
            if not auth.valid_username(username):
              user = User(username, password)
              return (messages["registered"], 201) if save_model(user) else (messages["not_registered"], 400)
            else:
              return messages["user_exist"], 406
        else:
            return messages["user_pass_blank"], 406


class SingleBucketList(Resource):
    @auth.user_is_login
    @auth.bucketlist_exist
    def get(self, id):
        bucketlist = BucketList.query.filter_by(
            id=id).first()
        bucketlist_output = get_bucketlist(bucketlist)
        return jsonify({"data": bucketlist_output})

    @auth.user_is_login
    @auth.bucketlist_exist
    def put(self, id):
      name = request.form.get("name")
      bucketlist = BucketList.query.filter_by(id=id).first()
      token = request.headers.get('Token')
      current_user = get_current_user_id(token)
      check_bucketlist_name = BucketList.query.filter_by(
          name=name, created_by=current_user).first()
      if not check_bucketlist_name:
          try:
            bucketlist.name = name
            db.session.commit()
            return messages["bucketlist_updated"], 200
          except:
            return messages["bucketlist_not_updated"], 400
      else:
        return messages["bucketlist_exist"], 406

    @auth.user_is_login
    @auth.bucketlist_exist
    def delete(self, id):
        try:          
            bucketlist = BucketList.query.filter_by(id=id).first()
            db.session.delete(bucketlist)
            db.session.commit()
            return messages["bucketlist_deleted"], 204
        except:
            return messages["bucketlist_not_deleted"], 400



class AllBucketLists(Resource):
    @auth.user_is_login
    def get(self):
        token = request.headers.get('Token')
        user_id = get_current_user_id(token)
        all_bucketlist = BucketList.query.filter_by(
        created_by=user_id).all()
        if all_bucketlist:
            bucketlist_output = [get_bucketlist(bucketlist) for bucketlist in all_bucketlist]
            return jsonify({"data": bucketlist_output})   
        else:
            return messages["no_bucketlist"], 200

    @auth.user_is_login
    def post(self):
        name = request.form.get("name")
        token = request.headers.get('Token')
        current_user = get_current_user_id(token)
        bucketlist = BucketList.query.filter_by(
            name=name, created_by=current_user).first()
        if name:
            if bucketlist:
                return messages["bucketlist_exist"], 400
            else:
                bucketlist = BucketList(name, current_user)
                return {"message": "Saved",
                        "name": name,
                        "created_by": current_user
                        } if save_model(bucketlist) \
                        else messages["bucketlist_not_saved"], 400
        else:
            return messages["no_bucketlist_name"], 400

class AllBucketListItems(Resource):
    @auth.user_is_login
    @auth.bucketlist_exist
    def post(self, id):
        name = request.form.get("name")
        bucketlist_item = BucketListItem.query.filter_by(
            name=name, bucketlist_id=id).first()
        if name:
            if bucketlist_item:
                return messages["bucketlist_item_exist"]
            else:
                bucketlist_item = BucketListItem(name=name, bucketlist_id=id)
                return {"message": "Saved",
                        "name": name,
                        "bucketlist_id": id
                                } if save_model(bucketlist_item) \
                    else messages["bucketlist_item_not_saved"], 400
        else:
            return messages["no_bucketlist_item_name"], 400

    @auth.user_is_login
    @auth.bucketlist_exist
    def get(self, id):
        all_bucketlist_item = BucketListItem.query.filter_by(
            bucketlist_id=id).all()
        if all_bucketlist_item:
            bucketlist_item_output = [get_single_bucketlist_item(bucketlist_item) for bucketlist_item in all_bucketlist_item]
            return jsonify({"items": bucketlist_item_output})    
        else:
          return messages["no_bucketlist_item"], 200

class SingleBucketListItem(Resource):
    @auth.user_is_login
    @auth.bucketlist_exist
    @auth.bucketlist_item_exist
    def get(self, id, item_id):
        bucketlist_item = BucketListItem.query.filter_by(id=item_id,bucketlist_id=id).first()
        if bucketlist_item:
            return jsonify ({"items": get_single_bucketlist_item(bucketlist_item)})
        else:
            return messages["no_bucketlist_item"],200

    @auth.user_is_login
    @auth.bucketlist_exist
    @auth.bucketlist_item_exist
    def put(self, id, item_id):
        bucketlist_item = BucketListItem.query.filter_by(id=item_id,bucketlist_id=id).first()
        name = request.form.get("name")
        done = request.form.get("done")
        done = True if str(done).lower() == "true" else False
        check_bucketlist_item_details = BucketListItem.query.filter_by(
          name=name, id=item_id, bucketlist_id=id, done=done).first()
        if not check_bucketlist_item_details:
            try:
                bucketlist_item.name = name
                bucketlist_item.done = done
                db.session.commit()
                return messages["bucketlist_item_updated"], 200
            except:
                return messages["bucketlist_item_not_updated"], 400
        else:
            return messages["bucketlist_item_exist"], 400

    @auth.user_is_login
    @auth.bucketlist_exist
    @auth.bucketlist_item_exist
    def delete(self, id, item_id):
        bucketlist_item = BucketListItem.query.filter_by(id=item_id,bucketlist_id=id).first()
        try:
            db.session.delete(bucketlist_item)
            db.session.commit()
            return messages["bucketlist_item_deleted"], 204
        except:
            return messages["bucketlist_item_not_deleted"], 400

