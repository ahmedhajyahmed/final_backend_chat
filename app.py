import json
import os

from flask import Flask, request, jsonify
import sys
from flask import Flask
from flask_restful import Resource, Api, reqparse, abort
from flask.views import MethodView
from flask_cors import CORS

from Auth import Authentication

app = Flask(__name__)
api = Api(app)
path = os.path.dirname(__file__)
CORS(app)

authentication = Authentication()


class HelloWorld(Resource):
    def get(self):
        return {'hello': 'world'}


class Login(Resource):
    def post(self):
        return authentication.login()


class Signup(Resource):
    def post(self):

        return authentication.signup()


api.add_resource(HelloWorld, '/')
api.add_resource(Login, '/login')
api.add_resource(Signup, '/signup')

if __name__ == '__main__':
    app.run(debug=True)
