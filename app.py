import os
from flask import Flask
from flask_cors import CORS, cross_origin
from flask_jwt_extended import JWTManager, jwt_required
from flask_restful import Resource, Api
from Auth import Authentication
from login.User import get_all_users

app = Flask(__name__)

# FLask configuration
JWT_SECRET_KEY = 't1NP63m4wnBg6nyHYKfmc2TpCOGI4nss'
app.config['JWT_SECRET_KEY'] = JWT_SECRET_KEY
app.secret_key = 't1NP63m4wnBg6nyHYKfmc2Ulvdtggbsd'
app.config['CORS_HEADERS'] = 'Content-Type'
api = Api(app)
path = os.path.dirname(__file__)
CORS(app, resources={r"/*": {"origins": "*"}})
jwt = JWTManager(app)


authentication = Authentication()


# test
class HelloWorld(Resource):
    @jwt_required
    def get(self):
        return {'hello': 'world'}


class Login(Resource):
    @cross_origin()
    def post(self):
        return authentication.login()


class Signup(Resource):
    def post(self):
        print('jesuis ici')
        return authentication.signup()


class SocketIO(Resource):
    @jwt_required
    def get(self):
        return


# get all users with attributes : uid, cn, sn, public key
class AllUseres(Resource):
    # @jwt_required
    def get(self):
        return get_all_users()


# paths
api.add_resource(HelloWorld, '/')
api.add_resource(Login, '/login')
api.add_resource(Signup, '/signup')
api.add_resource(SocketIO, '/socketIO')
api.add_resource(AllUseres, '/getAllUsers')

if __name__ == '__main__':
    app.run(debug=True)
