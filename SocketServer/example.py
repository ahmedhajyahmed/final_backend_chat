from flask import Flask, render_template
from flask_socketio import SocketIO, emit

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app, cors_allowed_origins='*')

users = []


@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('getUsers',namespace="/test")
def getUsers():
    emit('sendUsers',users)

@socketio.on('send_message', namespace='/test')
def send(message):
    print('event send message')
    print(message)
    emit('get_message', message, broadcast=True)



@socketio.on('connect', namespace='/test')
def test_connect():
    print("a client connected")


def check_new_user(new_user):
    for user in users:
        if user['id'] == new_user['id']:
            print("user already exists ")
            return False
    print("user doesnt exist => adding to users")
    users.append(new_user)
    return True


@socketio.on('user_infos', namespace='/test')
def broadcast_user_infos(user):
    print("a new client gave his infos")
    print(user)
    check_new_user(user)
    emit('USER_CONNECTED', users, broadcast=True)



@socketio.on('disconnect', namespace='/test')
def test_disconnect():
    print('Client disconnected')


if __name__ == '__main__':



    socketio.run(app,port=5001)
