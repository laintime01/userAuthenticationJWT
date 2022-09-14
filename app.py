from flask import Flask, request, jsonify, make_response, render_template, session
import jwt
from datetime import datetime, timedelta
from functools import wraps
import uuid

# generate a good secret key
# print(uuid.uuid4().hex)

app = Flask(__name__)
app.config['SECRET_KEY'] = "d285d746b8794bde9f04d6bb8b231211"


def token_required(func):
    @wraps(func) # @wrap->Add additional function without changing origin code
    # *args **kwargs-> any args would put here
    def decorated(*args,**kwargs):
        token = request.args.get('token')
        if not token:
            return jsonify({'Alert!':'Token is missing'})
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'])
        except:
            return jsonify({"Alert":"Invalid Token!"})
    return decorated()



@app.route('/')
def main():
    print("main page")
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        return 'Logged in currently'


# login
@app.route('/login', methods=['POST'])
def login():
    if request.form['username'] and request.form['password'] == "123":
        session['logged_in'] = True
        token = jwt.encode({
            'user': request.form['username'],
            'expiration': str(datetime.utcnow() + timedelta(seconds=120))
        },
            app.config['SECRET_KEY'])
        return jsonify({'token': token.decode('utf-8')})
    else:
        return make_response('Unable to verify', 403, {'WWW-Authenticate': 'Basic realm:Failed!'})


# public page
@app.route('/public')
def public_page():
    return "public page"

#Authenticated page
@app.route('/auth')
@token_required
def auth():
    return "JWT is verified, Welcome to my website"

if __name__ == '__main__':
    app.run(host='localhost', debug=True)
