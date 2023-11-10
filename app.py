from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Resource, Api
from flask_jwt_extended import create_access_token, JWTManager
app = Flask(__name__)

app.config['SECRET_KEY'] = 'Abdullah'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
api= Api(app)
jwt = JWTManager(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(200), unique=True, nullable=True)
    password = db.Column(db.String(200), nullable=True)

with app.app_context():

   db.create_all()


#User Regestration
class UserRegistration(Resource):
    def post(self):
        data = request.get_json()
        username = data['username']
        password = data['password']
        if not username or not password:
            return {'message':'Missing username and password'}, 400
        
        if User.query.filter_by(username=username).first():
            return {'message' : 'Username already taken'}, 400
        
        new_user = User(username=username , password=password)
        db.session.add(new_user)
        db.session.commit()

        return {'message' : 'User created successfully'},200
    

#User Login
class UserLogin(Resource):
    def post(self):
        data = request.get_json()
        username = data['username']
        password = data['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.password == password:
            access_token = create_access_token(identity=user.id)
            return {'access_token' : access_token}, 200
        
        return {'message' : 'Invalid credentials'}, 401
    

api.add_resource(UserRegistration, '/register')
api.add_resource(UserLogin, '/login')
    



if __name__ == '__main__':
    app.run(debug=True)