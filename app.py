from flask import Flask,request,jsonify,make_response
import  os
from flask_sqlalchemy import SQLAlchemy
import  uuid
from werkzeug.security import generate_password_hash,check_password_hash
import  jwt
import datetime
from functools import wraps
from flask_mail import Mail,Message
from flask_migrate import Migrate




application=Flask(__name__)

application.config['SECRET_KEY']='somesecret'

# Configuring Database Uri

base_dir=os.path.abspath(os.path.dirname(__file__))


application.config['SQLALCHEMY_DATABASE_URI']='sqlite:///' + os.path.join(base_dir , 'db.sqlite')
application.config['SQLALCHEMY_TRACK_MODIFICATIONS']= False

# Flask-mail config

application.config['MAIL_SERVER']='smtp.mailtrap.io'
application.config['MAIL_PORT'] = 2525
application.config['MAIL_USERNAME'] = '060437940720dc'
application.config['MAIL_PASSWORD'] = 'c075a5e5c39bff'
application.config['MAIL_USE_TLS'] = True
application.config['MAIL_USE_SSL'] = False

# db init
db=SQLAlchemy(application)
mail=Mail(application)
migrate = Migrate(application, db)
from app import db
# models

class User(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    public_id=db.Column(db.String(50),unique=True)
    name=db.Column(db.String(50))
    password=db.Column(db.String(80))
    admin=db.Column(db.Boolean)
    email=db.Column(db.String(60))

class Todo(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    text=db.Column(db.String(200))
    user_id=db.Column(db.Integer)
    completed=db.Column(db.Boolean)

def token_required(f):
    @wraps(f)
    def decorated(*args,**kwargs):
        token=None
        if 'x-access-token' in request.headers:
            token=request.headers['x-access-token']
        if not token :
            return jsonify ({'message': 'token is missing'}),401
        try:
            data=jwt.decode(token,application.config['SECRET_KEY'])
            current_user=User.query.filter_by(public_id=data['public_id']).first()

        except:
            return jsonify({'message': 'token is invalid '}), 401
        return f(current_user,*args,**kwargs)

    return decorated




# Routes 
@application.route('/users',methods=['GET'])
@token_required
def get_users(current_user):
    if not current_user.admin:
        return jsonify({'alert': 'you are not authorized for this action'})
    users=User.query.all()

    output=[]

    for user in users:
        basket={}
        basket['name']=user.name
        basket['public_id']=user.public_id
        basket['password']=user.password
        basket['admin']=user.admin
        output.append(basket)
    return jsonify({'users':output})

@application.route('/single-user/<public_id>',methods=['GET'])
@token_required
def single_user(current_user,public_id):
    if not current_user.admin:
        return jsonify({'alert': 'you are not authorized for this action'})
    user=User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({"message":"No User Found"})
    else:
        basket = {}
        basket['name'] = user.name
        basket['public_id'] = user.public_id
        basket['password'] = user.password
        basket['admin'] = user.admin
        return jsonify(basket)

@application.route('/create_user',methods=['POST'])
def create_new_user():
    data=request.get_json()
    hashed_password=generate_password_hash(data['password'],method='sha256')
    user=User(name=data['name'],password=hashed_password,public_id=str(uuid.uuid4()),admin=False,email=data['email'])
    db.session.add(user)
    db.session.commit()
    return 'created user'


@application.route('/update-user/<public_id>',methods=['PUT'])

def update_user(current_user,public_id):
    if not current_user.admin:
        return jsonify({'alert': 'you are not authorized for this action'})
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({"message": "No User Found"})
    else:
        user.admin=True
        db.session.commit()
        return jsonify({"message": "Successfully Promoted to Admin User"})



@application.route('/delete_user/<public_id>',methods=['DELETE'])
@token_required
def user_del(current_user,public_id):
    if not current_user.admin:
        return jsonify({'alert': 'you are not authorized for this action'})
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({"Warning": "No User Found"})
    else:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"Success":"user deleted"})

@application.route('/login')
def login():
    auth=request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify ',401,{'WWW.Authenticate':"Basic-realm='Login Required !'"})
    user=User.query.filter_by(name=auth.username).first()
    if not user:
        return make_response('Could not verify ', 401, {'WWW.Authenticate': "Basic-realm='Login Required !'"})

    if check_password_hash(user.password,auth.password):
        token=jwt.encode({"public_id":user.public_id,"exp": datetime.datetime.now() + datetime.timedelta(minutes=30)},application.config['SECRET_KEY'])
        return jsonify({"token":token.decode('UTF-8')})
    return make_response('Could not verify ', 401, {'WWW.Authenticate': "Basic-realm='Login Required !'"})

@application.route('/create_todo',methods=['POST'])
@token_required
def add_todo(current_user):
    todo_data=request.get_json()
    new_todo=Todo(text=todo_data['text'],user_id=current_user.id,completed=todo_data['completed'])
    x=db.session.add(new_todo)
    db.session.commit()
    return jsonify({"message":'Todo Created '})


@application.route('/all_todos',methods=['GET'])
@token_required
def all_todo(current_user):
    x=Todo.query.filter_by(user_id=current_user.id)
    output=[]

    for user in x:
        basket={}
        basket['text']=user.text
        basket['user_id']=user.user_id
        basket['completed']=user.completed
        basket['id']=user.id
        output.append(basket)
    if len(output)<1:
        return jsonify(message='You have no todo')
    return jsonify({'Todos':output})

@application.route('/delete-todo/<id>' , methods=['DELETE'] )
@token_required
def deletetodo(currentuser,id):
    todo_check=Todo.query.get(id)
    if not todo_check is None:
        if todo_check.user_id==currentuser.id:
            db.session.delete(todo_check)
            db.session.commit()
            return jsonify({"message":" to do deleted  " })
        else :
            return jsonify({"message": "You are not authorized to perform this action"})
        

    else:
        return jsonify({"message":'No To do found for this id'})



   

@application.route('/update-todo/<id>' , methods=['PUT'] )
@token_required
def updatetodo(currentuser,id):
    todo_check=Todo.query.filter_by(user_id=currentuser.id , id=id).first()
    if not todo_check:
        print('not matches')
        return jsonify({"m":"output"})

    todo_check.completed=True
    db.session.commit()
    return jsonify ("updated")
       

    
@application.route('/retrieve-password/<string:email>' , methods=['GET'])
def retrieve_password(email:str):
    user=User.query.filter_by(email=email).first()
    if user:
        msg=Message('your password is '+ user.password , sender='admin@flask-api.com',recipients=[email])

        mail.send(msg)
        return jsonify ("mail sent to "+ email)
    else:
        return jsonify("mail does not exist")