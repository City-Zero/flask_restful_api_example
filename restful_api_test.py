from flask import Flask,request,render_template,g,jsonify,current_app
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash,check_password_hash
from flask_httpauth import HTTPBasicAuth
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask_script import Manager

import os
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
manager = Manager(app)
db = SQLAlchemy(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////' + os.path.join(BASE_DIR, 'db.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SECRET_KEY'] = 'restful_api_test'

auth = HTTPBasicAuth()


#定义了一个匿名用户类
class AnonymousUser():
    @property
    def is_anonymous(self):
        return True


#普通用户类
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer,primary_key=True)
    username = db.Column(db.String(80),unique=True)
    password_hash = db.Column(db.String(128))

    #生成token
    def get_auth_token(self,expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'],expires_in=expiration)
        s = s.dumps({'id':self.id}).decode('utf-8')
        return s

    #验证token
    @staticmethod
    def verify_auth_token(token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return None
        return User.query.get(data['id'])


#一
    @property
    def password(self):
        raise AttributeError('Password is not a readable attribute')

    #设置password的方法
    @password.setter
    def password(self,password):
        self.password_hash = generate_password_hash(password)

    #验证密码
    def verify_password(self,password):
        return check_password_hash(self.password_hash,password)

    @property
    def is_anonymous(self):
        return False


@auth.verify_password
def verify_password(email_or_token,password):
    if email_or_token == '':
        g.current_user = AnonymousUser()
        return False

    if password == '':
        g.current_user = User.verify_auth_token(email_or_token)
        g.token_used = True
        return g.current_user is not None

    user = User.query.filter_by(username=email_or_token).first()
    if not user:
        return False
    g.current_user = user
    g.token_used = False
    return user.verify_password(password)


@app.route('/')
def index():
    return render_template('index.html')


#获取token
@app.route('/api/token')
@auth.login_required
def get_token():
    if g.current_user.is_anonymous or g.token_used:
        return unauthorized('Invalid credentials')

    return jsonify({'token':g.current_user.get_auth_token(expiration=3600),'expiration':3600})

def unauthorized(message):
    response = jsonify({'error':'forbidden','message':message})
    response.status_code = 401
    return response

@app.errorhandler
def auth_error():
    return unauthorized('Invalid credentials')


#用户注册
@app.route('/api/user',methods=['POST'])
def AddUser():
    username = request.json.get('username')
    password = request.json.get('password')
    if not username or not password:
        return jsonify({'state':False,'message':'用户名密码不能为空！'})
    else:
        if User.query.filter_by(username=username).first() == None:
            u = User()
            u.username = username
            u.password = password
            db.session.add(u)
            db.session.commit()
            return jsonify({'state':True,'message':'成功注册%s!'%username})
        return jsonify({'state':False,'message':'用户名已经被注册了...'})


#获得用户信息
@app.route('/api/user')
@auth.login_required
def UserInfo():
    return jsonify({'state':True,'message':{'username':g.current_user.username}})



if __name__ == '__main__':
    manager.run()
