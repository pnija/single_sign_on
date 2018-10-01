import jwt
from flask import Flask, session, redirect, url_for, escape, request, render_template,\
abort, redirect, url_for

app = Flask(__name__)


app.config.from_object(__name__)

# Set the secret key to some random bytes. Keep this really secret!
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

JWT_SECRET = '123456789'

from sqlalchemy import Column, String, Integer, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
 
Base = declarative_base()
 
class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    username = Column(String)

class UserInfo(Base):
    __tablename__ = 'userinfo'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id'))
    access_token = Column(String)

    parent = relationship("User", backref="userinfo")

 
 
from sqlalchemy import create_engine
engine =  create_engine('sqlite:///tutorial.db', echo=True)
 
from sqlalchemy.orm import sessionmaker
 
# Construct a sessionmaker object
Session = sessionmaker(bind=engine)
 
sessiondata = Session()
 
# Create all the tables in the database which are
# defined by Base's subclasses such as User
Base.metadata.create_all(engine)



@app.route('/')
def index():
    if 'access_token' in session:
        if sessiondata.query(UserInfo).filter(UserInfo.access_token==session['access_token']).all():
            return render_template('index.html')

    return redirect(url_for('login'))


@app.route('/accounts/login/', methods=['GET'])
def login():

    if 'access_token' in session:
        if sessiondata.query(UserInfo).filter(UserInfo.access_token==session['access_token']).all():
            return redirect(url_for('index'))

    redirect_url = request.url_root+'accounts/login-info/'
    token = jwt.encode({'redirect_url': redirect_url}, JWT_SECRET, algorithm='HS256')
    return redirect('http://example.com:8000/accounts/check-login/%s' %token.decode())


@app.route('/accounts/login-info/<token>/', methods=['GET'])
def login_info(token=None):
    user_info = jwt.decode(token.encode(), JWT_SECRET, algorithms=['HS256'])

    if not sessiondata.query(User).filter(User.id==user_info['id']).all():
        ed_user = User(id= user_info['id'], username=user_info['username'])
        sessiondata.add(ed_user)
    else:
        ed_user = sessiondata.query(User).get(user_info['id'])
        
    sessiondata.commit()

    userinfo = UserInfo(user_id=ed_user.id, access_token=user_info['access_token'])
    sessiondata.add(userinfo)
    sessiondata.commit()

    session['access_token'] = user_info['access_token']

    return redirect(url_for('index'))


@app.route('/accounts/logout/', methods=['GET'])
def logout():
    # remove the username from the session if it's there

    data = {
        'redirect_url': request.url_root+'accounts/success/',
        'access_token': session['access_token']
    }
    token = jwt.encode(data, JWT_SECRET, algorithm='HS256')

    return redirect('http://example.com:8000/accounts/process-logout/%s' %token.decode())


@app.route('/accounts/process-logout/<token>/', methods=['GET'])
def process_logout(token=None):
    
    access_token = jwt.decode(token.encode(), JWT_SECRET, algorithms=['HS256'])['access_token']
    sessiondata.query(UserInfo).filter(UserInfo.access_token==access_token).delete()
    sessiondata.commit()

    return 'success'


@app.route('/accounts/success/', methods=['GET'])
def logout_success(token=None):

    return render_template('loged_out.html')
