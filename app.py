from urllib import request
import jwt
import socketio
from fastapi import FastAPI,Depends,HTTPException,status
from fastapi.security import OAuth2PasswordBearer,OAuth2PasswordRequestForm
from passlib.hash import bcrypt 
from pydantic import BaseModel
from sqlmodel import Field, SQLModel,create_engine,Session,select
from typing import Optional

#creating a fast api instance
fastapi_app=FastAPI()
JWT_SECRET='Thisismysecret'
################################  DATABASE SECTION ######################################


class User_DB(SQLModel,table=True):
    id:Optional[int] = Field(default=None, primary_key=True)
    username:str
    password:str

class User(BaseModel):
    username : str
    password : str
    class Config:
        orm_mode=True


    
sqlite_file_name = "database.db"
sqlite_url = f"sqlite:///{sqlite_file_name}"

engine = create_engine(sqlite_url, echo=True)
engine = create_engine(sqlite_url, echo=True)

@fastapi_app.post('/createuser/')
def AddUser(user:User):
    password = bcrypt.hash(user.password)
    add_user=User_DB(
        username=user.username,
        password=password
    )
    session=Session(engine)
    session.add(add_user)
    session.commit()
    session.close()
    return {'success':'inserted'}


def authenticate_user(username,password):
    with Session(engine) as session:
        statement=select(User_DB)
        result = session.exec(statement)
        for user in result:
            if user.username == username and bcrypt.verify(password,user.password):
                return True

#############################################################################################









################################ AUTHENTICATION-SECTION ##################################### 


#creating scheme using oauthpassword bearer
oauth2_sheme=OAuth2PasswordBearer(tokenUrl='login')


#creating endpoint login to accept form data and returning access token
@fastapi_app.post('/login')
async def login(form_data:OAuth2PasswordRequestForm=Depends()):
    user = authenticate_user(form_data.username,form_data.password)
    if user:
        token = jwt.encode({'data':form_data.username},JWT_SECRET)
        return {'token':token}
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail='Invalid username or password'
        )

def Verify_token(token:str=Depends(oauth2_sheme)):
    try : 
        payload=jwt.decode(token,JWT_SECRET,algorithms=['HS256'])
    except:
         raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail='Invalid username or password'
        )
    return payload

##############################################################################################







############################ API'S ENDPOINT AND SOCKET.IO SECTION ###################################


#creating an asynchrounus server using socket io to work with websockets
sio = socketio.AsyncServer(async_mode='asgi')

#creating asgi app and wraaping fastapi app
app = socketio.ASGIApp(sio,other_asgi_app=fastapi_app,on_startup=print('starting'),static_files={'/':'./Frontend/index.html'})

#connect event handler
@sio.event
def connect(sid,environ):
    print('connected')



#recieving message from the cient and pull into all client again
@fastapi_app.get('/message/{message}')
async def IndexView(message,token:str =Depends(Verify_token)):
    username=token.get('data')
    await sio.emit('recieve_message',{'message':message,'data':username},)
    return {'message':message,'data':username}




#disconnect event handler
@sio.event
def disconnect(sid):
    print("Disconnected!!")
##############################################################################################

SQLModel.metadata.create_all(engine)
