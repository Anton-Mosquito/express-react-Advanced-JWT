import React, { FC, useContext, useEffect, useState } from 'react';
import { Context } from './index';
import LoginForm from './components/LoginForm';
import { observer } from 'mobx-react-lite';
import { IUser } from './models/IUser';
import UserService from './services/UserService';

const App: FC = () => {

  const { store } = useContext(Context);
  const [users, setUsers] = useState<IUser[]>([]);

  useEffect(()=>{
    if(localStorage.getItem('token')) {
      store.checkAuth();
    }
  }, []);

  const getUser = async () => {
    try {
      const response = await UserService.fetchUsers();
      setUsers(response.data)
    } catch (error) {
      console.log(error);
    }
  }

  if(store.isLoading) {
    return <div>Loading...</div>
  }


  if(!store.isAuth) {
    return (
      <div>
        <LoginForm/>
        <button onClick={getUser}>Get users</button>
      </div>
    )
  }

  return (
    <div>
      <h1>{store.isAuth ? `User ${store.user.email} is authorized` : `User ${store.user.email} is not authorized`}</h1>
      <h2>{store.user.isActivated ? `Account accept on email` : `Accept the account`}</h2>
      <button onClick={()=> store.logout()}>Exit</button>
      <div>
        <button onClick={getUser}>Get users</button>
      </div>
      {users.map((user: IUser) => <div key={user.email}>{user.email}</div>)}
    </div>
  );
}

export default observer(App);
