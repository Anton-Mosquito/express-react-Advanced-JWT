import React, { createContext } from 'react';
import ReactDOM from 'react-dom';
import App from './App';
import Store from './store/store';

interface IStore {
  store: Store
}

const store = new Store();

export const Context = createContext<IStore>({
  store,
})

ReactDOM.render(
  <React.StrictMode>
    <Context.Provider value={{store}}>
      <App />
    </Context.Provider>
  </React.StrictMode>,
  document.getElementById('root')
);

