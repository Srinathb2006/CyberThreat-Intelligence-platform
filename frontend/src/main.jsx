import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App.jsx';
import './styles.css';
document.documentElement.classList.toggle('compact', localStorage.getItem('cyberintel.compact') === 'true');
ReactDOM.createRoot(document.getElementById('root')).render(<React.StrictMode><App /></React.StrictMode>);
