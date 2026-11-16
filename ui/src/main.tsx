import React from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import './styles.css';
import './upload.css';
import './explorer.css';
import './builder.css';
import './assistant.css';

const root = document.getElementById('root');
if (!root) throw new Error('no #root element');

createRoot(root).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
