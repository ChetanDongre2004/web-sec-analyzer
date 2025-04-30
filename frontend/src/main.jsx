import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.jsx'
import DOMPurify from 'dompurify';

// Sanitize user inputs before rendering
const sanitize = (input) => DOMPurify.sanitize(input);

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <App sanitize={sanitize} />
  </StrictMode>,
)
