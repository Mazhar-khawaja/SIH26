import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./index.css";
import App from "./App.jsx";

const originalFetch = window.fetch;
window.fetch = async function () {
    let [resource, config] = arguments;
    config = config || {};
    config.headers = {
        ...config.headers,
        'X-API-Key': 'default_api_key_change_me'
    };
    return originalFetch(resource, config);
};

createRoot(document.getElementById("root")).render(
  <StrictMode>
    <App />
  </StrictMode>,
);