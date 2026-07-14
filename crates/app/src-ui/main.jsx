import React from "react";
import { createRoot } from "react-dom/client";
// Leo design tokens (Brave's Nala design system) — CSS variables for colors,
// spacing, radii, typography used across all Leo components.
import "@brave/leo/tokens/css/variables.css";
import { setIconBasePath } from "@brave/leo/react/icon";
import "./styles.css";
import App from "./App.jsx";

// Leo icons are fetched at runtime as /icons/<name>.svg. We serve a curated
// subset from public/icons (see src-ui/public/icons).
setIconBasePath("/icons");

createRoot(document.getElementById("root")).render(<App />);
