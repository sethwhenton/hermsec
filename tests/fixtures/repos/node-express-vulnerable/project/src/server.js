import express from "express";
import routes from "./routes/search.js";

const app = express();
app.use(routes);

export default app;
