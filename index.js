const express = require("express");
const app = express();
const cors = require("cors");
const ConnectToMongo = require("./database");
const dotenv = require('dotenv');
dotenv.config();
const port = process.env.PORT || 5000;

// node app.js

ConnectToMongo();
app.use(cors());
app.use(express.json()); // parsing body
app.use("/api/auth", require("./routes/auth"));
app.use("/api/jobs", require("./routes/jobs")); 

app.listen(port, () => {
  console.log(`JOBUP app listening at http://localhost:${port}`);
});
 