require("dotenv").config();

const { Pool } = require("pg");

const isProduction =
process.env.NODE_ENV === "production";

const pool = new Pool({

console.log(
  "DB URL =",
  process.env.DATABASE_URL?.replace(/:\/\/.*@/, "://****@")
);

  connectionString:
  process.env.DATABASE_URL,

  ssl: isProduction
    ? {
        rejectUnauthorized: false
      }
    : false

});

/* =========================
   CONNECT
========================= */

pool.on("connect",()=>{

  console.log(
    "✅ PostgreSQL Connected"
  );

});

/* =========================
   ERROR
========================= */

pool.on("error",(err)=>{

  console.error(
    "❌ PostgreSQL Error:",
    err.message
  );

});

/* =========================
   TEST CONNECTION
========================= */

async function testConnection(){

  try{

    await pool.query(
      "SELECT NOW()"
    );

    console.log(
      "✅ Database Ready"
    );

    return true;

  }catch(err){

    console.log(
      "❌ Database Failed"
    );

    console.log(
      err.message
    );

    return false;

  }

}

module.exports={

  query:(text,params)=>
    pool.query(text,params),

  pool,

  testConnection

};
