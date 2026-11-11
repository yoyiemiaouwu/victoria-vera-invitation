const express = require("express");
const crypto = require("crypto");
const path = require("path");
const app = express();
const PORT = process.env.PORT || 3000;
const PASSWORD = process.env.PRIVATE_PAGE_PASSWORD;
const SECRET = process.env.SESSION_SECRET;

if (!PASSWORD || !SECRET) {
  console.error("Set PRIVATE_PAGE_PASSWORD and SESSION_SECRET before starting.");
  process.exit(1);
}
app.use(express.json({limit:"10kb"}));
app.use(express.static(path.join(__dirname,"public")));

app.use("/assets", express.static(path.join(__dirname,"assets")));

const participants = [
"Ninang Hyacinth Sortijas","Ninang Julie Maniebo","Shella Buena Araza",
"Rency Araza Luna","Emma Arenas","Daine Krishmen Abella",
"Andrea Pacumio-Dechavez","Jamielee Pacumio Abueg","Lola Virginia Araza",
"Lola Lourdes Pacumio","Mother Verna Pacumio","Totie Araga",
"Lolo Agapito Pacumio","Ninong Eymard Sortijas","Ronald Araza",
"Craig Krystan Barrera","Brother Victor Vernard Pacumio","Father Victor Rayo Pacumio"
];
const tokens = new Map();
function sign(value){return crypto.createHmac("sha256",SECRET).update(value).digest("hex")}
function makeCookie(){const payload=JSON.stringify({exp:Date.now()+8*60*60*1000});const data=Buffer.from(payload).toString("base64url");return data+"."+sign(data)}
function validCookie(req){
 const raw=(req.headers.cookie||"").split(";").map(x=>x.trim()).find(x=>x.startsWith("yellow_access="));
 if(!raw)return false;const value=raw.slice("yellow_access=".length);const [data,signature]=value.split(".");
 if(!data||!signature||!crypto.timingSafeEqual(Buffer.from(sign(data)),Buffer.from(signature)))return false;
 try{return JSON.parse(Buffer.from(data,"base64url").toString()).exp>Date.now()}catch{return false}
}
app.post("/api/unlock",(req,res)=>{
 const supplied=String(req.body?.password||"");
 const a=Buffer.from(supplied),b=Buffer.from(PASSWORD);
 if(a.length!==b.length||!crypto.timingSafeEqual(a,b))return res.status(401).json({error:"Incorrect password"});
 res.setHeader("Set-Cookie",`yellow_access=${makeCookie()}; HttpOnly; SameSite=Lax; Path=/; Max-Age=28800${process.env.NODE_ENV==="production"?"; Secure":""}`);
 res.json({ok:true,participants});
});
app.get("/api/yellow-bills",(req,res)=>{
 if(!validCookie(req))return res.status(401).json({error:"Access denied"});
 res.json({participants});
});
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(PORT,()=>console.log(`Invitation listening on ${PORT}`));
