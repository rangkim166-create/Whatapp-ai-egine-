import http from "node:http";
import crypto from "node:crypto";

const PORT=Number(process.env.PORT||3000);
const WEBHOOK_SECRET=process.env.WHATSAPP_WEBHOOK_SECRET||"";
const ENGINE_NAME="Ash WhatsApp AI Engine";

function json(res,status,body){
  res.writeHead(status,{"content-type":"application/json; charset=utf-8"});
  res.end(JSON.stringify(body));
}
function authorized(req){
  if(!WEBHOOK_SECRET) return process.env.NODE_ENV!=="production";
  const supplied=req.headers["x-whatsapp-engine-secret"];
  return typeof supplied==="string" && crypto.timingSafeEqual(Buffer.from(supplied),Buffer.from(WEBHOOK_SECRET));
}
async function readBody(req){
  const chunks=[]; for await(const c of req) chunks.push(c);
  return Buffer.concat(chunks).toString("utf8");
}

const server=http.createServer(async(req,res)=>{
  if(req.method==="GET" && req.url==="/health"){
    return json(res,200,{ok:true,engine:ENGINE_NAME,status:"online",timestamp:new Date().toISOString()});
  }
  if(req.method==="GET" && req.url==="/"){
    return json(res,200,{ok:true,engine:ENGINE_NAME,version:"1.0.0"});
  }
  if(req.method==="POST" && req.url==="/webhook"){
    if(!authorized(req)) return json(res,401,{ok:false,error:"Unauthorized"});
    let payload={};
    try{ payload=JSON.parse(await readBody(req)||"{}"); }catch{return json(res,400,{ok:false,error:"Invalid JSON"});}
    // Transport layer only: WhatsApp events are accepted here and handed to the AI adapter.
    // Provider credentials and admin secrets never belong in webhook payloads.
    return json(res,200,{ok:true,accepted:true,eventId:crypto.randomUUID(),receivedAt:new Date().toISOString()});
  }
  json(res,404,{ok:false,error:"Not found"});
});
server.listen(PORT,"0.0.0.0",()=>console.log(`${ENGINE_NAME} listening on ${PORT}`));