import { createHmac, timingSafeEqual } from "node:crypto";
import { gunzipSync } from "node:zlib";
import { loadLocalSettings } from "./local-settings";
import { runWazuhCommand } from "./wazuh";

const cookieName="wazuh-session", maxAge=8*60*60;
type Session={user:string;exp:number};

export async function authenticateWazuhUser(username:string,password:string){
  await loadLocalSettings();
  const user=username.trim();
  if(!user||!password||user.length>128||/[\r\n\0]/.test(user))throw new Error("Введите доменный логин и пароль");
  const auth=Buffer.from(`${user}:${password}`).toString("base64");
  const remote=`sudo -n bash -o pipefail -c 'read -r auth_b64; auth=$(printf %s "$auth_b64" | base64 -d); curl --fail-with-body -sS --max-time 12 --cacert /etc/wazuh-indexer/certs/root-ca.pem -u "$auth" https://127.0.0.1:9200/_plugins/_security/authinfo | gzip -c | base64'`;
  let encoded:string;
  try{encoded=await runWazuhCommand(remote,{stdinData:`${auth}\n`,skipPasswordStdin:true})}catch{throw new Error("Неверный доменный логин, пароль или нет доступа к Wazuh")}
  const text=gunzipSync(Buffer.from(encoded.replace(/\s/g,""),"base64")).toString("utf8");
  let response:Record<string,unknown>;
  try{response=JSON.parse(text)}catch{throw new Error("Неверный доменный логин, пароль или нет доступа к Wazuh")}
  if(!response.user_name)throw new Error("Wazuh не подтвердил доменную учётную запись");
  return createSession(String(response.user_name));
}

export async function currentSession(cookieHeader:string|undefined):Promise<Session|null>{
  await loadLocalSettings();
  if(!cookieHeader)return null;
  const token=cookieHeader.split(";").map(part=>part.trim()).find(part=>part.startsWith(`${cookieName}=`))?.slice(cookieName.length+1);
  if(!token)return null;
  const [payload,signature]=token.split(".");
  if(!payload||!signature)return null;
  const expected=sign(payload);
  if(signature.length!==expected.length||!timingSafeEqual(Buffer.from(signature),Buffer.from(expected)))return null;
  try{const session=JSON.parse(Buffer.from(payload,"base64url").toString("utf8")) as Session;return session.exp>Date.now()/1000?session:null}catch{return null}
}
export async function requireSession(request:Request){return currentSession(request.headers.get("cookie")||undefined)}

export function sessionCookie(session:Session){return `${cookieName}=${Buffer.from(JSON.stringify(session)).toString("base64url")}.${sign(Buffer.from(JSON.stringify(session)).toString("base64url"))}; Max-Age=${maxAge}; Path=/; HttpOnly; SameSite=Lax${process.env.NODE_ENV==="production"?"; Secure":""}`}
export function clearSessionCookie(){return `${cookieName}=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax${process.env.NODE_ENV==="production"?"; Secure":""}`}
function createSession(user:string){const session={user,exp:Math.floor(Date.now()/1000)+maxAge};return{session,cookie:sessionCookie(session)}}
function sign(value:string){return createHmac("sha256",secret()).update(value).digest("base64url")}
function secret(){
  const configured=process.env.AUTH_SESSION_SECRET;
  if(configured)return configured;
  if(process.env.NODE_ENV==="production")throw new Error("AUTH_SESSION_SECRET is required in production");
  return "local-wazuh-session-secret";
}
