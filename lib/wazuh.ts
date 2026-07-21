import { execFile } from "node:child_process";
import { chmod, readFile, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { homedir } from "node:os";
import { join } from "node:path";
import { gunzipSync } from "node:zlib";
import { loadLocalSettings } from "./local-settings";
import { log, logError, requestId } from "./logger";

export type WazuhAlert = { id:string; time:string; timestamp:string; level:number; title:string; host:string; ip:string; rule:string; group:string; detail:string; story?:string; fields?:[string,string][] };
export type WazuhAlertPage={alerts:WazuhAlert[];hasMore:boolean;nextCursor:string|null};
type AlertQuery={from?:string|null;to?:string|null;limit?:number;cursor?:string|null;minLevel?:number;maxLevel?:number};
let alertsInFlight:Promise<WazuhAlert[]>|null=null;

export async function loadWazuhAlerts(): Promise<WazuhAlert[]> {
  if(alertsInFlight)return alertsInFlight;
  alertsInFlight=loadWazuhAlertsOnce();
  try{return await alertsInFlight}finally{alertsInFlight=null}
}

export async function loadWazuhAlertArchive(_offset=0,limit=500):Promise<{alerts:WazuhAlert[];hasMore:boolean}>{const page=await queryWazuhAlerts({limit});return{alerts:page.alerts,hasMore:page.hasMore}}

async function loadWazuhAlertsOnce(): Promise<WazuhAlert[]> {
  return (await queryWazuhAlerts({limit:500})).alerts;
}

export async function queryWazuhAlerts({from,to,limit=500,cursor,minLevel=8,maxLevel}:AlertQuery={}):Promise<WazuhAlertPage>{
  const rid=requestId(),safeLimit=Math.min(1000,Math.max(1,Math.floor(limit))),safeMin=Math.max(8,Math.floor(minLevel)),safeMax=Number.isFinite(maxLevel)?Math.max(safeMin,Math.floor(maxLevel as number)):undefined,filters:Record<string,unknown>[]=[{range:{"rule.level":{gte:safeMin,...(safeMax!==undefined?{lte:safeMax}:{})}}}];
  if(from||to)filters.push({range:{timestamp:{...(from?{gte:from}:{}),...(to?{lte:to}:{})}}});
  const searchAfter=decodeCursor(cursor),fromTime=from?Date.parse(from):NaN,recentWindow=!to&&(!from||(Number.isFinite(fromTime)&&Math.abs(Date.now()-fromTime)<48*60*60*1000)),index=from&&to&&from.slice(0,10)===to.slice(0,10)?`wazuh-alerts-4.x-${from.slice(0,10).replaceAll("-",".")}`:recentWindow?`wazuh-alerts-4.x-${localIndexDate()}`:"wazuh-alerts-*",body:Record<string,unknown>={size:safeLimit+1,track_total_hits:false,query:{bool:{filter:filters}},sort:[{timestamp:{order:"desc",unmapped_type:"date"}}]};
  if(searchAfter)body.search_after=searchAfter;
  const body64=Buffer.from(JSON.stringify(body)).toString("base64"),remote=`printf %s ${body64} | base64 -d | curl --fail-with-body -sS --max-time 45 --cacert /etc/wazuh-indexer/certs/root-ca.pem --cert /etc/wazuh-indexer/certs/admin.pem --key /etc/wazuh-indexer/certs/admin-key.pem -H 'Content-Type: application/json' --data-binary @- ${shellQuote(`https://127.0.0.1:9200/${index}/_search`)} | gzip -c | base64`;
  log("wazuh","indexer.query.start",{rid,from,to,index,limit:safeLimit,minLevel:safeMin,maxLevel:safeMax,hasCursor:Boolean(cursor)});
  const encoded=await runWazuhCommand(`sudo -n bash -o pipefail -c ${shellQuote(remote)}`),json=gunzipSync(Buffer.from(encoded.replace(/\s/g,""),"base64")).toString("utf8"),response=JSON.parse(json) as {hits?:{hits?:Array<{_id?:string;_source?:Record<string,unknown>;sort?:unknown[]}>}};
  const hits=response.hits?.hits||[],pageHits=hits.slice(0,safeLimit),alerts=pageHits.flatMap(hit=>{try{const alert=mapAlert({...hit._source,id:hit._source?.id||hit._id});return alert.level>=8?[alert]:[]}catch{return []}}),last=pageHits.at(-1),nextCursor=hits.length>safeLimit&&last?.sort?encodeCursor(last.sort):null;
  log("wazuh","indexer.query.success",{rid,hits:hits.length,alerts:alerts.length,hasMore:Boolean(nextCursor),levels:[...new Set(alerts.map(alert=>alert.level))].sort((a,b)=>a-b)});
  return{alerts,hasMore:Boolean(nextCursor),nextCursor};
}

function encodeCursor(value:unknown[]){return Buffer.from(JSON.stringify(value)).toString("base64url")}
function decodeCursor(value?:string|null):unknown[]|null{if(!value)return null;try{const parsed=JSON.parse(Buffer.from(value,"base64url").toString("utf8"));return Array.isArray(parsed)&&parsed.every(item=>["string","number"].includes(typeof item))?parsed:null}catch{return null}}
function shellQuote(value:string){return `'${value.replace(/'/g,`'"'"'`)}'`}
function localIndexDate(){const date=new Date(),pad=(value:number)=>String(value).padStart(2,"0");return `${date.getFullYear()}.${pad(date.getMonth()+1)}.${pad(date.getDate())}`}

export async function runWazuhCommand(command:string,options:{stdinData?:string;skipPasswordStdin?:boolean}={}): Promise<string> {
  const rid=requestId(); const started=Date.now(); log("ssh","command.start",{rid,command:command.replace(/\s+/g," ").slice(0,180)});
  await loadLocalSettings();
  const host=cleanHost(process.env.WAZUH_SSH_HOST), user=cleanValue(process.env.WAZUH_SSH_USER), key=process.env.WAZUH_SSH_PRIVATE_KEY, password=process.env.WAZUH_SSH_PASSWORD;
  const keyPathSetting=process.env.WAZUH_SSH_PRIVATE_KEY_PATH || (process.env.WAZUH_SSH_PRIVATE_KEY?.startsWith("~/")?process.env.WAZUH_SSH_PRIVATE_KEY:undefined);
  if(!host||!user||(!key&&!keyPathSetting&&!password)) throw new Error("Wazuh SSH не настроен: укажите ключ или пароль");
  const port=process.env.WAZUH_SSH_PORT||"22";
  const jumpHost=cleanHost(process.env.WAZUH_SSH_JUMP_HOST), jumpUser=cleanValue(process.env.WAZUH_SSH_JUMP_USER)||user, jumpPort=cleanValue(process.env.WAZUH_SSH_JUMP_PORT)||"22";
  const keyPath=join(tmpdir(),`wazuh-key-${crypto.randomUUID()}`), askpassPath=join(tmpdir(),`wazuh-askpass-${crypto.randomUUID()}`);
  const debugPath=join(tmpdir(),`wazuh-ssh-${rid}.log`);
  try {
    const rawKeyContents=keyPathSetting
      ? await readFile(keyPathSetting.startsWith("~/")?keyPathSetting.replace("~",homedir()):keyPathSetting,"utf8")
      : key||"";
    const keyContents=rawKeyContents.trim()?rawKeyContents.replace(/^\uFEFF/,"").replace(/\\r?\\n/g,"\n").replace(/\r\n/g,"\n").trim()+"\n":"";
    if(keyContents) { await writeFile(keyPath,keyContents.replace(/\\n/g,"\n"),{encoding:"utf8",mode:0o600}); await chmod(keyPath,0o600); }
    // Если есть ключ, SSH должен работать ровно как ручной скрипт пользователя:
    // пароль нужен только удалённому sudo, а не ProxyJump/SSH.
    const authOptions=keyContents?["BatchMode=yes","PreferredAuthentications=publickey","ConnectTimeout=15"]:password?["BatchMode=no","PreferredAuthentications=password","ConnectTimeout=15"]:["BatchMode=yes","ConnectTimeout=15"];
    const args=["-E",debugPath,...(keyContents?["-i",keyPath]:[]),"-p",port,"-o","IdentitiesOnly=yes",...authOptions.flatMap(option=>["-o",option]),"-o","ConnectionAttempts=3","-o","ServerAliveInterval=15","-o","ServerAliveCountMax=3","-o","TCPKeepAlive=yes","-o","StrictHostKeyChecking=accept-new"];
    if(jumpHost) args.push("-o",`ProxyJump=${jumpUser}@${jumpHost}:${jumpPort}`);
    const effectiveCommand=password?command:command.replaceAll("sudo -S -p ''","sudo -n");
    args.push(`${user}@${host}`,effectiveCommand);
    log("ssh","command.args",{rid,args:args.map((arg,index)=>index===args.length-1?"[REMOTE_COMMAND]":arg)});
    const env={...process.env,...(!keyContents&&password?{SSH_ASKPASS:askpassPath,SSH_ASKPASS_REQUIRE:"force",DISPLAY:":0"}:{})};
    if(!keyContents&&password) await writeFile(askpassPath,`#!/bin/sh\nprintf '%s\\n' ${JSON.stringify(password)}`,{encoding:"utf8",mode:0o700});
    const child=execFile("ssh",args,{timeout:60000,maxBuffer:4_000_000,env});
    if(password&&!options.skipPasswordStdin)child.stdin?.write(`${password}\n`);
    if(options.stdinData)child.stdin?.write(options.stdinData);
    child.stdin?.end();
    const {stdout}=await new Promise<{stdout:string}>((resolve,reject)=>{let output="",errorOutput="";child.stdout?.on("data",chunk=>{output+=chunk});child.stderr?.on("data",chunk=>{errorOutput+=chunk});child.on("error",reject);child.on("close",code=>{if(code===0)resolve({stdout:output});else{const detail=errorOutput.trim().replace(/\s+/g," ").slice(-600);reject(new Error(detail||`ssh завершился с кодом ${code}`))}})}) ;
    log("ssh","command.success",{rid,durationMs:Date.now()-started,bytes:stdout.length}); return stdout;
  } catch(error) { let trace=""; try{trace=(await readFile(debugPath,"utf8")).replace(/\s+/g," ").slice(-1200)}catch{} logError("ssh","command.failure",error,{rid,durationMs:Date.now()-started,host,user,port,jumpHost,hasKey:Boolean(key||keyPathSetting),hasPassword:Boolean(password),trace}); throw error;
  } finally { await unlink(keyPath).catch(()=>{}); await unlink(askpassPath).catch(()=>{}); await unlink(debugPath).catch(()=>{}); }
}

function cleanValue(value?:string){return (value||"").trim().replace(/^['"]|['"]$/g,"")}
function cleanHost(value?:string){const raw=cleanValue(value).replace(/^ssh:\/\//i,"");return raw.includes("://")?raw.split("://").pop()||"":raw}

function mapAlert(value:unknown): WazuhAlert {
  const raw=value as Record<string,unknown>, rule=(raw.rule??{}) as Record<string,unknown>, agent=(raw.agent??{}) as Record<string,unknown>, manager=(raw.manager??{}) as Record<string,unknown>, data=(raw.data??{}) as Record<string,unknown>;
  const timestamp=String(raw.timestamp||new Date(0).toISOString());
  const level=Number(rule.level||0),title=String(rule.description||"Событие Wazuh"),host=String(agent.name||manager.name||"—"),ip=String(data.srcip||data.src_ip||agent.ip||"—"),ruleId=String(rule.id||"—"),group=Array.isArray(rule.groups)?rule.groups.join(", "):String(rule.groups||"—");
  const win=((data.win||{}) as Record<string,unknown>),system=((win.system||{}) as Record<string,unknown>),eventdata=((win.eventdata||{}) as Record<string,unknown>);
  const pick=(...values:unknown[])=>String(values.find(v=>v!==undefined&&v!==null&&String(v).trim())||"");
  const user=pick(eventdata.user,data.srcuser,data.dstuser),process=pick(eventdata.image,eventdata.process,data.image,data.process),parent=pick(eventdata.parentImage,data.parentImage),command=pick(eventdata.commandLine,data.command,data.cmd),provider=pick(system.providerName),eventId=pick(system.eventID,data.event_id),channel=pick(system.channel),fqdn=pick(system.computer),agentId=pick(agent.id),pid=pick(eventdata.processId,system.processID,data.processId),target=pick(eventdata.targetFilename,data.file,data.filename,data.path),hashes=pick(eventdata.hashes,data.hashes),mitre=rule.mitre as Record<string,unknown>|undefined;
  const storyParts=[`На хосте ${host} сработало правило ${ruleId} — ${title}.`,provider&&`Источник события: ${provider}.`,user&&`Пользователь: ${user}.`,process&&`Процесс: ${process}.`,parent&&`Родительский процесс: ${parent}.`,target&&`Объект/файл: ${target}.`,command&&`Командная строка: ${command}.`,hashes&&`Хэши: ${hashes}.`].filter(Boolean) as string[];
  const fields:[string,string][]=[["Правило",`${ruleId} — ${title}`],["Критичность",`${level>=15?"CRITICAL":level>=12?"HIGH":level>=8?"MEDIUM":level>=5?"LOW":"INFO"} (level ${level})`],["Хост",host],["Время",timestamp]];
  for(const pair of [["FQDN",fqdn],["Agent ID",agentId],["IP агента",String(agent.ip||"")],["Provider",provider],["Event ID",eventId],["Канал",channel],["Пользователь",user],["Процесс",process],["Родительский процесс",parent],["PID",pid],["Файл/объект",target],["Командная строка",command],["Hashes",hashes],["MITRE",mitre?JSON.stringify(mitre):""],["Группы",group]])if(pair[1]&&pair[1]!==host)fields.push(pair as [string,string]);
  return {id:String(raw.id||`${timestamp}-${rule.id||"unknown"}`),time:new Date(timestamp).toLocaleTimeString("ru-RU",{hour:"2-digit",minute:"2-digit",second:"2-digit"}),timestamp,level,title,host,ip,rule:ruleId,group,detail:"",story:storyParts.join(" "),fields};
}
