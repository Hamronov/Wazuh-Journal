import { randomUUID } from "node:crypto";

type Context = Record<string, unknown>;
const secretPattern = /^(?:key|password|secret|token|authorization|private|.*(?:private[_-]?key|api[_-]?key))$/i;
function safe(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(safe);
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([k,v]) => [k, secretPattern.test(k) ? "[REDACTED]" : safe(v)]));
  if (typeof value === "string" && (value.includes("BEGIN ") || value.length > 500)) return `[REDACTED_STRING length=${value.length}]`;
  return value;
}
export function requestId(){return randomUUID().slice(0,8)}
export function log(scope:string,event:string,context:Context={}){console.info(JSON.stringify({ts:new Date().toISOString(),scope,event,...safe(context) as Context}))}
export function logError(scope:string,event:string,error:unknown,context:Context={}){console.error(JSON.stringify({ts:new Date().toISOString(),scope,event,error:error instanceof Error?error.message:String(error),...safe(context) as Context}))}
export async function timed<T>(scope:string,event:string,work:()=>Promise<T>,context:Context={}):Promise<T>{const started=Date.now();log(scope,`${event}.start`,context);try{const result=await work();log(scope,`${event}.success`,{...context,durationMs:Date.now()-started});return result}catch(error){logError(scope,`${event}.failure`,error,{...context,durationMs:Date.now()-started});throw error}}
