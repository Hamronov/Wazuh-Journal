import { chmod, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

export const settingKeys=["WAZUH_SSH_HOST","WAZUH_SSH_PORT","WAZUH_SSH_USER","WAZUH_SSH_PRIVATE_KEY","WAZUH_SSH_PRIVATE_KEY_PATH","WAZUH_SSH_PASSWORD","WAZUH_SSH_JUMP_HOST","WAZUH_SSH_JUMP_PORT","WAZUH_SSH_JUMP_USER","AUTH_SESSION_SECRET","AUTH_COOKIE_SECURE","AD_TENANT_ID","AD_CLIENT_ID","AD_CLIENT_SECRET","LDAP_SERVER_URIS","LDAP_BASE_DN","LDAP_BIND_DN","LDAP_BIND_PASSWORD","LDAP_USERS_DNS","LDAP_GROUPS_DN","LDAP_CA_CERT","OPENAI_BASE_URL","OPENAI_API_KEY","OPENAI_MODEL"] as const;
export type SettingKey=typeof settingKeys[number];
const secretKeys=new Set<SettingKey>(["WAZUH_SSH_PRIVATE_KEY","WAZUH_SSH_PASSWORD","AUTH_SESSION_SECRET","AD_CLIENT_SECRET","LDAP_BIND_PASSWORD","LDAP_CA_CERT","OPENAI_API_KEY"]);
const filePath=join(process.cwd(),".env.local");

export async function loadLocalSettings(){try{const values=parse(await readFile(filePath,"utf8"));for(const key of settingKeys)if(values[key])process.env[key]=values[key]}catch{} }
export async function publicSettings(){await loadLocalSettings();const result:Record<string,string|boolean>={};for(const key of settingKeys){result[key]=secretKeys.has(key)?"":process.env[key]||"";if(secretKeys.has(key))result[`${key}_CONFIGURED`]=Boolean(process.env[key])}return result}
export async function saveLocalSettings(input:Record<string,unknown>){await loadLocalSettings();const lines:string[]=[];for(const key of settingKeys){let value=typeof input[key]==="string"?String(input[key]).trim():"";if(secretKeys.has(key)&&!value)value=process.env[key]||"";validate(key,value);if(value){process.env[key]=value;lines.push(`${key}=${quote(value)}`)}else delete process.env[key]}await writeFile(filePath,`${lines.join("\n")}\n`,{encoding:"utf8",mode:0o600});await chmod(filePath,0o600)}
function parse(text:string){const result:Record<string,string>={};for(const key of settingKeys){const match=text.match(new RegExp(`^${key}=("[\\s\\S]*?"|[^\\n]*)`,"m"));if(!match)continue;let value=match[1];if(value.startsWith('"')&&value.endsWith('"')){try{value=JSON.parse(value)}catch{value=value.slice(1,-1)}}result[key]=value}return result}
function quote(value:string){return JSON.stringify(value)}
function validate(key:SettingKey,value:string){if(key==="WAZUH_SSH_PORT"&&value&&(!/^\d+$/.test(value)||Number(value)>65535))throw new Error("Некорректный SSH-порт");if((key==="OPENAI_BASE_URL")&&value){const url=new URL(value);if(!["http:","https:"].includes(url.protocol))throw new Error("Некорректный URL AI API")}if(value.includes("\0"))throw new Error(`Некорректное значение ${key}`)}
