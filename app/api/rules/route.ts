import { NextResponse } from "next/server";
import { runWazuhCommand } from "@/lib/wazuh";
import { requireSession } from "@/lib/auth";

export const runtime="nodejs";
export const dynamic="force-dynamic";
const path="/var/ossec/etc/rules/local_rules.xml";

export async function GET(request:Request){if(!await requireSession(request))return NextResponse.json({error:"Требуется доменная авторизация Wazuh"},{status:401});try{return NextResponse.json({xml:await runWazuhCommand(`sudo -S -p '' su -c 'cat ${path}'`)},{headers:{"cache-control":"no-store"}})}catch(error){return NextResponse.json({error:error instanceof Error?error.message:"Не удалось прочитать local_rules.xml"},{status:503})}}

export async function POST(request:Request){if(!await requireSession(request))return NextResponse.json({error:"Требуется доменная авторизация Wazuh"},{status:401});try{const {xml}=await request.json() as {xml?:unknown};if(typeof xml!=="string"||!xml.trim())throw new Error("XML не может быть пустым");const opens=(xml.match(/<group(?:\s|>)/g)||[]).length,closes=(xml.match(/<\/group>/g)||[]).length;if(opens!==closes)throw new Error("Нарушена структура XML: проверьте блоки <group>");const encoded=Buffer.from(xml,"utf8").toString("base64");await runWazuhCommand(`sudo -S -p '' su -c 'cp ${path} ${path}.bak && printf %s ${encoded} | base64 -d > ${path}.tmp && chown root:wazuh ${path}.tmp && chmod 660 ${path}.tmp && mv ${path}.tmp ${path}'`);return NextResponse.json({ok:true})}catch(error){return NextResponse.json({error:error instanceof Error?error.message:"Не удалось сохранить local_rules.xml"},{status:400})}}
