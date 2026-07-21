import { NextResponse } from "next/server";
import { publicSettings, saveLocalSettings } from "@/lib/local-settings";
import { requireSession } from "@/lib/auth";
export const runtime="nodejs"; export const dynamic="force-dynamic";
export async function GET(request:Request){if(!await requireSession(request))return NextResponse.json({error:"Требуется доменная авторизация Wazuh"},{status:401});return NextResponse.json(await publicSettings(),{headers:{"cache-control":"no-store"}})}
export async function POST(request:Request){if(!await requireSession(request))return NextResponse.json({error:"Требуется доменная авторизация Wazuh"},{status:401});try{const input=await request.json();if(!input||typeof input!=="object")throw new Error("Некорректные настройки");await saveLocalSettings(input);return NextResponse.json({ok:true})}catch(error){return NextResponse.json({error:error instanceof Error?error.message:"Ошибка сохранения"},{status:400})}}
