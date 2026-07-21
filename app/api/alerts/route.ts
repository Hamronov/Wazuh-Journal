import { NextResponse } from "next/server";
import { queryWazuhAlerts } from "@/lib/wazuh";
import { requireSession } from "@/lib/auth";
export const runtime="nodejs"; export const dynamic="force-dynamic";
export async function GET(request:Request){if(!await requireSession(request))return NextResponse.json({error:"Требуется доменная авторизация Wazuh"},{status:401});try{const url=new URL(request.url),from=url.searchParams.get("from"),to=url.searchParams.get("to"),cursor=url.searchParams.get("cursor"),limit=Number(url.searchParams.get("limit")||500),minLevel=Number(url.searchParams.get("minLevel")||8),maxValue=url.searchParams.get("maxLevel"),maxLevel=maxValue===null?undefined:Number(maxValue),page=await queryWazuhAlerts({from,to,cursor,limit,minLevel,maxLevel});return NextResponse.json({...page,updatedAt:new Date().toISOString()},{headers:{"cache-control":"no-store"}})}catch(error){return NextResponse.json({error:error instanceof Error?error.message:"Ошибка Wazuh"},{status:503})}}
