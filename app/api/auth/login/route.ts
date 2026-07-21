import { NextResponse } from "next/server";
import { authenticateWazuhUser } from "@/lib/auth";
export const runtime="nodejs"; export const dynamic="force-dynamic";
export async function POST(request:Request){try{const body=await request.json() as {username?:unknown;password?:unknown};const result=await authenticateWazuhUser(typeof body.username==="string"?body.username:"",typeof body.password==="string"?body.password:"");const response=NextResponse.json({ok:true,user:result.session.user});response.headers.set("set-cookie",result.cookie);return response}catch(error){return NextResponse.json({error:error instanceof Error?error.message:"Доменная авторизация не пройдена"},{status:401})}}
