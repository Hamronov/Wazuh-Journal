import { NextResponse } from "next/server";
import { currentSession } from "@/lib/auth";
export const runtime="nodejs"; export const dynamic="force-dynamic";
export async function GET(request:Request){const session=await currentSession(request.headers.get("cookie")||undefined);return NextResponse.json(session?{authenticated:true,user:session.user}:{authenticated:false},{headers:{"cache-control":"no-store"}})}
