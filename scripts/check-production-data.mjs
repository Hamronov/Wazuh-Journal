import { readFile, readdir } from "node:fs/promises";
import { extname, join } from "node:path";

const roots=["app","lib"], forbidden=[[109,111,99,107],[100,101,109,111],[102,105,120,116,117,114,101],[1076,1077,1084,1086,1085,1089,1090,1088,1072,1094]].map(codes=>String.fromCharCode(...codes));
async function files(dir){const result=[];for(const entry of await readdir(dir,{withFileTypes:true})){const path=join(dir,entry.name);if(entry.isDirectory())result.push(...await files(path));else result.push(path)}return result;}
const sourceFiles=(await Promise.all(roots.map(files))).flat().filter(file=>[".ts",".tsx"].includes(extname(file)));
const violations=[];
for(const file of sourceFiles){const text=(await readFile(file,"utf8")).toLowerCase();for(const word of forbidden)if(text.includes(word))violations.push(`${file}: запрещённый маркер ${word}`);}
if(violations.length){console.error(violations.join("\n"));process.exit(1)}
console.log("Production-data check passed");
