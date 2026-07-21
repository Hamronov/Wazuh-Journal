import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("ships English-first interface with Russian localization", async () => {
  const [page, layout, license] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/layout.tsx", import.meta.url), "utf8"),
    readFile(new URL("../LICENSE", import.meta.url), "utf8"),
  ]);
  assert.match(layout, /<html lang="en">/);
  assert.match(layout, /Wazuh Journal — SOC alert feed/);
  assert.match(page, /useState<Language>\("en"\)/);
  assert.match(page, />EN<\/button>/);
  assert.match(page, />RU<\/button>/);
  assert.match(page, /tr\("Feed", "Лента"\)/);
  assert.match(page, /localStorage\.setItem\("wazuh-language", language\)/);
  assert.match(license, /Commercial use is prohibited/);
});
