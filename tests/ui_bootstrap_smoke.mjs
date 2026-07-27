import fs from "node:fs";
import vm from "node:vm";

const app = { innerHTML: "" };
const document = {
  querySelector: selector => selector === "#app" ? app : null,
  addEventListener: () => {},
};

const context = {
  document,
  window: { CYBER_SAMPLE: "incident sample" },
  fetch: () => new Promise(() => {}),
  setTimeout,
  clearTimeout,
  URL,
  Blob,
  console,
};

vm.runInNewContext(
  fs.readFileSync(new URL("../static/app.js", import.meta.url), "utf8"),
  context,
);

if (!app.innerHTML.includes('class="app"')) {
  throw new Error("UI did not render while optional API requests were pending.");
}

console.log(`bootstrap-render-ok ${app.innerHTML.length}`);
