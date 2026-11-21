/**
 * Local preview of the login pages with the production headers (CSP, fonts) and config.
 *   npx tsx scripts/preview-pages.ts   → http://127.0.0.1:8766/ (device page), /landing, /landing-single, /choose, /error
 * IDC_START_URL / IDC_REGION / ALLOWED_ROLE_PATTERN are read like in the Lambda.
 */
import { createServer, type ServerResponse } from "node:http";
import { loadConfig } from "../lambda/config.js";
import { jsonRes, type Res } from "../lambda/http.js";
import { choosePage, devicePage, errorPage, fontAsset, htmlRes, landingPage, siteInfo } from "../lambda/pages.js";

const cfg = loadConfig({ IDC_START_URL: "https://d-1234567890.awsapps.com/start", ...process.env });
const write = (out: ServerResponse, r: Res) => {
  out.writeHead(r.status, r.headers);
  out.end(r.body === undefined ? "" : Buffer.from(r.body, r.isBase64Encoded ? "base64" : "utf8"));
};

createServer((req, out) => {
  const path = (req.url ?? "/").split("?")[0]!;
  if (path === "/poll") return write(out, jsonRes(200, { status: "pending", interval: 5 }));
  if (path === "/error") return write(out, htmlRes(400, errorPage("Unknown client. Remove and re-add the connector.")));
  const asset = fontAsset(path);
  if (asset) return write(out, asset);
  const scriptNonce = "preview";
  if (path === "/landing" || path === "/landing-single") {
    const single = path === "/landing-single" ? siteInfo(cfg) : undefined;
    const page = landingPage({ baseUrl: "https://switchboard.example.com", rolePattern: cfg.allowedRolePattern.source, scriptNonce, repoUrl: cfg.repoUrl, branding: cfg.branding, single, hosted: process.env.HOSTED_NOTICE === "on" ? cfg.repoUrl : undefined });
    return write(out, htmlRes(200, page, { scriptNonce }));
  }
  if (path === "/choose") return write(out, htmlRes(200, choosePage({ params: [["client_id", "x"]], directory: "", region: "eu-central-1", hosted: process.env.HOSTED_NOTICE === "on" ? cfg.repoUrl : undefined }), { form: true }));
  write(
    out,
    htmlRes(200, devicePage({ userCode: "KCJB-MNKV", verifyUrl: "https://example.invalid/verify", pending: "asb1.preview", interval: 5, expiresIn: 600, scriptNonce, site: siteInfo(cfg) }), { scriptNonce }),
  );
}).listen(8766, "127.0.0.1", () => console.log("http://127.0.0.1:8766/"));
