#!/usr/bin/env node

const esbuild = require("esbuild");

esbuild
  .build({
    entryPoints: ["node_modules/qr-code-styling/lib/qr-code-styling.js"],
    bundle: true,
    format: "esm",
    outfile: "SSO-Auth/Views/qr-code-styling.esm.js",
    minify: true,
    platform: "browser",
    globalName: "QRCodeStyling",
  })
  .catch(() => process.exit(1));
