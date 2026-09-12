import parser from "@apidevtools/swagger-parser";
await parser.validate("docs/openapi.json");
console.log("OpenAPI validation passed.");
