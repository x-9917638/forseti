// Modify tauri-specta bindings to use objects as args
import { Project, SyntaxKind } from "ts-morph";

const GENERATED_FILE = "../src/lib/bindings.ts";

const project = new Project({
  tsConfigFilePath: "../tsconfig.json",
});

const sourceFile = project.addSourceFileAtPath(GENERATED_FILE);

// Find the "commands" object
const commandsObj = sourceFile
  .getVariableDeclaration("commands")
  ?.getInitializerIfKind(SyntaxKind.ObjectLiteralExpression);

if (!commandsObj) {
  console.error("Could not find 'commands' object in the file!");
  process.exit(1);
}

// Iterate over each function in commands
commandsObj.getProperties().forEach((prop) => {
  if (!prop.isKind(SyntaxKind.MethodDeclaration)) return;

  const method = prop.asKindOrThrow(SyntaxKind.MethodDeclaration);
  const params = method.getParameters();

  // Skip functions with 0 or 1 parameter
  if (params.length <= 1) return;

  // Collect parameter names and types
  const paramNames: string[] = [];
  const paramTypes: string[] = [];

  params.forEach((p) => {
    paramNames.push(p.getName());
    paramTypes.push(p.getTypeNode()?.getText() || "any");
  });

  // Build object type string
  const objType = `{ ${paramNames.map((n, i) => `${n}: ${paramTypes[i]}`).join("; ")} }`;

  // Replace parameters with a single destructured object
  method.getParameters().forEach((p) => p.remove());
  method.addParameter({
    name: `{ ${paramNames.join(", ")} }`,
    type: objType,
  });
});

sourceFile.saveSync();
