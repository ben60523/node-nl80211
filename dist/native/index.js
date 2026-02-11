import { createRequire } from 'module';
import { fileURLToPath } from "url";
import path from "path";
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const require = createRequire(import.meta.url);
const native = require(path.join(__dirname, "binding.cjs"));
export default native;
