import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const native = require('./binding.cjs');
export default native;
