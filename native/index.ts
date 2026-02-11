import { createRequire } from 'module';
import { fileURLToPath } from "url";
import path from "path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const require = createRequire(import.meta.url);

export type DiscoveredApInfo = {
  name: string;
  freq: number;
  rssi: number;
  privacy: boolean;
}

export type InterfaceInfo = {
  name: string;
  ssid: string;
  ip: string;
}

export interface NativeAddon {
  initNl80211(): boolean;
  getInterfaceInfo(): InterfaceInfo[];
  scanAp(dev: string): DiscoveredApInfo[];
  // connectAp(dev: string, ssid: string, psk: string): boolean;
}

const native = require(path.join(__dirname, "binding.cjs")) as NativeAddon;

export default native;
