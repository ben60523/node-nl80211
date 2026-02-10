import { createRequire } from 'module';

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

const native = require('./binding.cjs') as NativeAddon;

export default native;
