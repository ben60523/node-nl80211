import native from '../native/index.js';
import { DiscoveredApInfo } from '../native/index.js';

let tmp_ap_list: DiscoveredApInfo[] = []

export function init() {
  try {
    const res = native.initNl80211();
    return res;
  } catch (e) {
    return false;
  }
}

export function scanAp(dev: string) {
  try {
    tmp_ap_list = native.scanAp(dev);
  } catch(e) {
    console.warn(e);
  } finally {
    return tmp_ap_list;
  }
}

export function getInterfaceInfo() {
  return native.getInterfaceInfo();
}

// export function connectAp(dev: string, ssid: string, psk: string) {
//   return native.connectAp(dev, ssid, psk);
// }
