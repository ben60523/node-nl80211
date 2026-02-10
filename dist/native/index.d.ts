export type DiscoveredApInfo = {
    name: string;
    freq: number;
    rssi: number;
    privacy: boolean;
};
export type InterfaceInfo = {
    name: string;
    ssid: string;
    ip: string;
};
export interface NativeAddon {
    initNl80211(): boolean;
    getInterfaceInfo(): InterfaceInfo[];
    scanAp(dev: string): DiscoveredApInfo[];
}
declare const native: NativeAddon;
export default native;
