
# node-nl80211

A Node.js library for interacting with nl80211 (netlink wireless) Linux kernel interface.

## Installation

```bash
npm install node-nl80211
```

## Features

- Wireless device management
- Network interface configuration
- nl80211 netlink protocol support

## Usage

```javascript
import { init, getInterfaceInfo, scanAp } from './dist/src/index.js';

init();

const iface = getInterfaceInfo();
console.log(iface);
const { name } = iface[1];
if (1) {
  try {
    const ap_list = scanAp(name);
    console.log(ap_list);
  } catch (e) {
    console.error(e);
  }
}
```

## API

### `init()`
Initialize driver

### `getInterfaceInfo()`
Gets all Wi-Fi interfaces information.
```
{
  index,
  name,
  ssid,
  ip,
}
```
### `scanAp(interface_name)`
Scan nearby APs with the specific Wi-Fi interfaces
```
{
  ssid,
  freq,
  rssi,
  is_privacy
}
```

## Requirements

- Node.js >= 12.0
- Linux kernel with nl80211 support

## License

MIT

## Contributing

Contributions welcome. Please submit pull requests or issues.
