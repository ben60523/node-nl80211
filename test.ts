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
