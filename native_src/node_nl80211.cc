// node_nl80211.cc

#include <cstring>
#include <ifaddrs.h>
#include <linux/nl80211.h>
#include <map>
#include <napi.h>
#include <netlink/errno.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/netlink.h>
#include <vector>

#include "model.h"

using namespace std;

static nl_sock *nl_socket = nullptr;
static int nl80211_id = -1;
static bool is_initialized = false;
static vector<NETWORK_INTERFACE_INFO> interfaces;
static vector<DISCOVERED_NETWORK> discovered_ap_list;
static struct nla_policy bss_policy[NL80211_BSS_MAX + 1];

static void init_bss_policy(void) {
  memset(bss_policy, 0, sizeof(bss_policy));
  bss_policy[NL80211_BSS_TSF].type = NLA_U64;
  bss_policy[NL80211_BSS_FREQUENCY].type = NLA_U32;
  bss_policy[NL80211_BSS_BEACON_INTERVAL].type = NLA_U16;
  bss_policy[NL80211_BSS_CAPABILITY].type = NLA_U16;
  bss_policy[NL80211_BSS_SIGNAL_MBM].type = NLA_S32;
  bss_policy[NL80211_BSS_SIGNAL_UNSPEC].type = NLA_U8;
  bss_policy[NL80211_BSS_STATUS].type = NLA_U32;
  bss_policy[NL80211_BSS_SEEN_MS_AGO].type = NLA_U32;
  bss_policy[NL80211_BSS_INFORMATION_ELEMENTS].type = NLA_S8;
}

static int interface_handler(struct nl_msg *msg, void *arg) {
  struct gen1msghdr *gnlh = (gen1msghdr *)nlmsg_data(nlmsg_hdr(msg));
  struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];
  static struct nla_policy policy[NL80211_ATTR_MAX + 1] = {
      0}; // Initialize all to zero
  char ifname[IF_NAMESIZE];
  nla_parse(tb_msg, NL80211_ATTR_MAX,
            genlmsg_attrdata((const genlmsghdr *)gnlh, 0),
            genlmsg_attrlen((const genlmsghdr *)gnlh, 0), policy);
  NETWORK_INTERFACE_INFO iface_info;
  if (tb_msg[NL80211_ATTR_IFINDEX]) {
    int ifindex = nla_get_u32(tb_msg[NL80211_ATTR_IFINDEX]);
    if (if_indextoname(ifindex, ifname)) {
      iface_info.if_index = ifindex;
      strncpy(iface_info.if_name, ifname, IF_NAMESIZE);
    } else {
      return NL_OK;
    }
  } else {
    return NL_OK;
  }
  if (tb_msg[NL80211_ATTR_SSID]) {
    int len = nla_len(tb_msg[NL80211_ATTR_SSID]);
    unsigned char *data = (unsigned char *)nla_data(tb_msg[NL80211_ATTR_SSID]);
    iface_info.ssid = (unsigned char *)malloc(len + 1);
    memcpy(iface_info.ssid, data, len);
    iface_info.ssid[len] = '\0'; // Null-terminate the SSID string
    iface_info.ipv4_addr = (char *)malloc(sizeof(INET_ADDRSTRLEN));
    struct ifaddrs *ifaddr;
    if (getifaddrs(&ifaddr) == -1) {
      perror("getifaddrs");
      return NL_OK;
    }
    for (ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
      if (!ifa->ifa_addr) {
        continue;
      }
      if (strcmp(ifa->ifa_name, ifname) != 0) {
        continue;
      }
      if (ifa->ifa_addr->sa_family == AF_INET) {
        struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
        inet_ntop(AF_INET, &(sa->sin_addr), iface_info.ipv4_addr,
                  INET_ADDRSTRLEN);
        break;
      }
    }
    freeifaddrs(ifaddr);
  } else {
    iface_info.ssid = nullptr;
    iface_info.ipv4_addr = nullptr;
  }

  interfaces.push_back(iface_info);

  return NL_OK;
}

Napi::Boolean InitNl80211(const Napi::CallbackInfo &info) {
  Napi::Env env = info.Env();

  nl_socket = nl_socket_alloc();
  if (!nl_socket) {
    Napi::Error::New(env, "Failed to allocate netlink socket")
        .ThrowAsJavaScriptException();
    return Napi::Boolean::New(env, false);
  }

  if (genl_connect(nl_socket)) {
    nl_socket_free(nl_socket);
    nl_socket = nullptr;
    Napi::Error::New(env, "Failed to connect to generic netlink")
        .ThrowAsJavaScriptException();
    return Napi::Boolean::New(env, false);
  }

  nl80211_id = genl_ctrl_resolve(nl_socket, "nl80211");
  if (nl80211_id < 0) {
    nl_socket_free(nl_socket);
    nl_socket = nullptr;
    Napi::Error::New(env, "nl80211 not found").ThrowAsJavaScriptException();
    return Napi::Boolean::New(env, false);
  }
  is_initialized = true;
  return Napi::Boolean::New(env, true);
}

Napi::Boolean IsNl80211Initialized(const Napi::CallbackInfo &info) {
  Napi::Env env = info.Env();
  return Napi::Boolean::New(env, is_initialized);
}

Napi::Boolean FreeNl80211(const Napi::CallbackInfo &info) {
  Napi::Env env = info.Env();
  nl_close(nl_socket);
  if (nl_socket) {
    nl_socket_free(nl_socket);
  }
  nl80211_id = -1;
  is_initialized = false;
  return Napi::Boolean::New(env, true);
}

Napi::Value GetInterfacesInfo(const Napi::CallbackInfo &info) {
  Napi::Env env = info.Env();

  if (!is_initialized) {
    Napi::Error::New(env, "nl80211 is not initialized")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  // Implementation to get interfaces info goes here
  struct nl_msg *msg = nlmsg_alloc();
  if (!msg) {
    Napi::Error::New(env, "Failed to allocate netlink message")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  if (interfaces.size() > 0) {
    interfaces.clear();
  }
  genlmsg_put(msg, 0, 0, nl80211_id, 0, NLM_F_DUMP, NL80211_CMD_GET_INTERFACE,
              0);
  nl_socket_modify_cb(nl_socket, NL_CB_VALID, NL_CB_CUSTOM, interface_handler,
                      NULL);
  int ret = nl_send_auto(nl_socket, msg);
  if (ret < 0) {
    nlmsg_free(msg);
    Napi::Error::New(env, "Failed to send netlink message")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  nlmsg_free(msg);
  ret = nl_recvmsgs_default(nl_socket);
  if (ret < 0) {
    Napi::Error::New(env, nl_geterror(-ret)).ThrowAsJavaScriptException();
    return env.Null();
  }
  if (interfaces.size() > 0) {
    Napi::Array ifaceList = Napi::Array::New(env, interfaces.size());
    vector<NETWORK_INTERFACE_INFO>::iterator begin = interfaces.begin();
    vector<NETWORK_INTERFACE_INFO>::iterator end = interfaces.end();
    vector<NETWORK_INTERFACE_INFO>::iterator it;
    int nb_inteface = 0;
    for (it = begin; it != end; it++) {
      Napi::Object obj = Napi::Object::New(env);
      obj.Set("index", Napi::Number::New(env, it->if_index));
      obj.Set("name", Napi::String::New(env, it->if_name));
      if (it->ssid != nullptr) {
        obj.Set("ssid", Napi::String::New(env, (char *)it->ssid));
        obj.Set("ip", Napi::String::New(env, it->ipv4_addr));
      } else {
        obj.Set("ssid", env.Null());
        obj.Set("ip", env.Null());
      }
      ifaceList.Set(nb_inteface, obj);
      nb_inteface++;
    }
    return ifaceList;
  }
  return env.Null(); // Placeholder
}

static int scan_error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err,
                              void *arg) {
  int *ret = (int *)arg;
  *ret = err->error;
  return NL_STOP;
}

static int scan_finish_handler(struct nl_msg *msg, void *arg) {
  int *ret = (int *)arg;
  *ret = 0;
  return NL_SKIP;
}

static int scan_ack_handler(struct nl_msg *msg, void *arg) {
  int *ret = (int *)arg;
  *ret = 0;
  return NL_STOP;
}

static int scan_no_seq_check(struct nl_msg *msg, void *arg) { return NL_OK; }

static int scan_family_handler(struct nl_msg *msg, void *arg) {
  struct handler_args *grp = (handler_args *)arg;
  struct nlattr *tb[CTRL_ATTR_MAX + 1];
  struct genlmsghdr *gnlh = (genlmsghdr *)nlmsg_data(nlmsg_hdr(msg));
  struct nlattr *mcgrp;
  int rem_mcgrp;
  nla_parse(tb, CTRL_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
            genlmsg_attrlen(gnlh, 0), NULL);
  if (!tb[CTRL_ATTR_MCAST_GROUPS]) {
    return NL_STOP;
  }
  // This is a loop
  nla_for_each_nested(mcgrp, tb[CTRL_ATTR_MCAST_GROUPS], rem_mcgrp) {
    struct nlattr *tb_mcgrp[CTRL_ATTR_MCAST_GRP_MAX + 1];
    nla_parse(tb_mcgrp, CTRL_ATTR_MCAST_GRP_MAX, (nlattr *)nla_data(mcgrp),
              nla_len(mcgrp), NULL);
    if (!tb_mcgrp[CTRL_ATTR_MCAST_GRP_NAME] ||
        !tb_mcgrp[CTRL_ATTR_MCAST_GRP_ID]) {
      continue;
    }
    if (strncmp((const char *)nla_data(tb_mcgrp[CTRL_ATTR_MCAST_GRP_NAME]),
                grp->group, nla_len(tb_mcgrp[CTRL_ATTR_MCAST_GRP_NAME]))) {
      continue;
    }
    grp->id = nla_get_u32(tb_mcgrp[CTRL_ATTR_MCAST_GRP_ID]);
    break;
  }
  return NL_SKIP;
}

static int scan_callback_trigger(struct nl_msg *msg, void *arg) {
  struct genlmsghdr *gnlh = (genlmsghdr *)nlmsg_data(nlmsg_hdr(msg));
  struct trigger_results *result = (trigger_results *)arg;
  if (gnlh->cmd == NL80211_CMD_SCAN_ABORTED) {
    printf("[Warn]: NL80211_CMD_SCAN_ABORTED\n");
    result->aborted = 1;
    result->done = 1;
  } else if (gnlh->cmd == NL80211_CMD_NEW_SCAN_RESULTS) {
    result->done = 1;
    result->aborted = 0;
  }
  return NL_SKIP;
}

static int scan_callback_dump(struct nl_msg *msg, void *arg) {
  struct genlmsghdr *gnlh = (genlmsghdr *)nlmsg_data(nlmsg_hdr(msg));
  char mac_addr[20];
  struct nlattr *tb[NL80211_ATTR_MAX + 1];
  struct nlattr *bss[NL80211_BSS_MAX + 1];
  init_bss_policy();
  nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
            genlmsg_attrlen(gnlh, 0), NULL);
  if (!tb[NL80211_ATTR_BSS]) {
    // bss info missing
    return NL_SKIP;
  }
  if (nla_parse_nested(bss, NL80211_BSS_MAX, tb[NL80211_ATTR_BSS],
                       bss_policy)) {
    // failed to parse nested attributes
    return NL_SKIP;
  }
  if (!bss[NL80211_BSS_BSSID]) {
    return NL_SKIP;
  }
  if (!bss[NL80211_BSS_INFORMATION_ELEMENTS]) {
    return NL_SKIP;
  }
  // ie: Information Element
  DISCOVERED_NETWORK ap;
  const unsigned char *ie =
      (unsigned char *)nla_data(bss[NL80211_BSS_INFORMATION_ELEMENTS]);
  int ie_len = nla_len(bss[NL80211_BSS_INFORMATION_ELEMENTS]);
  ap.is_privacy = false;
  while (ie_len >= 2 && ie_len >= ie[1]) {
    uint8_t id = ie[0];
    uint8_t len = ie[1];
    if ((len + 2) > ie_len) {
      break;
    }
    switch (id) {
    case 0: // SSID
      ap.ssid = (unsigned char *)malloc(len);
      memcpy(ap.ssid, ie + 2, len);
      ap.ssid[len] = '\0';
      break;
    case 48:
      // WPA2/WPA3
      ap.is_privacy = true;
      break;
    case 221:
      // WPA1/WPS IE
      if (len >= 4 && memcmp(ie + 2, "\x00\x50\xF2\x01", 4) == 0) {
        ap.is_privacy = true;
      } else if (len >= 4 && memcmp(ie + 2, "\x00\x50\xF2\x04", 4) == 0) {
        ap.is_privacy = true;
      }
      break;
    }
    ie_len -= ie[1] + 2;
    ie += ie[1] + 2;
  }
  if (ap.ssid == nullptr) {
    return NL_SKIP;
  }
  if (strcmp((const char *)ap.ssid, "\0") == 0) {
    return NL_SKIP;
  }
  if (!bss[NL80211_BSS_FREQUENCY]) {
    return NL_SKIP;
  }
  ap.frequency = nla_get_u32(bss[NL80211_BSS_FREQUENCY]);
  if (!bss[NL80211_BSS_SIGNAL_MBM]) {
    return NL_SKIP;
  }
  ap.rssi = nla_get_s32(bss[NL80211_BSS_SIGNAL_MBM]) / 100.0f;
  discovered_ap_list.push_back(ap);
  return NL_OK;
}

int nl_get_multicast_id(struct nl_sock *sock, const char *family,
                        const char *group) {
  struct nl_msg *msg;
  struct nl_cb *cb;
  int ret, ctrlId;
  struct handler_args grp = {.group = group, .id = -ENOENT};
  msg = nlmsg_alloc();
  if (!msg) {
    return -ENOMEM;
  }
  cb = nl_cb_alloc(NL_CB_DEFAULT);
  if (!cb) {
    ret = -ENOMEM;
    goto out_fail_cb;
  }
  ctrlId = genl_ctrl_resolve(sock, "nlctrl");
  genlmsg_put(msg, 0, 0, ctrlId, 0, 0, CTRL_CMD_GETFAMILY, 0);
  ret = -ENOBUFS;
  NLA_PUT_STRING(msg, CTRL_ATTR_FAMILY_NAME, family);
  ret = nl_send_auto_complete(sock, msg);
  if (ret < 0) {
    goto out;
  }
  ret = 1;
  nl_cb_err(cb, NL_CB_CUSTOM, scan_error_handler, &ret);
  nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, scan_ack_handler, &ret);
  nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, scan_family_handler, &grp);

  while (ret > 0) {
    nl_recvmsgs(sock, cb);
  }
  if (ret == 0) {
    ret = grp.id;
  }
nla_put_failure:
out:
  nl_cb_put(cb);
out_fail_cb:
  nlmsg_free(msg);
  return ret;
}

int do_scan_trigger(struct nl_sock *socket, int if_index, int driver_id) {
  // Starts the scan and waits for it to finish.
  struct trigger_results result = {.done = 0, .aborted = 0};
  struct nl_msg *msg;
  struct nl_cb *cb;
  struct nl_msg *ssids_to_scan;
  int err;
  int ret;
  int mcid = nl_get_multicast_id(socket, "nl80211", "scan");
  // Without this, callback_trigger() won't be called
  nl_socket_add_memberships(socket, mcid);
  // Allocate the message and callback handler
  msg = nlmsg_alloc();
  if (!msg) {
    return -ENOMEM;
  }
  ssids_to_scan = nlmsg_alloc();
  if (!ssids_to_scan) {
    return -ENOMEM;
  }
  cb = nl_cb_alloc(NL_CB_DEFAULT);
  if (!cb) {
    nlmsg_free(msg);
    nlmsg_free(ssids_to_scan);
    return -ENOMEM;
  }
  // Setup the messages and callback handler.
  genlmsg_put(msg, 0, 0, driver_id, 0, 0, NL80211_CMD_TRIGGER_SCAN, 0);
  nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);
  nla_put(ssids_to_scan, 1, 0, "");
  nla_put_nested(msg, NL80211_ATTR_SCAN_SSIDS, ssids_to_scan);
  nlmsg_free(ssids_to_scan);
  nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, scan_callback_trigger, &result);
  nl_cb_err(cb, NL_CB_CUSTOM, scan_error_handler, &err);
  nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, scan_finish_handler, &err);
  nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, scan_ack_handler, &err);
  nl_cb_set(cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, scan_no_seq_check, NULL);

  // Send NL80211_CMD_TRIGGER_SCAN to start the scan. The kernel may reply with
  // NL80211_CMD_NEW_SCAN_RESULTS on success or NL80211_CMD_SCAN_ABORTED if
  // another scan was started by another process.
  err = 1;
  ret = nl_send_auto(socket, msg); // Send the message.
  printf("Waiting for scan to complete...\n");
  while (err > 0) {
    ret = nl_recvmsgs(
        socket,
        cb); // First wait for ack_handler(). This helps with basic errors.
  }
  if (err < 0) {
    printf("WARNING: err has a value of %d.\n", err);
  }
  if (ret < 0) {
    printf("ERROR: nl_recvmsgs() returned %d (%s).\n", ret, nl_geterror(-ret));
    return ret;
  }
  while (!result.done)
    nl_recvmsgs(socket, cb); // Now wait until the scan is done or aborted.
  if (result.aborted) {
    printf("ERROR: Kernel aborted scan.\n");
    return 1;
  }

  // Cleanup.
  nlmsg_free(msg);
  nl_cb_put(cb);
  nl_socket_drop_membership(socket, mcid); // No longer need this.
  return 0;
}

Napi::Value ScanAp(const Napi::CallbackInfo &info) {
  Napi::Env env = info.Env();
  if (!is_initialized) {
    Napi::Error::New(env, "nl80211 is not initialized")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  if (info.Length() == 0) {
    Napi::Error::New(env, "The interface name is required")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  std::string iface = info[0].As<Napi::String>();
  int if_index = if_nametoindex(iface.c_str());
  if (if_index == 0) {
    char errMsg[20];
    sprintf(errMsg, "%s cannot be found", iface.c_str());
    Napi::Error::New(env, errMsg).ThrowAsJavaScriptException();
    return env.Null();
  }
  if (discovered_ap_list.size() > 0) {
    discovered_ap_list.clear();
  }
  int err = do_scan_trigger(nl_socket, if_index, nl80211_id);
  if (err != 0) {
    Napi::Error::New(env, nl_geterror(err)).ThrowAsJavaScriptException();
    return env.Null();
  }
  struct nl_msg *msg = nlmsg_alloc();
  genlmsg_put(msg, 0, 0, nl80211_id, 0, NLM_F_DUMP, NL80211_CMD_GET_SCAN, 0);
  nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);
  nl_socket_modify_cb(nl_socket, NL_CB_VALID, NL_CB_CUSTOM, scan_callback_dump,
                      NULL);
  int ret = nl_send_auto(nl_socket, msg);
  if (ret < 0) {
    nlmsg_free(msg);
    Napi::Error::New(env, nl_geterror(-ret));
    return env.Null();
  }
  ret = nl_recvmsgs_default(nl_socket);
  nlmsg_free(msg);
  if (ret < 0) {
    Napi::Error::New(env, nl_geterror(-ret));
    return env.Null();
  }
  printf("#### Ready to output discovered APs ####\n");
  if (discovered_ap_list.size() <= 0) {
    return Napi::Array::New(env);
  }

  std::map<std::string, DISCOVERED_NETWORK> minMap;
  for (const DISCOVERED_NETWORK &ap : discovered_ap_list) {
    std::string key = std::string(reinterpret_cast<char*>(ap.ssid));
    if (minMap.find(key) == minMap.end() ||
        ap.rssi < minMap.at(key).rssi) {
      minMap[key] = ap;
    }
  }

  std::vector<DISCOVERED_NETWORK> result;
  for (auto const &[key, val] : minMap) {
    result.push_back(val);
  }
  Napi::Array apList = Napi::Array::New(env, result.size());
  vector<DISCOVERED_NETWORK>::iterator begin = result.begin();
  vector<DISCOVERED_NETWORK>::iterator end = result.end();
  vector<DISCOVERED_NETWORK>::iterator it;

  int nb_ap = 0;
  for (it = begin; it != end; it++) {
    Napi::Object obj = Napi::Object::New(env);
    obj.Set("ssid", Napi::String::New(env, (char *)it->ssid));
    obj.Set("freq", Napi::Number::New(env, it->frequency));
    obj.Set("rssi", Napi::Number::New(env, it->rssi));
    obj.Set("is_privacy", Napi::Boolean::New(env, it->is_privacy));
    apList.Set(nb_ap, obj);
    nb_ap++;
  }
  return apList;
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  exports.Set(Napi::String::New(env, "initNl80211"),
              Napi::Function::New(env, InitNl80211));
  exports.Set(Napi::String::New(env, "isNl80211Initialized"),
              Napi::Function::New(env, IsNl80211Initialized));
  exports.Set(Napi::String::New(env, "getInterfaceInfo"),
              Napi::Function::New(env, GetInterfacesInfo));
  exports.Set(Napi::String::New(env, "scanAp"),
              Napi::Function::New(env, ScanAp));
  return exports;
}

NODE_API_MODULE(NODE_GYP_MODULE_NAME, Init);
