// model.h

#pragma once
#ifndef NETWORK_INTERFACE_INFO_H
#define NETWORK_INTERFACE_INFO_H
#include <arpa/inet.h>
#include <net/if.h>

typedef struct _NETWORK_INTERFACE_INFO
{
  int if_index;
  char if_name[IF_NAMESIZE];
  unsigned char *ssid;
  char *ipv4_addr;
} NETWORK_INTERFACE_INFO;

typedef struct _DISCOVERED_NETWORK
{
  unsigned char *ssid;
  uint32_t frequency;
  float rssi;
  bool is_privacy;
} DISCOVERED_NETWORK;

struct trigger_results {
  int done;
  int aborted;
};

struct handler_args { // For family_handler() and nl_get_multicast_id().
  const char *group;
  int id;
};
#endif // NETWORK_INTERFACE_INFO_H
