#include <stdint.h>
#ifndef HEADER_H
#define HEADER_H

#endif // 802HEADER_H

#define CHANNEL_STANDARD 2412
#define BEACONS_TYPE 0x0080
#define DATA_TYPE 0x0800

typedef struct ieee80211_radiotap_header {
    uint8_t it_version;
    uint8_t it_pad;
    uint16_t it_len;
    uint32_t it_present;
}radiotap;

typedef struct alfa_header {
    uint32_t af_present;
    uint32_t af_null1;
    uint32_t af_mac_timestamp1;
    uint32_t af_mac_timestamp2;
    uint8_t af_flag;
    uint8_t af_rate;
    uint16_t af_fre;
    uint16_t af_channelflag;
    char af_sig1;
    uint8_t af_null2;
    uint16_t af_RXfalg;
    char af_sig2;
    uint8_t af_antenna;
}alfa;

typedef struct beacon_header {
    uint16_t type_subtype;
    uint16_t duration;
    uint8_t d_addr[6];
    uint8_t s_addr[6];
    uint8_t bssid[6];
    uint16_t fragment;
}beacons;

typedef struct fixed_wireless_header {
    uint32_t timestamp1;
    uint32_t timestamp2;
    uint16_t interval;
    uint16_t capabilities;
}fixed_header;

struct data {
    uint8_t essid_len;
    char pwr;
    uint8_t beacons;
    uint8_t bssid[6];
    uint8_t channel;
    uint8_t encrypt;
    uint8_t essid[6];
    uint8_t null[7];
};

