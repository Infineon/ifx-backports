// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2010 Broadcom Corporation
 */

/* Toplevel file. Relies on dhd_linux.c to send commands to the dongle. */

#include <linux/kernel.h>
#include <linux/etherdevice.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/bitfield.h>
#include <net/cfg80211.h>
#include <net/netlink.h>
#include <uapi/linux/if_arp.h>

#include <brcmu_utils.h>
#include <defs.h>
#include <brcmu_wifi.h>
#include <brcm_hw_ids.h>
#include "core.h"
#include "debug.h"
#include "tracepoint.h"
#include "fwil_types.h"
#include "p2p.h"
#include "btcoex.h"
#include "pno.h"
#include "fwsignal.h"
#include "cfg80211.h"
#include "feature.h"
#include "fwil.h"
#include "proto.h"
#include "vendor.h"
#include "vendor_ifx.h"
#include "bus.h"
#include "common.h"
#include "twt.h"

#define BRCMF_SCAN_IE_LEN_MAX		2048

#define WPA_OUI				"\x00\x50\xF2"	/* WPA OUI */
#define WPA_OUI_TYPE			1
#define RSN_OUI				"\x00\x0F\xAC"	/* RSN OUI */
#define	WME_OUI_TYPE			2
#define WPS_OUI_TYPE			4
#define WFA_OUI_TYPE_MBO_OCE		0x16

#define VS_IE_FIXED_HDR_LEN		6
#define WPA_IE_VERSION_LEN		2
#define WPA_IE_MIN_OUI_LEN		4
#define WPA_IE_SUITE_COUNT_LEN		2

#define WPA_CIPHER_NONE			0	/* None */
#define WPA_CIPHER_WEP_40		1	/* WEP (40-bit) */
#define WPA_CIPHER_TKIP			2	/* TKIP: default for WPA */
#define WPA_CIPHER_AES_CCM		4	/* AES (CCM) */
#define WPA_CIPHER_WEP_104		5	/* WEP (104-bit) */

#define RSN_AKM_NONE			0	/* None (IBSS) */
#define RSN_AKM_UNSPECIFIED		1	/* Over 802.1x */
#define RSN_AKM_PSK			2	/* Pre-shared Key */
#define RSN_AKM_SHA256_1X		5	/* SHA256, 802.1X */
#define RSN_AKM_SHA256_PSK		6	/* SHA256, Pre-shared Key */
#define RSN_AKM_SAE			8	/* SAE */
#define RSN_AKM_OWE			18	/* OWE */
#define RSN_CAP_LEN			2	/* Length of RSN capabilities */
#define RSN_CAP_PTK_REPLAY_CNTR_MASK	(BIT(2) | BIT(3))
#define RSN_CAP_MFPR_MASK		BIT(6)
#define RSN_CAP_MFPC_MASK		BIT(7)
#define RSN_PMKID_COUNT_LEN		2

#define DPP_AKM_SUITE_TYPE		2
#define WLAN_AKM_SUITE_DPP		SUITE(WLAN_OUI_WFA, DPP_AKM_SUITE_TYPE)

#define VNDR_IE_CMD_LEN			4	/* length of the set command
						 * string :"add", "del" (+ NUL)
						 */
#define VNDR_IE_COUNT_OFFSET		4
#define VNDR_IE_PKTFLAG_OFFSET		8
#define VNDR_IE_VSIE_OFFSET		12
#define VNDR_IE_HDR_SIZE		12
#define VNDR_IE_PARSE_LIMIT		5

#define	DOT11_MGMT_HDR_LEN		24	/* d11 management header len */
#define	DOT11_BCN_PRB_FIXED_LEN		12	/* beacon/probe fixed length */

#define BRCMF_SCAN_JOIN_ACTIVE_DWELL_TIME_MS		320
#define BRCMF_SCAN_JOIN_PASSIVE_DWELL_TIME_MS		400
#define BRCMF_SCAN_JOIN_ACTIVE_DWELL_TIME_MS_6E		80
#define BRCMF_SCAN_JOIN_PASSIVE_DWELL_TIME_MS_6E	130
#define BRCMF_SCAN_JOIN_PROBE_INTERVAL_MS	20

#define BRCMF_SCAN_CHANNEL_TIME		40
#define BRCMF_SCAN_UNASSOC_TIME		40
#define BRCMF_SCAN_PASSIVE_TIME		120

#define BRCMF_ND_INFO_TIMEOUT		msecs_to_jiffies(2000)

#define MGMT_AUTH_FRAME_DWELL_TIME	4000
#define MGMT_AUTH_FRAME_WAIT_TIME	(MGMT_AUTH_FRAME_DWELL_TIME + 100)

/* Dump obss definitions */
#define ACS_MSRMNT_DELAY		80
#define CHAN_NOISE_DUMMY		(-80)
#define OBSS_TOKEN_IDX			15
#define IBSS_TOKEN_IDX			15
#define TX_TOKEN_IDX			14
#define CTG_TOKEN_IDX			13
#define PKT_TOKEN_IDX			15
#define IDLE_TOKEN_IDX			12

#define BRCMF_ASSOC_PARAMS_FIXED_SIZE \
	(sizeof(struct brcmf_assoc_params_le) - sizeof(u16))

#define BRCMF_MAX_CHANSPEC_LIST \
	(BRCMF_DCMD_MEDLEN / sizeof(__le32) - 1)

#define BSS_MEMBERSHIP_SELECTOR_SAE_H2E_ONLY 123
#define BSS_MEMBERSHIP_SELECTOR_SET 0x80
#define SAE_H2E_ONLY_ENABLE (BSS_MEMBERSHIP_SELECTOR_SAE_H2E_ONLY | \
				BSS_MEMBERSHIP_SELECTOR_SET)

enum brcmf_pmksa_action {
	PMKSA_SET = 0,
	PMKSA_DELETE = 1
};

struct brcmf_dump_survey {
	u32 obss;
	u32 ibss;
	u32 no_ctg;
	u32 no_pckt;
	u32 tx;
	u32 idle;
};

struct cca_stats_n_flags {
	u32 msrmnt_time; /* Time for Measurement (msec) */
	u32 msrmnt_done; /* flag set when measurement complete */
	char buf[1];
};

struct cca_msrmnt_query {
	u32 msrmnt_query;
	u32 time_req;
};

enum cca_survey_config {
        CCA_SURVEY_READ_CLEAR = 1,      /* previous data only */
        CCA_SURVEY_READ = 2,            /* sum for each of data */
        CCA_SURVEY_RESET = 3,           /* Set for each of data */
};

struct cca_survey {
        u32 usecs;   /**< millisecs spent sampling this channel */
        u32 ibss;    /**< millisecs spent ibss */
        u32 obss;    /**< millisecs spent obss */
        u32 txdur;   /**< millisecs spent txdur */
        u32 noctg;   /**< millisecs spent 802.11 of unknown type */
        u32 nopkt;   /**< millisecs spent non 802.11 */
        u32 PM;      /**< usecs MAC spent in doze mode for PM */
};

struct cca_survey_req {
        u16 chanspec;    /**< Which channel? */
        u16 num_secs;        /**< How many secs worth of data */
        struct cca_survey  secs[1];  /**< Data */
        enum cca_survey_config config;     /**< enum */
};

/* algo bit vector */
#define KEY_ALGO_MASK(_algo)	(1 << (_algo))
/* version of the wl_wsec_info structure */
#define WL_WSEC_INFO_VERSION 0x01

/* start enum value for BSS properties */
#define WL_WSEC_INFO_BSS_BASE 0x0100
#define WL_WSEC_INFO_BSS_ALGOS (WL_WSEC_INFO_BSS_BASE + 6)

static bool check_vif_up(struct brcmf_cfg80211_vif *vif)
{
	if (!test_bit(BRCMF_VIF_STATUS_READY, &vif->sme_state)) {
		brcmf_dbg(INFO, "device is not ready : status (%lu)\n",
			  vif->sme_state);
		return false;
	}
	return true;
}

#define RATE_TO_BASE100KBPS(rate)   (((rate) * 10) / 2)
#define RATETAB_ENT(_rateid, _flags) \
	{                                                               \
		.bitrate        = RATE_TO_BASE100KBPS(_rateid),     \
		.hw_value       = (_rateid),                            \
		.flags          = (_flags),                             \
	}

static struct ieee80211_rate __wl_rates[] = {
	RATETAB_ENT(BRCM_RATE_1M, 0),
	RATETAB_ENT(BRCM_RATE_2M, IEEE80211_RATE_SHORT_PREAMBLE),
	RATETAB_ENT(BRCM_RATE_5M5, IEEE80211_RATE_SHORT_PREAMBLE),
	RATETAB_ENT(BRCM_RATE_11M, IEEE80211_RATE_SHORT_PREAMBLE),
	RATETAB_ENT(BRCM_RATE_6M, 0),
	RATETAB_ENT(BRCM_RATE_9M, 0),
	RATETAB_ENT(BRCM_RATE_12M, 0),
	RATETAB_ENT(BRCM_RATE_18M, 0),
	RATETAB_ENT(BRCM_RATE_24M, 0),
	RATETAB_ENT(BRCM_RATE_36M, 0),
	RATETAB_ENT(BRCM_RATE_48M, 0),
	RATETAB_ENT(BRCM_RATE_54M, 0),
};

#define wl_g_rates		(__wl_rates + 0)
#define wl_g_rates_size		ARRAY_SIZE(__wl_rates)
#define wl_a_rates		(__wl_rates + 4)
#define wl_a_rates_size		(wl_g_rates_size - 4)

#define CHAN2G(_channel, _freq) {				\
	.band			= NL80211_BAND_2GHZ,		\
	.center_freq		= (_freq),			\
	.hw_value		= (_channel),			\
	.max_antenna_gain	= 0,				\
	.max_power		= 30,				\
}

#define CHAN5G(_channel) {					\
	.band			= NL80211_BAND_5GHZ,		\
	.center_freq		= 5000 + (5 * (_channel)),	\
	.hw_value		= (_channel),			\
	.max_antenna_gain	= 0,				\
	.max_power		= 30,				\
}

#define CHAN6G(_channel) {				\
	.band			= NL80211_BAND_6GHZ,		\
	.center_freq		= 5950 + (5 * (_channel)),	\
	.hw_value		= (_channel),			\
	.max_antenna_gain	= 0,				\
	.max_power		= 30,				\
}

static struct ieee80211_channel __wl_2ghz_channels[] = {
	CHAN2G(1, 2412), CHAN2G(2, 2417), CHAN2G(3, 2422), CHAN2G(4, 2427),
	CHAN2G(5, 2432), CHAN2G(6, 2437), CHAN2G(7, 2442), CHAN2G(8, 2447),
	CHAN2G(9, 2452), CHAN2G(10, 2457), CHAN2G(11, 2462), CHAN2G(12, 2467),
	CHAN2G(13, 2472), CHAN2G(14, 2484)
};

static struct ieee80211_channel __wl_5ghz_channels[] = {
	CHAN5G(34), CHAN5G(36), CHAN5G(38), CHAN5G(40), CHAN5G(42),
	CHAN5G(44), CHAN5G(46), CHAN5G(48), CHAN5G(52), CHAN5G(56),
	CHAN5G(60), CHAN5G(64), CHAN5G(100), CHAN5G(104), CHAN5G(108),
	CHAN5G(112), CHAN5G(116), CHAN5G(120), CHAN5G(124), CHAN5G(128),
	CHAN5G(132), CHAN5G(136), CHAN5G(140), CHAN5G(144), CHAN5G(149),
	CHAN5G(153), CHAN5G(157), CHAN5G(161), CHAN5G(165)
};

static struct ieee80211_channel __wl_6ghz_channels[] = {
	CHAN6G(1), CHAN6G(5), CHAN6G(9), CHAN6G(13), CHAN6G(17),
	CHAN6G(21), CHAN6G(25), CHAN6G(29), CHAN6G(33), CHAN6G(37),
	CHAN6G(41), CHAN6G(45), CHAN6G(49), CHAN6G(53),	CHAN6G(57),
	CHAN6G(61), CHAN6G(65), CHAN6G(69), CHAN6G(73), CHAN6G(77),
	CHAN6G(81), CHAN6G(85), CHAN6G(89), CHAN6G(93), CHAN6G(97),
	CHAN6G(101), CHAN6G(105), CHAN6G(109), CHAN6G(113), CHAN6G(117),
	CHAN6G(121), CHAN6G(125), CHAN6G(129), CHAN6G(133), CHAN6G(137),
	CHAN6G(141), CHAN6G(145), CHAN6G(149), CHAN6G(153), CHAN6G(157),
	CHAN6G(161), CHAN6G(165), CHAN6G(169), CHAN6G(173), CHAN6G(177),
	CHAN6G(181), CHAN6G(185), CHAN6G(189), CHAN6G(193), CHAN6G(197),
	CHAN6G(201), CHAN6G(205), CHAN6G(209), CHAN6G(213), CHAN6G(217),
	CHAN6G(221), CHAN6G(225), CHAN6G(229), CHAN6G(233)
};

struct ieee80211_sband_iftype_data sdata[NUM_NL80211_BANDS];

/* Band templates duplicated per wiphy. The channel info
 * above is added to the band during setup.
 */
static const struct ieee80211_supported_band __wl_band_2ghz = {
	.band = NL80211_BAND_2GHZ,
	.bitrates = wl_g_rates,
	.n_bitrates = wl_g_rates_size,
};

static const struct ieee80211_supported_band __wl_band_5ghz = {
	.band = NL80211_BAND_5GHZ,
	.bitrates = wl_a_rates,
	.n_bitrates = wl_a_rates_size,
};

static struct ieee80211_supported_band __wl_band_6ghz = {
	.band = NL80211_BAND_6GHZ,
	.bitrates = wl_a_rates,
	.n_bitrates = wl_a_rates_size,
};

/* This is to override regulatory domains defined in cfg80211 module (reg.c)
 * By default world regulatory domain defined in reg.c puts the flags
 * NL80211_RRF_NO_IR for 5GHz channels (for * 36..48 and 149..165).
 * With respect to these flags, wpa_supplicant doesn't * start p2p
 * operations on 5GHz channels. All the changes in world regulatory
 * domain are to be done here.
 */
static const struct ieee80211_regdomain brcmf_regdom = {
	.n_reg_rules = 5,
	.alpha2 =  "99",
	.reg_rules = {
		/* IEEE 802.11b/g, channels 1..11 */
		REG_RULE(2412-10, 2472+10, 40, 6, 20, 0),
		/* If any */
		/* IEEE 802.11 channel 14 - Only JP enables
		 * this and for 802.11b only
		 */
		REG_RULE(2484-10, 2484+10, 20, 6, 20, 0),
		/* IEEE 802.11a, channel 36..64 */
		REG_RULE(5150-10, 5350+10, 160, 6, 20, 0),
		/* IEEE 802.11a, channel 100..165 */
		REG_RULE(5470-10, 5850+10, 160, 6, 20, 0),
		/* IEEE 802.11ax, 6E */
		REG_RULE(5935-10, 7115+10, 160, 6, 20, 0),
	}
};

/* Note: brcmf_cipher_suites is an array of int defining which cipher suites
 * are supported. A pointer to this array and the number of entries is passed
 * on to upper layers. AES_CMAC defines whether or not the driver supports MFP.
 * So the cipher suite AES_CMAC has to be the last one in the array, and when
 * device does not support MFP then the number of suites will be decreased by 4
 */
static const u32 brcmf_cipher_suites[] = {
	WLAN_CIPHER_SUITE_WEP40,
	WLAN_CIPHER_SUITE_WEP104,
	WLAN_CIPHER_SUITE_TKIP,
	WLAN_CIPHER_SUITE_CCMP,
	WLAN_CIPHER_SUITE_CCMP_256,
	WLAN_CIPHER_SUITE_GCMP,
	WLAN_CIPHER_SUITE_GCMP_256,
	/* Keep as last entry: */
	WLAN_CIPHER_SUITE_AES_CMAC,
	WLAN_CIPHER_SUITE_BIP_CMAC_256,
	WLAN_CIPHER_SUITE_BIP_GMAC_128,
	WLAN_CIPHER_SUITE_BIP_GMAC_256
};

/* Vendor specific ie. id = 221, oui and type defines exact ie */
struct brcmf_vs_tlv {
	u8 id;
	u8 len;
	u8 oui[3];
	u8 oui_type;
};

struct parsed_vndr_ie_info {
	u8 *ie_ptr;
	u32 ie_len;	/* total length including id & length field */
	struct brcmf_vs_tlv vndrie;
};

struct parsed_vndr_ies {
	u32 count;
	struct parsed_vndr_ie_info ie_info[VNDR_IE_PARSE_LIMIT];
};

struct brcmf_ext_tlv {
	u8 id;
	u8 len;
	u8 ext_id;
};

struct parsed_ext_ie_info {
	u8 *ie_ptr;
	u32 ie_len;	/* total length including id & length field */
	struct brcmf_ext_tlv ie_data;
};

struct parsed_extension_ies {
	u32 count;
	struct parsed_ext_ie_info ie_info[VNDR_IE_PARSE_LIMIT];
};

struct ie_info {
	u32 pktflag;			/* bitmask indicating which packet(s) contain this IE */
	struct brcmf_tlv ie_data;	/* IE data */
} __packed;

struct ie_buf {
	s32 iecount;			/* number of entries in the ie_list[] array */
	struct ie_info ie_list[1];	/* variable size list of ie_info_t structs */
} __packed;

struct ie_set_buffer {
	char cmd[VNDR_IE_CMD_LEN];	/* ie IOVar set command : "add" + NUL */
	struct ie_buf ie_buffer;	/* buffer containing IE list information */
} __packed;

/* flags */
#define BRCMF_ASSOC_REQ_IS_REASSOC 0x01 /* assoc req was actually a reassoc */

struct dot11_assoc_req {
	u16 capability;		/* capability information */
	u16 listen;		/* listen interval */
};

struct dot11_reassoc_req {
	u16 capability;		/* capability information */
	u16 listen;		/* listen interval */
	u8 ap[ETH_ALEN];	/* Current AP address */
};

struct dot11_assoc_resp {
	u16 capability;		/* capability information */
	u16 status;		/* status code */
	u16 aid;		/* association ID */
};

struct brcmf_owe_info_buf {
	bool with_pmkid;
	bool with_ecdh;/* if doing PMK Caching, might not have ECDH IE. */
	__le16 status_le16;/* hostapd gives status of Assoc Resp */
	u8 peer_mac[ETH_ALEN];
	u8 pmkid[WLAN_PMKID_LEN];
	u8 ecdh_ie_info[0];
};

#define WLC_E_IF_ROLE_STA		0	/* Infra STA */
#define WLC_E_IF_ROLE_AP		1	/* Access Point */

#define WL_INTERFACE_CREATE_VER_1		1
#define WL_INTERFACE_CREATE_VER_2		2
#define WL_INTERFACE_CREATE_VER_3		3
#define WL_INTERFACE_CREATE_VER_MAX		WL_INTERFACE_CREATE_VER_3

#define WL_INTERFACE_MAC_DONT_USE	0x0
#define WL_INTERFACE_MAC_USE		0x2

#define WL_INTERFACE_CREATE_STA		0x0
#define WL_INTERFACE_CREATE_AP		0x1

struct wl_interface_create_v1 {
	u16	ver;			/* structure version */
	u32	flags;			/* flags for operation */
	u8	mac_addr[ETH_ALEN];	/* MAC address */
	u32	wlc_index;		/* optional for wlc index */
};

struct wl_interface_create_v2 {
	u16	ver;			/* structure version */
	u8	pad1[2];
	u32	flags;			/* flags for operation */
	u8	mac_addr[ETH_ALEN];	/* MAC address */
	u8	iftype;			/* type of interface created */
	u8	pad2;
	u32	wlc_index;		/* optional for wlc index */
};

struct wl_interface_create_v3 {
	u16 ver;			/* structure version */
	u16 len;			/* length of structure + data */
	u16 fixed_len;			/* length of structure */
	u8 iftype;			/* type of interface created */
	u8 wlc_index;			/* optional for wlc index */
	u32 flags;			/* flags for operation */
	u8 mac_addr[ETH_ALEN];		/* MAC address */
	u8 bssid[ETH_ALEN];		/* optional for BSSID */
	u8 if_index;			/* interface index request */
	u8 pad[3];
	u8 data[];			/* Optional for specific data */
};

#define WL_IOV_OP_BSSCFG_DISABLE		0
#define WL_IOV_OP_BSSCFG_ENABLE			1
#define WL_IOV_OP_MANUAL_STA_BSSCFG_CREATE	2
#define WL_IOV_OP_MANUAL_AP_BSSCFG_CREATE	3

/* tlv used to return wl_wsec_info properties */
struct wl_wsec_info_tlv {
	u16 type;
	u16 len;	/* data length */
	u8 data[1];	/* data follows */
};

/* input/output data type for wsec_info iovar */
struct wl_wsec_info {
	u8 version; /* structure version */
	u8 pad[2];
	u8 num_tlvs;
	struct wl_wsec_info_tlv tlvs[1]; /* tlv data follows */
};

static bool brcmf_has_pmkid(const u8 *parse, u32 len, u32 *offset_in_ie);
static int brcmf_setup_wiphybands(struct brcmf_cfg80211_info *cfg);
static bool
wl_cfgoce_has_ie(const u8 *ie, const u8 **tlvs, u32 *tlvs_len,
		 const u8 *oui, u32 oui_len, u8 type);

/* Check whether the given IE looks like WFA OCE IE. */
#define wl_cfgoce_is_oce_ie(ie, tlvs, len)	\
	wl_cfgoce_has_ie(ie, tlvs, len,		\
			 (const u8 *)WFA_OUI, TLV_OUI_LEN, WFA_OUI_TYPE_MBO_OCE)

static s32
wl_set_wsec_info_algos(struct brcmf_if *ifp, u32 algos, u32 mask)
{
	struct brcmf_pub *drvr = ifp->drvr;
	s32 err = 0;
	struct wl_wsec_info *wsec_info;
	struct bcm_xtlv *wsec_info_tlv;
	u16 tlv_data_len;
	u8 tlv_data[8];
	u32 param_len;
	u8 *buf;

	brcmf_dbg(TRACE, "Enter\n");

	buf = kzalloc(sizeof(struct wl_wsec_info) + sizeof(tlv_data), GFP_KERNEL);
	if (!buf) {
		bphy_err(drvr, "unable to allocate.\n");
		return -ENOMEM;
	}

	wsec_info = (struct wl_wsec_info *)buf;
	wsec_info->version = WL_WSEC_INFO_VERSION;
	wsec_info_tlv = (struct bcm_xtlv *)(buf + offsetof(struct wl_wsec_info, tlvs));

	wsec_info->num_tlvs++;
	tlv_data_len = sizeof(tlv_data);
	memcpy(tlv_data, &algos, sizeof(algos));
	memcpy(tlv_data + sizeof(algos), &mask, sizeof(mask));

	wsec_info_tlv->id = cpu_to_le16(WL_WSEC_INFO_BSS_ALGOS);
	wsec_info_tlv->len = cpu_to_le16(tlv_data_len);
	memcpy(wsec_info_tlv->data, tlv_data, tlv_data_len);

	param_len = offsetof(struct wl_wsec_info, tlvs) +
		    offsetof(struct wl_wsec_info_tlv, data) + tlv_data_len;

	err = brcmf_fil_bsscfg_data_set(ifp, "wsec_info", buf, param_len);
	if (err)
		brcmf_err("set wsec_info_error:%d\n", err);

	kfree(buf);
	return err;
}

/* Is any of the tlvs the expected entry? If
 * not update the tlvs buffer pointer/length.
 */
static bool
wl_cfgoce_has_ie(const u8 *ie, const u8 **tlvs, u32 *tlvs_len,
		 const u8 *oui, u32 oui_len, u8 type)
{
	/* If the contents match the OUI and the type */
	if (ie[TLV_LEN_OFF] >= oui_len + 1 &&
	    !memcmp(&ie[TLV_BODY_OFF], oui, oui_len) &&
	    type == ie[TLV_BODY_OFF + oui_len]) {
		return true;
	}

	if (!tlvs)
		return false;
	/* point to the next ie */
	ie += ie[TLV_LEN_OFF] + TLV_HDR_LEN;
	/* calculate the length of the rest of the buffer */
	*tlvs_len -= (int)(ie - *tlvs);
	/* update the pointer to the start of the buffer */
	*tlvs = ie;

	return false;
}

u8 nl80211_band_to_fwil(enum nl80211_band band)
{
	switch (band) {
	case NL80211_BAND_2GHZ:
		return WLC_BAND_2G;
	case NL80211_BAND_5GHZ:
		return WLC_BAND_5G;
	case NL80211_BAND_6GHZ:
		return WLC_BAND_6G;
	default:
		WARN_ON(1);
		break;
	}
	return 0;
}

static u16 chandef_to_chanspec(struct brcmu_d11inf *d11inf,
			       struct cfg80211_chan_def *ch)
{
	struct brcmu_chan ch_inf;
	s32 primary_offset;

	brcmf_dbg(TRACE, "chandef: control %d center %d width %d\n",
		  ch->chan->center_freq, ch->center_freq1, ch->width);
	ch_inf.chnum = ieee80211_frequency_to_channel(ch->center_freq1);
	primary_offset = ch->chan->center_freq - ch->center_freq1;
	switch (ch->width) {
	case NL80211_CHAN_WIDTH_20:
	case NL80211_CHAN_WIDTH_20_NOHT:
		ch_inf.bw = BRCMU_CHAN_BW_20;
		WARN_ON(primary_offset != 0);
		break;
	case NL80211_CHAN_WIDTH_40:
		ch_inf.bw = BRCMU_CHAN_BW_40;
		if (primary_offset > 0)
			ch_inf.sb = BRCMU_CHAN_SB_U;
		else
			ch_inf.sb = BRCMU_CHAN_SB_L;
		break;
	case NL80211_CHAN_WIDTH_80:
		ch_inf.bw = BRCMU_CHAN_BW_80;
		if (primary_offset == -30)
			ch_inf.sb = BRCMU_CHAN_SB_LL;
		else if (primary_offset == -10)
			ch_inf.sb = BRCMU_CHAN_SB_LU;
		else if (primary_offset == 10)
			ch_inf.sb = BRCMU_CHAN_SB_UL;
		else
			ch_inf.sb = BRCMU_CHAN_SB_UU;
		break;
	case NL80211_CHAN_WIDTH_160:
		ch_inf.bw = BRCMU_CHAN_BW_160;
		if (primary_offset == -70)
			ch_inf.sb = BRCMU_CHAN_SB_LLL;
		else if (primary_offset == -50)
			ch_inf.sb = BRCMU_CHAN_SB_LLU;
		else if (primary_offset == -30)
			ch_inf.sb = BRCMU_CHAN_SB_LUL;
		else if (primary_offset == -10)
			ch_inf.sb = BRCMU_CHAN_SB_LUU;
		else if (primary_offset == 10)
			ch_inf.sb = BRCMU_CHAN_SB_ULL;
		else if (primary_offset == 30)
			ch_inf.sb = BRCMU_CHAN_SB_ULU;
		else if (primary_offset == 50)
			ch_inf.sb = BRCMU_CHAN_SB_UUL;
		else
			ch_inf.sb = BRCMU_CHAN_SB_UUU;
		break;
	case NL80211_CHAN_WIDTH_80P80:
	case NL80211_CHAN_WIDTH_5:
	case NL80211_CHAN_WIDTH_10:
	default:
		WARN_ON_ONCE(1);
	}
	switch (ch->chan->band) {
	case NL80211_BAND_2GHZ:
		ch_inf.band = BRCMU_CHAN_BAND_2G;
		break;
	case NL80211_BAND_5GHZ:
		ch_inf.band = BRCMU_CHAN_BAND_5G;
		break;
	case NL80211_BAND_6GHZ:
		ch_inf.band = BRCMU_CHAN_BAND_6G;
		break;
	case NL80211_BAND_60GHZ:
	default:
		WARN_ON_ONCE(1);
	}
	d11inf->encchspec(&ch_inf);

	brcmf_dbg(TRACE, "chanspec: 0x%x\n", ch_inf.chspec);
	return ch_inf.chspec;
}

u16 channel_to_chanspec(struct brcmu_d11inf *d11inf,
			struct ieee80211_channel *ch)
{
	struct brcmu_chan ch_inf;

	switch (ch->band) {
	case NL80211_BAND_2GHZ:
		ch_inf.band = BRCMU_CHAN_BAND_2G;
		break;
	case NL80211_BAND_5GHZ:
		ch_inf.band = BRCMU_CHAN_BAND_5G;
		break;
	case NL80211_BAND_6GHZ:
		ch_inf.band = BRCMU_CHAN_BAND_6G;
		break;
	case NL80211_BAND_60GHZ:
	default:
		WARN_ON_ONCE(1);
	}
	ch_inf.chnum = ieee80211_frequency_to_channel(ch->center_freq);
	ch_inf.bw = BRCMU_CHAN_BW_20;
	d11inf->encchspec(&ch_inf);

	return ch_inf.chspec;
}

/* Traverse a string of 1-byte tag/1-byte length/variable-length value
 * triples, returning a pointer to the substring whose first element
 * matches tag
 */
static const struct brcmf_tlv *
brcmf_parse_tlvs(const void *buf, int buflen, uint key)
{
	const struct brcmf_tlv *elt = buf;
	int totlen = buflen;

	/* find tagged parameter */
	while (totlen >= TLV_HDR_LEN) {
		int len = elt->len;

		/* validate remaining totlen */
		if ((elt->id == key) && (totlen >= (len + TLV_HDR_LEN)))
			return elt;

		elt = (struct brcmf_tlv *)((u8 *)elt + (len + TLV_HDR_LEN));
		totlen -= (len + TLV_HDR_LEN);
	}

	return NULL;
}

/* Is any of the tlvs the expected entry? If
 * not update the tlvs buffer pointer/length.
 */
static bool
brcmf_tlv_has_ie(const u8 *ie, const u8 **tlvs, u32 *tlvs_len,
		 const u8 *oui, u32 oui_len, u8 type)
{
	/* If the contents match the OUI and the type */
	if (ie[TLV_LEN_OFF] >= oui_len + 1 &&
	    !memcmp(&ie[TLV_BODY_OFF], oui, oui_len) &&
	    type == ie[TLV_BODY_OFF + oui_len]) {
		return true;
	}

	if (tlvs == NULL)
		return false;
	/* point to the next ie */
	ie += ie[TLV_LEN_OFF] + TLV_HDR_LEN;
	/* calculate the length of the rest of the buffer */
	*tlvs_len -= (int)(ie - *tlvs);
	/* update the pointer to the start of the buffer */
	*tlvs = ie;

	return false;
}

static struct brcmf_vs_tlv *
brcmf_find_wpaie(const u8 *parse, u32 len)
{
	const struct brcmf_tlv *ie;

	while ((ie = brcmf_parse_tlvs(parse, len, WLAN_EID_VENDOR_SPECIFIC))) {
		if (brcmf_tlv_has_ie((const u8 *)ie, &parse, &len,
				     WPA_OUI, TLV_OUI_LEN, WPA_OUI_TYPE))
			return (struct brcmf_vs_tlv *)ie;
	}
	return NULL;
}

static struct brcmf_vs_tlv *
brcmf_find_wpsie(const u8 *parse, u32 len)
{
	const struct brcmf_tlv *ie;

	while ((ie = brcmf_parse_tlvs(parse, len, WLAN_EID_VENDOR_SPECIFIC))) {
		if (brcmf_tlv_has_ie((u8 *)ie, &parse, &len,
				     WPA_OUI, TLV_OUI_LEN, WPS_OUI_TYPE))
			return (struct brcmf_vs_tlv *)ie;
	}
	return NULL;
}

struct brcmf_tlv *
brcmf_find_iwie(const u8 *parse, u32 len)
{
	const struct brcmf_tlv *ie = NULL;

/* unfortunately it's too much work to dispose the const cast - inff_parse_tlvs
 * is used everywhere and changing its prototype to take const qualifier needs
 * a massive change to all its callers...
 */

	ie = brcmf_parse_tlvs(parse, len, WLAN_EID_INTERWORKING);
	if (ie)
		return (struct brcmf_tlv *)ie;
	return NULL;
}

s32
brcmf_clear_iwie(struct brcmf_cfg80211_info *cfg, struct brcmf_if *ifp)
{
	struct ie_set_buffer ie_setbuf = {0};

	brcmf_dbg(TRACE, "clear interworking IE\n");

	memset(&ie_setbuf, 0, sizeof(struct ie_set_buffer));

	ie_setbuf.ie_buffer.iecount = cpu_to_le32(1);
	ie_setbuf.ie_buffer.ie_list[0].ie_data.id = WLAN_EID_INTERWORKING;
	ie_setbuf.ie_buffer.ie_list[0].ie_data.len = 0;

	return brcmf_fil_iovar_data_set(ifp, "ie", &ie_setbuf, sizeof(ie_setbuf));
}

s32
brcmf_add_iwie(struct brcmf_cfg80211_info *cfg, struct brcmf_if *ifp, s32 pktflag,
	       u8 ie_id, u8 *data, u8 data_len)
{
	int err = 0;
	u32 buf_len;
	struct ie_set_buffer *ie_setbuf;

	if (ie_id != WLAN_EID_INTERWORKING) {
		brcmf_err("unsupported (id=%d)\n", ie_id);
		return -EINVAL;
	}

	/* access network options (1 octet)  is the mandatory field */
	if (!data || data_len == 0 || data_len > BRCMF_IW_IES_MAX_BUF_LEN) {
		brcmf_err("wrong interworking IE (len=%d)\n", data_len);
		return -EINVAL;
	}

	/* Validate the pktflag parameter */
	if (pktflag & ~(BRCMF_VNDR_IE_CUSTOM_FLAG)) {
		brcmf_err("invalid packet flag 0x%x\n", pktflag);
		return -EINVAL;
	}

	buf_len = sizeof(struct ie_set_buffer) + data_len - 1;

	/* if already set with previous values, delete it first */
	err = brcmf_clear_iwie(cfg, ifp);
	if (err)
		return err;

	ie_setbuf = kmalloc(buf_len, GFP_KERNEL);
	if (!ie_setbuf)
		return -ENOMEM;

	strscpy(ie_setbuf->cmd, "add", sizeof(ie_setbuf->cmd));

	/* Buffer contains only 1 IE */
	ie_setbuf->ie_buffer.iecount = cpu_to_le32(1);
	/* use VNDR_IE_CUSTOM_FLAG flags for none vendor IE . currently fixed value */
	ie_setbuf->ie_buffer.ie_list[0].pktflag = cpu_to_le32(pktflag);

	/* Now, add the IE to the buffer */
	ie_setbuf->ie_buffer.ie_list[0].ie_data.id = WLAN_EID_INTERWORKING;
	ie_setbuf->ie_buffer.ie_list[0].ie_data.len = data_len;
	/* Returning void here as max data_len can be 8 */
	(void)memcpy((u8 *)&ie_setbuf->ie_buffer.ie_list[0].ie_data.data[0],
			data, data_len);

	err = brcmf_fil_iovar_data_set(ifp, "ie", ie_setbuf, buf_len);
	if (err)
		brcmf_err("Failed to add interworking IE\n");

	kfree(ie_setbuf);

	return err;
}

static int brcmf_vif_change_validate(struct brcmf_cfg80211_info *cfg,
				     struct brcmf_cfg80211_vif *vif,
				     enum nl80211_iftype new_type)
{
	struct brcmf_cfg80211_vif *pos;
	bool check_combos = false;
	int ret = 0;
	struct iface_combination_params params = {
		.num_different_channels = 1,
	};

	list_for_each_entry(pos, &cfg->vif_list, list)
		if (pos == vif) {
			params.iftype_num[new_type]++;
		} else {
			/* concurrent interfaces so need check combinations */
			check_combos = true;
			params.iftype_num[pos->wdev.iftype]++;
		}

	if (check_combos)
		ret = cfg80211_check_combinations(cfg->wiphy, &params);

	return ret;
}

static int brcmf_vif_add_validate(struct brcmf_cfg80211_info *cfg,
				  enum nl80211_iftype new_type)
{
	struct brcmf_cfg80211_vif *pos;
	struct iface_combination_params params = {
		.num_different_channels = 1,
	};

	list_for_each_entry(pos, &cfg->vif_list, list)
		params.iftype_num[pos->wdev.iftype]++;

	params.iftype_num[new_type]++;
	return cfg80211_check_combinations(cfg->wiphy, &params);
}

static void convert_key_from_CPU(struct brcmf_wsec_key *key,
				 struct brcmf_wsec_key_le *key_le)
{
	key_le->index = cpu_to_le32(key->index);
	key_le->len = cpu_to_le32(key->len);
	key_le->algo = cpu_to_le32(key->algo);
	key_le->flags = cpu_to_le32(key->flags);
	key_le->rxiv.hi = cpu_to_le32(key->rxiv.hi);
	key_le->rxiv.lo = cpu_to_le16(key->rxiv.lo);
	key_le->iv_initialized = cpu_to_le32(key->iv_initialized);
	memcpy(key_le->data, key->data, sizeof(key->data));
	memcpy(key_le->ea, key->ea, sizeof(key->ea));
}

static int
send_key_to_dongle(struct brcmf_if *ifp, struct brcmf_wsec_key *key)
{
	struct brcmf_pub *drvr = ifp->drvr;
	int err;
	struct brcmf_wsec_key_le key_le;

	convert_key_from_CPU(key, &key_le);

	brcmf_netdev_wait_pend8021x(ifp);

	err = brcmf_fil_bsscfg_data_set(ifp, "wsec_key", &key_le,
					sizeof(key_le));

	if (err)
		bphy_err(drvr, "wsec_key error (%d)\n", err);
	return err;
}

void
brcmf_cfg80211_update_proto_addr_mode(struct wireless_dev *wdev)
{
	struct brcmf_cfg80211_vif *vif;
	struct brcmf_if *ifp;

	vif = container_of(wdev, struct brcmf_cfg80211_vif, wdev);
	ifp = vif->ifp;

	if ((wdev->iftype == NL80211_IFTYPE_ADHOC) ||
	    (wdev->iftype == NL80211_IFTYPE_AP) ||
	    (wdev->iftype == NL80211_IFTYPE_P2P_GO))
		brcmf_proto_configure_addr_mode(ifp->drvr, ifp->ifidx,
						ADDR_DIRECT);
	else
		brcmf_proto_configure_addr_mode(ifp->drvr, ifp->ifidx,
						ADDR_INDIRECT);
}

static int brcmf_get_first_free_bsscfgidx(struct brcmf_pub *drvr)
{
	int bsscfgidx;

	for (bsscfgidx = 0; bsscfgidx < BRCMF_MAX_IFS; bsscfgidx++) {
		/* bsscfgidx 1 is reserved for legacy P2P */
		if (bsscfgidx == 1)
			continue;
		if (!drvr->iflist[bsscfgidx])
			return bsscfgidx;
	}

	return -ENOMEM;
}

static void brcmf_set_vif_sta_macaddr(struct brcmf_if *ifp, u8 *mac_addr)
{
	u8 mac_idx = ifp->drvr->sta_mac_idx;

	/* set difference MAC address with locally administered bit */
	memcpy(mac_addr, ifp->mac_addr, ETH_ALEN);
	mac_addr[0] |= 0x02;
	mac_addr[3] ^= mac_idx ? 0xC0 : 0xA0;
	mac_idx++;
	mac_idx = mac_idx % 2;
	ifp->drvr->sta_mac_idx = mac_idx;
}

static int brcmf_cfg80211_request_sta_if(struct brcmf_if *ifp, u8 *macaddr)
{
	struct wl_interface_create_v1 iface_v1;
	struct wl_interface_create_v2 iface_v2;
	struct wl_interface_create_v3 iface_v3;
	u32 iface_create_ver;
	int err;

	/* interface_create version 1 */
	memset(&iface_v1, 0, sizeof(iface_v1));
	iface_v1.ver = WL_INTERFACE_CREATE_VER_1;
	iface_v1.flags = WL_INTERFACE_CREATE_STA |
			 WL_INTERFACE_MAC_USE;
	if (!is_zero_ether_addr(macaddr))
		memcpy(iface_v1.mac_addr, macaddr, ETH_ALEN);
	else
		brcmf_set_vif_sta_macaddr(ifp, iface_v1.mac_addr);

	err = brcmf_fil_iovar_data_get(ifp, "interface_create",
				       &iface_v1,
				       sizeof(iface_v1));
	if (err) {
		brcmf_dbg(INFO, "failed to create interface(v1), err=%d\n",
			   err);
	} else {
		brcmf_dbg(INFO, "interface created(v1)\n");
		return 0;
	}

	/* interface_create version 2 */
	memset(&iface_v2, 0, sizeof(iface_v2));
	iface_v2.ver = WL_INTERFACE_CREATE_VER_2;
	iface_v2.flags = WL_INTERFACE_MAC_USE;
	iface_v2.iftype = WL_INTERFACE_CREATE_STA;
	if (!is_zero_ether_addr(macaddr))
		memcpy(iface_v2.mac_addr, macaddr, ETH_ALEN);
	else
		brcmf_set_vif_sta_macaddr(ifp, iface_v2.mac_addr);

	err = brcmf_fil_iovar_data_get(ifp, "interface_create",
				       &iface_v2,
				       sizeof(iface_v2));
	if (err) {
		brcmf_dbg(INFO, "failed to create interface(v2), err=%d\n",
			   err);
	} else {
		brcmf_dbg(INFO, "interface created(v2)\n");
		return 0;
	}

	/* interface_create version 3+ */
	/* get supported version from firmware side */
	iface_create_ver = 0;
	err = brcmf_fil_bsscfg_int_get(ifp, "interface_create",
				       &iface_create_ver);
	if (err) {
		brcmf_err("fail to get supported version, err=%d\n", err);
		return -EOPNOTSUPP;
	}

	switch (iface_create_ver) {
	case WL_INTERFACE_CREATE_VER_3:
		memset(&iface_v3, 0, sizeof(iface_v3));
		iface_v3.ver = WL_INTERFACE_CREATE_VER_3;
		iface_v3.flags = WL_INTERFACE_MAC_USE;
		iface_v3.iftype = WL_INTERFACE_CREATE_STA;
		if (!is_zero_ether_addr(macaddr))
			memcpy(iface_v3.mac_addr, macaddr, ETH_ALEN);
		else
			brcmf_set_vif_sta_macaddr(ifp, iface_v3.mac_addr);

		err = brcmf_fil_iovar_data_get(ifp, "interface_create",
					       &iface_v3,
					       sizeof(iface_v3));

		if (!err)
			brcmf_dbg(INFO, "interface created(v3)\n");
		break;
	default:
		brcmf_err("not support interface create(v%d)\n",
			  iface_create_ver);
		err = -EOPNOTSUPP;
		break;
	}

	if (err) {
		brcmf_info("station interface creation failed (%d)\n",
			   err);
		return -EIO;
	}

	return 0;
}

static int brcmf_cfg80211_request_ap_if(struct brcmf_if *ifp)
{
	struct wl_interface_create_v1 iface_v1;
	struct wl_interface_create_v2 iface_v2;
	struct wl_interface_create_v3 iface_v3;
	u32 iface_create_ver;
	struct brcmf_pub *drvr = ifp->drvr;
	struct brcmf_mbss_ssid_le mbss_ssid_le;
	int bsscfgidx;
	int err;

	/* interface_create version 1 */
	memset(&iface_v1, 0, sizeof(iface_v1));
	iface_v1.ver = WL_INTERFACE_CREATE_VER_1;
	iface_v1.flags = WL_INTERFACE_CREATE_AP |
			 WL_INTERFACE_MAC_USE;

	brcmf_set_vif_sta_macaddr(ifp, iface_v1.mac_addr);

	err = brcmf_fil_iovar_data_get(ifp, "interface_create",
				       &iface_v1,
				       sizeof(iface_v1));
	if (err) {
		brcmf_dbg(INFO, "failed to create interface(v1), err=%d\n",
			   err);
	} else {
		brcmf_dbg(INFO, "interface created(v1)\n");
		return 0;
	}

	/* interface_create version 2 */
	memset(&iface_v2, 0, sizeof(iface_v2));
	iface_v2.ver = WL_INTERFACE_CREATE_VER_2;
	iface_v2.flags = WL_INTERFACE_MAC_USE;
	iface_v2.iftype = WL_INTERFACE_CREATE_AP;

	brcmf_set_vif_sta_macaddr(ifp, iface_v2.mac_addr);

	err = brcmf_fil_iovar_data_get(ifp, "interface_create",
				       &iface_v2,
				       sizeof(iface_v2));
	if (err) {
		brcmf_dbg(INFO, "failed to create interface(v2), err=%d\n",
			   err);
	} else {
		brcmf_dbg(INFO, "interface created(v2)\n");
		return 0;
	}

	/* interface_create version 3+ */
	/* get supported version from firmware side */
	iface_create_ver = 0;
	err = brcmf_fil_bsscfg_int_get(ifp, "interface_create",
				       &iface_create_ver);
	if (err) {
		brcmf_err("fail to get supported version, err=%d\n", err);
		return -EOPNOTSUPP;
	}

	switch (iface_create_ver) {
	case WL_INTERFACE_CREATE_VER_3:
		memset(&iface_v3, 0, sizeof(iface_v3));
		iface_v3.ver = WL_INTERFACE_CREATE_VER_3;
		iface_v3.flags = WL_INTERFACE_MAC_USE;
		iface_v3.iftype = WL_INTERFACE_CREATE_AP;
		brcmf_set_vif_sta_macaddr(ifp, iface_v3.mac_addr);

		err = brcmf_fil_iovar_data_get(ifp, "interface_create",
					       &iface_v3,
					       sizeof(iface_v3));

		if (!err)
			brcmf_dbg(INFO, "interface created(v3)\n");
		break;
	default:
		brcmf_err("not support interface create(v%d)\n",
			  iface_create_ver);
		err = -EOPNOTSUPP;
		break;
	}

	if (err) {
		brcmf_info("Does not support interface_create (%d)\n",
			   err);
		memset(&mbss_ssid_le, 0, sizeof(mbss_ssid_le));
		bsscfgidx = brcmf_get_first_free_bsscfgidx(ifp->drvr);
		if (bsscfgidx < 0)
			return bsscfgidx;

		mbss_ssid_le.bsscfgidx = cpu_to_le32(bsscfgidx);
		mbss_ssid_le.SSID_len = cpu_to_le32(5);
		sprintf(mbss_ssid_le.SSID, "ssid%d", bsscfgidx);

		err = brcmf_fil_bsscfg_data_set(ifp, "bsscfg:ssid", &mbss_ssid_le,
						sizeof(mbss_ssid_le));

		if (err < 0)
			bphy_err(drvr, "setting ssid failed %d\n", err);
	}

	return err;
}

/**
 * brcmf_ap_add_vif() - create a new AP or STA virtual interface
 *
 * @wiphy: wiphy device of new interface.
 * @name: name of the new interface.
 * @params: contains mac address for AP or STA device.
 */
static
struct wireless_dev *brcmf_apsta_add_vif(struct wiphy *wiphy, const char *name,
					 struct vif_params *params,
					 enum nl80211_iftype type)
{
	struct brcmf_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct brcmf_if *ifp = netdev_priv(cfg_to_ndev(cfg));
	struct brcmf_pub *drvr = cfg->pub;
	struct brcmf_cfg80211_vif *vif;
	int err;

	if (type != NL80211_IFTYPE_STATION && type != NL80211_IFTYPE_AP)
		return ERR_PTR(-EINVAL);

	if (brcmf_cfg80211_vif_event_armed(cfg))
		return ERR_PTR(-EBUSY);

	brcmf_dbg(INFO, "Adding vif \"%s\"\n", name);

	vif = brcmf_alloc_vif(cfg, type);
	if (IS_ERR(vif))
		return (struct wireless_dev *)vif;

	brcmf_cfg80211_arm_vif_event(cfg, vif);

	if (type == NL80211_IFTYPE_STATION)
		err = brcmf_cfg80211_request_sta_if(ifp, params->macaddr);
	else
		err = brcmf_cfg80211_request_ap_if(ifp);
	if (err) {
		brcmf_cfg80211_arm_vif_event(cfg, NULL);
		goto fail;
	}

	/* wait for firmware event */
	err = brcmf_cfg80211_wait_vif_event(cfg, BRCMF_E_IF_ADD,
					    BRCMF_VIF_EVENT_TIMEOUT);
	brcmf_cfg80211_arm_vif_event(cfg, NULL);
	if (!err) {
		bphy_err(drvr, "timeout occurred\n");
		err = -EIO;
		goto fail;
	}

	/* interface created in firmware */
	ifp = vif->ifp;
	if (!ifp) {
		bphy_err(drvr, "no if pointer provided\n");
		err = -ENOENT;
		goto fail;
	}

	strncpy(ifp->ndev->name, name, sizeof(ifp->ndev->name) - 1);
	err = brcmf_net_attach(ifp, true);
	if (err) {
		bphy_err(drvr, "Registering netdevice failed\n");
		free_netdev(ifp->ndev);
		goto fail;
	}

	return &ifp->vif->wdev;

fail:
	brcmf_free_vif(vif);
	return ERR_PTR(err);
}

static bool brcmf_is_apmode(struct brcmf_cfg80211_vif *vif)
{
	enum nl80211_iftype iftype;

	iftype = vif->wdev.iftype;
	return iftype == NL80211_IFTYPE_AP || iftype == NL80211_IFTYPE_P2P_GO;
}

static bool brcmf_is_ibssmode(struct brcmf_cfg80211_vif *vif)
{
	return vif->wdev.iftype == NL80211_IFTYPE_ADHOC;
}

/**
 * brcmf_mon_add_vif() - create monitor mode virtual interface
 *
 * @wiphy: wiphy device of new interface.
 * @name: name of the new interface.
 */
static struct wireless_dev *brcmf_mon_add_vif(struct wiphy *wiphy,
					      const char *name)
{
	struct brcmf_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct brcmf_cfg80211_vif *vif;
	struct net_device *ndev;
	struct brcmf_if *ifp;
	int err;

	if (cfg->pub->mon_if) {
		err = -EEXIST;
		goto err_out;
	}

	vif = brcmf_alloc_vif(cfg, NL80211_IFTYPE_MONITOR);
	if (IS_ERR(vif)) {
		err = PTR_ERR(vif);
		goto err_out;
	}

	ndev = alloc_netdev(sizeof(*ifp), name, NET_NAME_UNKNOWN, ether_setup);
	if (!ndev) {
		err = -ENOMEM;
		goto err_free_vif;
	}
	ndev->type = ARPHRD_IEEE80211_RADIOTAP;
	ndev->ieee80211_ptr = &vif->wdev;
	ndev->needs_free_netdev = true;
	ndev->priv_destructor = brcmf_cfg80211_free_netdev;
	SET_NETDEV_DEV(ndev, wiphy_dev(cfg->wiphy));

	ifp = netdev_priv(ndev);
	ifp->vif = vif;
	ifp->ndev = ndev;
	ifp->drvr = cfg->pub;

	vif->ifp = ifp;
	vif->wdev.netdev = ndev;

	err = brcmf_net_mon_attach(ifp);
	if (err) {
		brcmf_err("Failed to attach %s device\n", ndev->name);
		free_netdev(ndev);
		goto err_free_vif;
	}

	cfg->pub->mon_if = ifp;

	return &vif->wdev;

err_free_vif:
	brcmf_free_vif(vif);
err_out:
	return ERR_PTR(err);
}

static int brcmf_mon_del_vif(struct wiphy *wiphy, struct wireless_dev *wdev)
{
	struct brcmf_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct net_device *ndev = wdev->netdev;

	ndev->netdev_ops->ndo_stop(ndev);

	brcmf_net_detach(ndev, true);

	cfg->pub->mon_if = NULL;

	return 0;
}

static struct wireless_dev *brcmf_cfg80211_add_iface(struct wiphy *wiphy,
						     const char *name,
						     unsigned char name_assign_type,
						     enum nl80211_iftype type,
						     struct vif_params *params)
{
	struct brcmf_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct brcmf_pub *drvr = cfg->pub;
	struct wireless_dev *wdev;
	int err;

	brcmf_dbg(TRACE, "enter: %s type %d\n", name, type);
	err = brcmf_vif_add_validate(wiphy_to_cfg(wiphy), type);
	if (err) {
		bphy_err(drvr, "iface validation failed: err=%d\n", err);
		return ERR_PTR(err);
	}
	switch (type) {
	case NL80211_IFTYPE_ADHOC:
	case NL80211_IFTYPE_AP_VLAN:
	case NL80211_IFTYPE_WDS:
	case NL80211_IFTYPE_MESH_POINT:
		return ERR_PTR(-EOPNOTSUPP);
	case NL80211_IFTYPE_MONITOR:
		return brcmf_mon_add_vif(wiphy, name);
	case NL80211_IFTYPE_STATION:
	case NL80211_IFTYPE_AP:
		wdev = brcmf_apsta_add_vif(wiphy, name, params, type);
		break;
	case NL80211_IFTYPE_P2P_CLIENT:
	case NL80211_IFTYPE_P2P_GO:
	case NL80211_IFTYPE_P2P_DEVICE:
		wdev = brcmf_p2p_add_vif(wiphy, name, name_assign_type, type, params);
		break;
	case NL80211_IFTYPE_UNSPECIFIED:
	default:
		return ERR_PTR(-EINVAL);
	}

	if (IS_ERR(wdev))
		bphy_err(drvr, "add iface %s type %d failed: err=%d\n", name,
			 type, (int)PTR_ERR(wdev));
	else
		brcmf_cfg80211_update_proto_addr_mode(wdev);

	return wdev;
}

static void brcmf_scan_config_mpc(struct brcmf_if *ifp, int mpc)
{
	if (brcmf_feat_is_quirk_enabled(ifp, BRCMF_FEAT_QUIRK_NEED_MPC))
		brcmf_set_mpc(ifp, mpc);
}

void brcmf_set_mpc(struct brcmf_if *ifp, int mpc)
{
	struct brcmf_pub *drvr = ifp->drvr;
	s32 err = 0;

	ifp->drvr->req_mpc = mpc;
	if (check_vif_up(ifp->vif)) {
		err = brcmf_fil_iovar_int_set(ifp,
					      "mpc",
					      ifp->drvr->req_mpc);
		if (err) {
			bphy_err(drvr, "fail to set mpc\n");
			return;
		}
		brcmf_dbg(INFO, "MPC : %d\n", mpc);
	}
}

bool brcmf_is_apmode_operating(struct wiphy *wiphy)
{
	struct brcmf_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct brcmf_cfg80211_vif *vif;
	bool ret = false;

	list_for_each_entry(vif, &cfg->vif_list, list) {
		if (brcmf_is_apmode(vif) &&
		    test_bit(BRCMF_VIF_STATUS_AP_CREATED, &vif->sme_state))
			ret = true;
	}

	return ret;
}

s32 brcmf_notify_escan_complete(struct brcmf_cfg80211_info *cfg,
				struct brcmf_if *ifp, bool aborted,
				bool fw_abort)
{
	struct brcmf_pub *drvr = cfg->pub;
	struct brcmf_scan_params_le params_le;
	struct cfg80211_scan_request *scan_request;
	u64 reqid;
	u32 bucket;
	s32 err = 0;

	brcmf_dbg(SCAN, "Enter\n");

	/* clear scan request, because the FW abort can cause a second call */
	/* to this functon and might cause a double cfg80211_scan_done      */
	scan_request = cfg->scan_request;
	cfg->scan_request = NULL;

	timer_delete_sync(&cfg->escan_timeout);

	if (fw_abort) {
		/* Do a scan abort to stop the driver's scan engine */
		brcmf_dbg(SCAN, "ABORT scan in firmware\n");
		memset(&params_le, 0, sizeof(params_le));
		eth_broadcast_addr(params_le.bssid);
		params_le.bss_type = DOT11_BSSTYPE_ANY;
		params_le.scan_type = 0;
		params_le.channel_num = cpu_to_le32(1);
		params_le.nprobes = cpu_to_le32(1);
		params_le.active_time = cpu_to_le32(-1);
		params_le.passive_time = cpu_to_le32(-1);
		params_le.home_time = cpu_to_le32(-1);
		/* Scan is aborted by setting channel_list[0] to -1 */
		params_le.channel_list[0] = cpu_to_le16(-1);
		/* E-Scan (or anyother type) can be aborted by SCAN */
		err = brcmf_fil_cmd_data_set(ifp, BRCMF_C_SCAN,
					     &params_le, sizeof(params_le));
		if (err)
			bphy_err(drvr, "Scan abort failed\n");
	}

	brcmf_scan_config_mpc(ifp, 1);

	/*
	 * e-scan can be initiated internally
	 * which takes precedence.
	 */
	if (cfg->int_escan_map) {
		brcmf_dbg(SCAN, "scheduled scan completed (%x)\n",
			  cfg->int_escan_map);
		while (cfg->int_escan_map) {
			bucket = __ffs(cfg->int_escan_map);
			cfg->int_escan_map &= ~BIT(bucket);
			reqid = brcmf_pno_find_reqid_by_bucket(cfg->pno,
							       bucket);
			if (!aborted) {
				brcmf_dbg(SCAN, "report results: reqid=%llu\n",
					  reqid);
				cfg80211_sched_scan_results(cfg_to_wiphy(cfg),
							    reqid);
			}
		}
	} else if (scan_request) {
		struct cfg80211_scan_info info = {
			.aborted = aborted,
		};

		brcmf_dbg(SCAN, "ESCAN Completed scan: %s\n",
			  aborted ? "Aborted" : "Done");
		cfg80211_scan_done(scan_request, &info);
	}
	if (!test_and_clear_bit(BRCMF_SCAN_STATUS_BUSY, &cfg->scan_status))
		brcmf_dbg(SCAN, "Scan complete, probably P2P scan\n");

	return err;
}

static int brcmf_cfg80211_del_apsta_iface(struct wiphy *wiphy,
					  struct wireless_dev *wdev)
{
	struct brcmf_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct net_device *ndev = wdev->netdev;
	struct brcmf_if *ifp = netdev_priv(ndev);
	struct brcmf_pub *drvr = cfg->pub;
	int ret;
	int err;

	brcmf_cfg80211_arm_vif_event(cfg, ifp->vif);

	err = brcmf_fil_bsscfg_data_set(ifp, "interface_remove", NULL, 0);
	if (err) {
		bphy_err(drvr, "interface_remove failed %d\n", err);
		goto err_unarm;
	}

	/* wait for firmware event */
	ret = brcmf_cfg80211_wait_vif_event(cfg, BRCMF_E_IF_DEL,
					    BRCMF_VIF_EVENT_TIMEOUT);
	if (!ret) {
		bphy_err(drvr, "timeout occurred\n");
		err = -EIO;
		goto err_unarm;
	}

	brcmf_remove_interface(ifp, true);

err_unarm:
	brcmf_cfg80211_arm_vif_event(cfg, NULL);
	return err;
}

static
int brcmf_cfg80211_del_iface(struct wiphy *wiphy, struct wireless_dev *wdev)
{
	struct brcmf_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct net_device *ndev = wdev->netdev;

	if (ndev && ndev == cfg_to_ndev(cfg))
		return -ENOTSUPP;

	/* vif event pending in firmware */
	if (brcmf_cfg80211_vif_event_armed(cfg))
		return -EBUSY;

	if (ndev) {
		if (test_bit(BRCMF_SCAN_STATUS_BUSY, &cfg->scan_status) &&
		    cfg->escan_info.ifp == netdev_priv(ndev))
			brcmf_notify_escan_complete(cfg, netdev_priv(ndev),
						    true, true);

		brcmf_fil_iovar_int_set(netdev_priv(ndev), "mpc", 1);
	}

	switch (wdev->iftype) {
	case NL80211_IFTYPE_ADHOC:
	case NL80211_IFTYPE_AP_VLAN:
	case NL80211_IFTYPE_WDS:
	case NL80211_IFTYPE_MESH_POINT:
		return -EOPNOTSUPP;
	case NL80211_IFTYPE_MONITOR:
		return brcmf_mon_del_vif(wiphy, wdev);
	case NL80211_IFTYPE_STATION:
	case NL80211_IFTYPE_AP:
		return brcmf_cfg80211_del_apsta_iface(wiphy, wdev);
	case NL80211_IFTYPE_P2P_CLIENT:
	case NL80211_IFTYPE_P2P_GO:
	case NL80211_IFTYPE_P2P_DEVICE:
		return brcmf_p2p_del_vif(wiphy, wdev);
	case NL80211_IFTYPE_UNSPECIFIED:
	default:
		return -EINVAL;
	}
	return -EOPNOTSUPP;
}

static s32
brcmf_cfg80211_change_iface(struct wiphy *wiphy, struct net_device *ndev,
			 enum nl80211_iftype type,
			 struct vif_params *params)
{
	struct brcmf_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct brcmf_if *ifp = netdev_priv(ndev);
	struct brcmf_cfg80211_vif *vif = ifp->vif;
	struct brcmf_pub *drvr = cfg->pub;
	s32 infra = 0;
	s32 ap = 0;
	s32 err = 0;

	brcmf_dbg(TRACE, "Enter, bsscfgidx=%d, type=%d\n", ifp->bsscfgidx,
		  type);

	/* WAR: There are a number of p2p interface related problems which
	 * need to be handled initially (before doing the validate).
	 * wpa_supplicant tends to do iface changes on p2p device/client/go
	 * which are not always possible/allowed. However we need to return
	 * OK otherwise the wpa_supplicant wont start. The situation differs
	 * on configuration and setup (p2pon=1 module param). The first check
	 * is to see if the request is a change to station for p2p iface.
	 */
	if ((type == NL80211_IFTYPE_STATION) &&
	    ((vif->wdev.iftype == NL80211_IFTYPE_P2P_CLIENT) ||
	     (vif->wdev.iftype == NL80211_IFTYPE_P2P_GO) ||
	     (vif->wdev.iftype == NL80211_IFTYPE_P2P_DEVICE))) {
		brcmf_dbg(TRACE, "Ignoring cmd for p2p if\n");
		/* Now depending on whether module param p2pon=1 was used the
		 * response needs to be either 0 or EOPNOTSUPP. The reason is
		 * that if p2pon=1 is used, but a newer supplicant is used then
		 * we should return an error, as this combination wont work.
		 * In other situations 0 is returned and supplicant will start
		 * normally. It will give a trace in cfg80211, but it is the
		 * only way to get it working. Unfortunately this will result
		 * in situation where we wont support new supplicant in
		 * combination with module param p2pon=1, but that is the way
		 * it is. If the user tries this then unloading of driver might
		 * fail/lock.
		 */
		if (cfg->p2p.p2pdev_dynamically)
			return -EOPNOTSUPP;
		else
			return 0;
	}
	err = brcmf_vif_change_validate(wiphy_to_cfg(wiphy), vif, type);
	if (err) {
		bphy_err(drvr, "iface validation failed: err=%d\n", err);
		return err;
	}
	switch (type) {
	case NL80211_IFTYPE_MONITOR:
	case NL80211_IFTYPE_WDS:
		bphy_err(drvr, "type (%d) : currently we do not support this type\n",
			 type);
		return -EOPNOTSUPP;
	case NL80211_IFTYPE_ADHOC:
		infra = 0;
		break;
	case NL80211_IFTYPE_STATION:
		infra = 1;
		break;
	case NL80211_IFTYPE_AP:
	case NL80211_IFTYPE_P2P_GO:
		ap = 1;
		break;
	default:
		err = -EINVAL;
		goto done;
	}

	if (ap) {
		if (type == NL80211_IFTYPE_P2P_GO) {
			brcmf_dbg(INFO, "IF Type = P2P GO\n");
			err = brcmf_p2p_ifchange(cfg, BRCMF_FIL_P2P_IF_GO);
		}
		if (!err) {
			brcmf_dbg(INFO, "IF Type = AP\n");
		}
	} else {
		err = brcmf_fil_cmd_int_set(ifp, BRCMF_C_SET_INFRA, infra);
		if (err) {
			bphy_err(drvr, "WLC_SET_INFRA error (%d)\n", err);
			err = -EAGAIN;
			goto done;
		}
		brcmf_dbg(INFO, "IF Type = %s\n", brcmf_is_ibssmode(vif) ?
			  "Adhoc" : "Infra");
	}
	ndev->ieee80211_ptr->iftype = type;

	brcmf_cfg80211_update_proto_addr_mode(&vif->wdev);
	brcmf_setup_wiphybands(cfg);

done:
	brcmf_dbg(TRACE, "Exit\n");

	return err;
}

static void brcmf_escan_prep(struct brcmf_cfg80211_info *cfg,
			     struct brcmf_scan_params_le *params_le,
			     struct cfg80211_scan_request *request)
{
	u32 n_ssids;
	u32 n_channels;
	s32 i;
	s32 offset;
	u16 chanspec;
	char *ptr;
	struct brcmf_ssid_le ssid_le;

	eth_broadcast_addr(params_le->bssid);
	params_le->bss_type = DOT11_BSSTYPE_ANY;
	params_le->scan_type = BRCMF_SCANTYPE_ACTIVE;
	params_le->channel_num = 0;
	params_le->nprobes = cpu_to_le32(-1);
	params_le->active_time = cpu_to_le32(-1);
	params_le->passive_time = cpu_to_le32(-1);
	params_le->home_time = cpu_to_le32(-1);
	memset(&params_le->ssid_le, 0, sizeof(params_le->ssid_le));

	n_ssids = request->n_ssids;
	n_channels = request->n_channels;

	/* Copy channel array if applicable */
	brcmf_dbg(SCAN, "### List of channelspecs to scan ### %d\n",
		  n_channels);
	if (n_channels > 0) {
		for (i = 0; i < n_channels; i++) {
			chanspec = channel_to_chanspec(&cfg->d11inf,
						       request->channels[i]);
			brcmf_dbg(SCAN, "Chan : %d, Channel spec: %x\n",
				  request->channels[i]->hw_value, chanspec);
			params_le->channel_list[i] = cpu_to_le16(chanspec);
		}
	} else {
		brcmf_dbg(SCAN, "Scanning all channels\n");
	}
	/* Copy ssid array if applicable */
	brcmf_dbg(SCAN, "### List of SSIDs to scan ### %d\n", n_ssids);
	if (n_ssids > 0) {
		offset = offsetof(struct brcmf_scan_params_le, channel_list) +
				n_channels * sizeof(u16);
		offset = roundup(offset, sizeof(u32));
		ptr = (char *)params_le + offset;
		for (i = 0; i < n_ssids; i++) {
			memset(&ssid_le, 0, sizeof(ssid_le));
			ssid_le.SSID_len =
					cpu_to_le32(request->ssids[i].ssid_len);
			memcpy(ssid_le.SSID, request->ssids[i].ssid,
			       request->ssids[i].ssid_len);
			if (!ssid_le.SSID_len)
				brcmf_dbg(SCAN, "%d: Broadcast scan\n", i);
			else
				brcmf_dbg(SCAN, "%d: scan for  %.32s size=%d\n",
					  i, ssid_le.SSID, ssid_le.SSID_len);
			memcpy(ptr, &ssid_le, sizeof(ssid_le));
			ptr += sizeof(ssid_le);
		}
	} else {
		brcmf_dbg(SCAN, "Performing passive scan\n");
		params_le->scan_type = BRCMF_SCANTYPE_PASSIVE;
	}
	/* Adding mask to channel numbers */
	params_le->channel_num =
		cpu_to_le32((n_ssids << BRCMF_SCAN_PARAMS_NSSID_SHIFT) |
			(n_channels & BRCMF_SCAN_PARAMS_COUNT_MASK));
}

static s32
brcmf_run_escan(struct brcmf_cfg80211_info *cfg, struct brcmf_if *ifp,
		struct cfg80211_scan_request *request)
{
	struct brcmf_pub *drvr = cfg->pub;
	s32 params_size = BRCMF_SCAN_PARAMS_FIXED_SIZE +
			  offsetof(struct brcmf_escan_params_le, params_le);
	struct brcmf_escan_params_le *params;
	s32 err = 0;

	brcmf_dbg(SCAN, "E-SCAN START\n");

	if (request != NULL) {
		/* Allocate space for populating ssids in struct */
		params_size += sizeof(u32) * ((request->n_channels + 1) / 2);

		/* Allocate space for populating ssids in struct */
		params_size += sizeof(struct brcmf_ssid_le) * request->n_ssids;
	}

	params = kzalloc(params_size, GFP_KERNEL);
	if (!params) {
		err = -ENOMEM;
		goto exit;
	}
	BUG_ON(params_size + sizeof("escan") >= BRCMF_DCMD_MEDLEN);
	brcmf_escan_prep(cfg, &params->params_le, request);
	params->version = cpu_to_le32(BRCMF_ESCAN_REQ_VERSION);
	params->action = cpu_to_le16(WL_ESCAN_ACTION_START);
	params->sync_id = cpu_to_le16(0x1234);

	err = brcmf_fil_iovar_data_set(ifp, "escan", params, params_size);
	if (err) {
		if (err == -EBUSY)
			brcmf_dbg(INFO, "system busy : escan canceled\n");
		else
			bphy_err(drvr, "error (%d)\n", err);
	}

	kfree(params);
exit:
	return err;
}

static s32
brcmf_do_escan(struct brcmf_if *ifp, struct cfg80211_scan_request *request)
{
	struct brcmf_cfg80211_info *cfg = ifp->drvr->config;
	s32 err;
	struct brcmf_scan_results *results;
	struct escan_info *escan = &cfg->escan_info;

	brcmf_dbg(SCAN, "Enter\n");
	escan->ifp = ifp;
	escan->wiphy = cfg->wiphy;
	escan->escan_state = WL_ESCAN_STATE_SCANNING;

	brcmf_scan_config_mpc(ifp, 0);
	results = (struct brcmf_scan_results *)cfg->escan_info.escan_buf;
	results->version = 0;
	results->count = 0;
	results->buflen = WL_ESCAN_RESULTS_FIXED_SIZE;

	err = escan->run(cfg, ifp, request);
	if (err)
		brcmf_scan_config_mpc(ifp, 1);
	return err;
}

static s32
brcmf_cfg80211_scan(struct wiphy *wiphy, struct cfg80211_scan_request *request)
{
	struct brcmf_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct brcmf_pub *drvr = cfg->pub;
	struct brcmf_cfg80211_vif *vif;
	s32 err = 0;
	struct brcmf_tlv *interworking_ie = NULL;

	brcmf_dbg(TRACE, "Enter\n");
	vif = container_of(request->wdev, struct brcmf_cfg80211_vif, wdev);
	if (!check_vif_up(vif))
		return -EIO;

	if (test_bit(BRCMF_SCAN_STATUS_BUSY, &cfg->scan_status)) {
		bphy_err(drvr, "Scanning already: status (%lu)\n",
			 cfg->scan_status);
		return -EAGAIN;
	}
	if (test_bit(BRCMF_SCAN_STATUS_ABORT, &cfg->scan_status)) {
		bphy_err(drvr, "Scanning being aborted: status (%lu)\n",
			 cfg->scan_status);
		return -EAGAIN;
	}
	if (test_bit(BRCMF_SCAN_STATUS_SUPPRESS, &cfg->scan_status)) {
		bphy_err(drvr, "Scanning suppressed: status (%lu)\n",
			 cfg->scan_status);
		return -EAGAIN;
	}
	if (test_bit(BRCMF_VIF_STATUS_CONNECTING, &vif->sme_state)) {
		bphy_err(drvr, "Connecting: status (%lu)\n", vif->sme_state);
		return -EAGAIN;
	}

	/* If scan req comes for p2p0, send it over primary I/F */
	if (vif == cfg->p2p.bss_idx[P2PAPI_BSSCFG_DEVICE].vif)
		vif = cfg->p2p.bss_idx[P2PAPI_BSSCFG_PRIMARY].vif;

	brcmf_dbg(SCAN, "START ESCAN\n");

	cfg->scan_request = request;
	set_bit(BRCMF_SCAN_STATUS_BUSY, &cfg->scan_status);

	interworking_ie = brcmf_find_iwie(request->ie, request->ie_len);
	if (interworking_ie) {
		err = brcmf_add_iwie(cfg, vif->ifp,
				     BRCMF_VNDR_IE_CUSTOM_FLAG,
				     interworking_ie->id,
				     interworking_ie->data,
				     interworking_ie->len);
		if (err)
			brcmf_err("Failed to add interworking IE");
	} else {
		/* we have to clear IW IE  */
		brcmf_clear_iwie(cfg, vif->ifp);
	}

	cfg->escan_info.run = brcmf_run_escan;
	err = brcmf_p2p_scan_prep(wiphy, request, vif);
	if (err)
		goto scan_out;

	err = brcmf_do_escan(vif->ifp, request);
	if (err)
		goto scan_out;

	/* Arm scan timeout timer */
	mod_timer(&cfg->escan_timeout,
		  jiffies + msecs_to_jiffies(BRCMF_ESCAN_TIMER_INTERVAL_MS));

	return 0;

scan_out:
	bphy_err(drvr, "scan error (%d)\n", err);
	clear_bit(BRCMF_SCAN_STATUS_BUSY, &cfg->scan_status);
	cfg->scan_request = NULL;
	return err;
}

static s32 brcmf_set_rts(struct net_device *ndev, u32 rts_threshold)
{
	struct brcmf_if *ifp = netdev_priv(ndev);
	struct brcmf_pub *drvr = ifp->drvr;
	s32 err = 0;

	err = brcmf_fil_iovar_int_set(ifp, "rtsthresh", rts_threshold);
	if (err)
		bphy_err(drvr, "Error (%d)\n", err);

	return err;
}

static s32 brcmf_set_frag(struct net_device *ndev, u32 frag_threshold)
{
	struct brcmf_if *ifp = netdev_priv(ndev);
	struct brcmf_pub *drvr = ifp->drvr;
	s32 err = 0;

	err = brcmf_fil_iovar_int_set(ifp, "fragthresh",
				      frag_threshold);
	if (err)
		bphy_err(drvr, "Error (%d)\n", err);

	return err;
}

static s32 brcmf_set_retry(struct net_device *ndev, u32 retry, bool l)
{
	struct brcmf_if *ifp = netdev_priv(ndev);
	struct brcmf_pub *drvr = ifp->drvr;
	s32 err = 0;
	u32 cmd = (l ? BRCMF_C_SET_LRL : BRCMF_C_SET_SRL);

	err = brcmf_fil_cmd_int_set(ifp, cmd, retry);
	if (err) {
		bphy_err(drvr, "cmd (%d) , error (%d)\n", cmd, err);
		return err;
	}
	return err;
}

static s32 brcmf_cfg80211_set_wiphy_params(struct wiphy *wiphy, u32 changed)
{
	struct brcmf_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct net_device *ndev = cfg_to_ndev(cfg);
	struct brcmf_if *ifp = netdev_priv(ndev);
	s32 err = 0;

	brcmf_dbg(TRACE, "Enter\n");
	if (!check_vif_up(ifp->vif))
		return -EIO;

	if (changed & WIPHY_PARAM_RTS_THRESHOLD &&
	    (cfg->conf->rts_threshold != wiphy->rts_threshold)) {
		cfg->conf->rts_threshold = wiphy->rts_threshold;
		err = brcmf_set_rts(ndev, cfg->conf->rts_threshold);
		if (!err)
			goto done;
	}
	if (changed & WIPHY_PARAM_FRAG_THRESHOLD &&
	    (cfg->conf->frag_threshold != wiphy->frag_threshold)) {
		cfg->conf->frag_threshold = wiphy->frag_threshold;
		err = brcmf_set_frag(ndev, cfg->conf->frag_threshold);
		if (!err)
			goto done;
	}
	if (changed & WIPHY_PARAM_RETRY_LONG
	    && (cfg->conf->retry_long != wiphy->retry_long)) {
		cfg->conf->retry_long = wiphy->retry_long;
		err = brcmf_set_retry(ndev, cfg->conf->retry_long, true);
		if (!err)
			goto done;
	}
	if (changed & WIPHY_PARAM_RETRY_SHORT
	    && (cfg->conf->retry_short != wiphy->retry_short)) {
		cfg->conf->retry_short = wiphy->retry_short;
		err = brcmf_set_retry(ndev, cfg->conf->retry_short, false);
		if (!err)
			goto done;
	}

done:
	brcmf_dbg(TRACE, "Exit\n");
	return err;
}

static void brcmf_init_prof(struct brcmf_cfg80211_profile *prof)
{
	memset(prof, 0, sizeof(*prof));
}

static u16 brcmf_map_fw_linkdown_reason(const struct brcmf_event_msg *e)
{
	u16 reason;

	switch (e->event_code) {
	case BRCMF_E_DEAUTH:
	case BRCMF_E_DEAUTH_IND:
	case BRCMF_E_DISASSOC_IND:
		reason = e->reason;
		break;
	case BRCMF_E_LINK:
	default:
		reason = 0;
		break;
	}
	return reason;
}

static int brcmf_set_pmk(struct brcmf_if *ifp, const u8 *pmk_data, u16 pmk_len)
{
	struct brcmf_pub *drvr = ifp->drvr;
	struct brcmf_wsec_pmk_le pmk;
	int err;

	memset(&pmk, 0, sizeof(pmk));

	/* pass pmk directly */
	pmk.key_len = cpu_to_le16(pmk_len);
	pmk.flags = cpu_to_le16(0);
	memcpy(pmk.key, pmk_data, pmk_len);

	/* store psk in firmware */
	err = brcmf_fil_cmd_data_set(ifp, BRCMF_C_SET_WSEC_PMK,
				     &pmk, sizeof(pmk));
	if (err < 0)
		bphy_err(drvr, "failed to change PSK in firmware (len=%u)\n",
			 pmk_len);

	return err;
}

static int brcmf_set_sae_password(struct brcmf_if *ifp, const u8 *pwd_data,
				  u16 pwd_len)
{
	struct brcmf_pub *drvr = ifp->drvr;
	struct brcmf_wsec_sae_pwd_le sae_pwd;
	int err;

	if (pwd_len > BRCMF_WSEC_MAX_SAE_PASSWORD_LEN) {
		bphy_err(drvr, "sae_password must be less than %d\n",
			 BRCMF_WSEC_MAX_SAE_PASSWORD_LEN);
		return -EINVAL;
	}

	sae_pwd.key_len = cpu_to_le16(pwd_len);
	memcpy(sae_pwd.key, pwd_data, pwd_len);

	err = brcmf_fil_iovar_data_set(ifp, "sae_password", &sae_pwd,
				       sizeof(sae_pwd));
	if (err < 0)
		bphy_err(drvr, "failed to set SAE password in firmware (len=%u)\n",
			 pwd_len);

	return err;
}

static void brcmf_link_down(struct brcmf_cfg80211_vif *vif, u16 reason,
			    bool locally_generated)
{
	struct brcmf_cfg80211_info *cfg = wiphy_to_cfg(vif->wdev.wiphy);
	struct brcmf_pub *drvr = cfg->pub;
	bool bus_up = drvr->bus_if->state == BRCMF_BUS_UP;
	s32 err = 0;

	brcmf_dbg(TRACE, "Enter\n");

	if (test_and_clear_bit(BRCMF_VIF_STATUS_CONNECTED, &vif->sme_state)) {
		if (bus_up) {
			brcmf_dbg(INFO, "Call WLC_DISASSOC to stop excess roaming\n");
			err = brcmf_fil_cmd_data_set(vif->ifp,
						     BRCMF_C_DISASSOC, NULL, 0);
			if (err) {
				bphy_err(drvr, "WLC_DISASSOC failed (%d)\n",
						err);
			} else {
				if (brcmf_feat_is_enabled(vif->ifp, BRCMF_FEAT_TWT)) {
					/* Cleanup TWT Session list */
					brcmf_twt_cleanup_sessions(vif->ifp);
				}
			}
		}

		if ((vif->wdev.iftype == NL80211_IFTYPE_STATION) ||
		    (vif->wdev.iftype == NL80211_IFTYPE_P2P_CLIENT))
			cfg80211_disconnected(vif->wdev.netdev, reason, NULL, 0,
					      locally_generated, GFP_KERNEL);
	}
	clear_bit(BRCMF_VIF_STATUS_CONNECTING, &vif->sme_state);
	clear_bit(BRCMF_VIF_STATUS_EAP_SUCCESS, &vif->sme_state);
	clear_bit(BRCMF_VIF_STATUS_ASSOC_SUCCESS, &vif->sme_state);
	clear_bit(BRCMF_SCAN_STATUS_SUPPRESS, &cfg->scan_status);
	brcmf_btcoex_set_mode(vif, BRCMF_BTCOEX_ENABLED, 0);
	if (vif->profile.use_fwsup != BRCMF_PROFILE_FWSUP_NONE) {
		if (bus_up)
			brcmf_set_pmk(vif->ifp, NULL, 0);
		vif->profile.use_fwsup = BRCMF_PROFILE_FWSUP_NONE;
	}

	brcmf_dbg(TRACE, "Exit\n");
}

static s32
brcmf_cfg80211_join_ibss(struct wiphy *wiphy, struct net_device *ndev,
		      struct cfg80211_ibss_params *params)
{
	struct brcmf_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct brcmf_if *ifp = netdev_priv(ndev);
	struct brcmf_cfg80211_profile *profile = &ifp->vif->profile;
	struct brcmf_pub *drvr = cfg->pub;
	struct brcmf_join_params join_params;
	size_t join_params_size = 0;
	s32 err = 0;
	s32 wsec = 0;
	s32 bcnprd;
	u16 chanspec;
	u32 ssid_len;

	brcmf_dbg(TRACE, "Enter\n");
	if (!check_vif_up(ifp->vif))
		return -EIO;

	if (params->ssid)
		brcmf_dbg(CONN, "SSID: %s\n", params->ssid);
	else {
		brcmf_dbg(CONN, "SSID: NULL, Not supported\n");
		return -EOPNOTSUPP;
	}

	set_bit(BRCMF_VIF_STATUS_CONNECTING, &ifp->vif->sme_state);

	if (params->bssid)
		brcmf_dbg(CONN, "BSSID: %pM\n", params->bssid);
	else
		brcmf_dbg(CONN, "No BSSID specified\n");

	if (params->chandef.chan)
		brcmf_dbg(CONN, "channel: %d\n",
			  params->chandef.chan->center_freq);
	else
		brcmf_dbg(CONN, "no channel specified\n");

	if (params->channel_fixed)
		brcmf_dbg(CONN, "fixed channel required\n");
	else
		brcmf_dbg(CONN, "no fixed channel required\n");

	if (params->ie && params->ie_len)
		brcmf_dbg(CONN, "ie len: %d\n", params->ie_len);
	else
		brcmf_dbg(CONN, "no ie specified\n");

	if (params->beacon_interval)
		brcmf_dbg(CONN, "beacon interval: %d\n",
			  params->beacon_interval);
	else
		brcmf_dbg(CONN, "no beacon interval specified\n");

	if (params->basic_rates)
		brcmf_dbg(CONN, "basic rates: %08X\n", params->basic_rates);
	else
		brcmf_dbg(CONN, "no basic rates specified\n");

	if (params->privacy)
		brcmf_dbg(CONN, "privacy required\n");
	else
		brcmf_dbg(CONN, "no privacy required\n");

	/* Configure Privacy for starter */
	if (params->privacy)
		wsec |= WEP_ENABLED;

	err = brcmf_fil_iovar_int_set(ifp, "wsec", wsec);
	if (err) {
		bphy_err(drvr, "wsec failed (%d)\n", err);
		goto done;
	}

	/* Configure Beacon Interval for starter */
	if (params->beacon_interval)
		bcnprd = params->beacon_interval;
	else
		bcnprd = 100;

	err = brcmf_fil_cmd_int_set(ifp, BRCMF_C_SET_BCNPRD, bcnprd);
	if (err) {
		bphy_err(drvr, "WLC_SET_BCNPRD failed (%d)\n", err);
		goto done;
	}

	/* Configure required join parameter */
	memset(&join_params, 0, sizeof(struct brcmf_join_params));

	/* SSID */
	ssid_len = min_t(u32, params->ssid_len, IEEE80211_MAX_SSID_LEN);
	memcpy(join_params.ssid_le.SSID, params->ssid, ssid_len);
	join_params.ssid_le.SSID_len = cpu_to_le32(ssid_len);
	join_params_size = sizeof(join_params.ssid_le);

	/* BSSID */
	if (params->bssid) {
		memcpy(join_params.params_le.bssid, params->bssid, ETH_ALEN);
		join_params_size += BRCMF_ASSOC_PARAMS_FIXED_SIZE;
		memcpy(profile->bssid, params->bssid, ETH_ALEN);
	} else {
		eth_broadcast_addr(join_params.params_le.bssid);
		eth_zero_addr(profile->bssid);
	}

	/* Channel */
	if (params->chandef.chan) {
		u32 target_channel;

		cfg->channel =
			ieee80211_frequency_to_channel(
				params->chandef.chan->center_freq);
		if (params->channel_fixed) {
			/* adding chanspec */
			chanspec = chandef_to_chanspec(&cfg->d11inf,
						       &params->chandef);
			join_params.params_le.chanspec_list[0] =
				cpu_to_le16(chanspec);
			join_params.params_le.chanspec_num = cpu_to_le32(1);
			join_params_size += sizeof(join_params.params_le);
		}

		/* set channel for starter */
		target_channel = cfg->channel;
		err = brcmf_fil_cmd_int_set(ifp, BRCMF_C_SET_CHANNEL,
					    target_channel);
		if (err) {
			bphy_err(drvr, "WLC_SET_CHANNEL failed (%d)\n", err);
			goto done;
		}
	} else
		cfg->channel = 0;

	cfg->ibss_starter = false;


	err = brcmf_fil_cmd_data_set(ifp, BRCMF_C_SET_SSID,
				     &join_params, join_params_size);
	if (err) {
		bphy_err(drvr, "WLC_SET_SSID failed (%d)\n", err);
		goto done;
	}

done:
	if (err)
		clear_bit(BRCMF_VIF_STATUS_CONNECTING, &ifp->vif->sme_state);
	brcmf_dbg(TRACE, "Exit\n");
	return err;
}

static s32
brcmf_cfg80211_leave_ibss(struct wiphy *wiphy, struct net_device *ndev)
{
	struct brcmf_if *ifp = netdev_priv(ndev);

	brcmf_dbg(TRACE, "Enter\n");
	if (!check_vif_up(ifp->vif)) {
		/* When driver is being unloaded, it can end up here. If an
		 * error is returned then later on a debug trace in the wireless
		 * core module will be printed. To avoid this 0 is returned.
		 */
		return 0;
	}

	brcmf_link_down(ifp->vif, WLAN_REASON_DEAUTH_LEAVING, true);
	brcmf_net_setcarrier(ifp, false);

	brcmf_dbg(TRACE, "Exit\n");

	return 0;
}

static s32 brcmf_set_wpa_version(struct net_device *ndev,
				 struct cfg80211_connect_params *sme)
{
	struct brcmf_if *ifp = netdev_priv(ndev);
	struct brcmf_cfg80211_profile *profile = ndev_to_prof(ndev);
	struct brcmf_pub *drvr = ifp->drvr;
	struct brcmf_cfg80211_security *sec;
	s32 val = 0;
	s32 err = 0;

	if (sme->crypto.wpa_versions & NL80211_WPA_VERSION_1) {
		val = WPA_AUTH_PSK | WPA_AUTH_UNSPECIFIED;
	} else if (sme->crypto.wpa_versions & NL80211_WPA_VERSION_2) {
		if (sme->crypto.akm_suites[0] == WLAN_AKM_SUITE_SAE)
			val = WPA3_AUTH_SAE_PSK;
		else if (sme->crypto.akm_suites[0] == WLAN_AKM_SUITE_OWE)
			val = WPA3_AUTH_OWE;
		else if (sme->crypto.akm_suites[0] == WLAN_AKM_SUITE_8021X_SHA256)
			val = WPA3_AUTH_1X_SHA256;
		else
			val = WPA2_AUTH_PSK | WPA2_AUTH_UNSPECIFIED;
	} else if (sme->crypto.wpa_versions & NL80211_WPA_VERSION_3) {
		if (sme->crypto.akm_suites[0] == WLAN_AKM_SUITE_FT_OVER_SAE)
			val = WPA3_AUTH_SAE_FBT;
		else if (sme->crypto.akm_suites[0] == WLAN_AKM_SUITE_FT_8021X_SHA384)
			val = WPA3_AUTH_SAE_FT_1X;
		else
			val = WPA3_AUTH_SAE_PSK;
	} else {
		val = WPA_AUTH_DISABLED;
	}
	brcmf_dbg(CONN, "setting wpa_auth to 0x%0x\n", val);
	err = brcmf_fil_bsscfg_int_set(ifp, "wpa_auth", val);
	if (err) {
		bphy_err(drvr, "set wpa_auth failed (%d)\n", err);
		return err;
	}
	sec = &profile->sec;
	sec->wpa_versions = sme->crypto.wpa_versions;
	return err;
}

static s32 brcmf_set_auth_type(struct net_device *ndev,
			       struct cfg80211_connect_params *sme)
{
	struct brcmf_if *ifp = netdev_priv(ndev);
	struct brcmf_cfg80211_profile *profile = ndev_to_prof(ndev);
	struct brcmf_pub *drvr = ifp->drvr;
	struct brcmf_cfg80211_security *sec;
	s32 val = 0;
	s32 err = 0;

	switch (sme->auth_type) {
	case NL80211_AUTHTYPE_OPEN_SYSTEM:
		val = 0;
		brcmf_dbg(CONN, "open system\n");
		break;
	case NL80211_AUTHTYPE_SHARED_KEY:
		val = 1;
		brcmf_dbg(CONN, "shared key\n");
		break;
	case NL80211_AUTHTYPE_SAE:
		val = 3;
		brcmf_dbg(CONN, "SAE authentication\n");
		break;
	default:
		val = 2;
		brcmf_dbg(CONN, "automatic, auth type (%d)\n", sme->auth_type);
		break;
	}

	err = brcmf_fil_bsscfg_int_set(ifp, "auth", val);
	if (err) {
		bphy_err(drvr, "set auth failed (%d)\n", err);
		return err;
	}
	sec = &profile->sec;
	sec->auth_type = sme->auth_type;
	return err;
}

static s32
brcmf_set_wsec_mode(struct net_device *ndev,
		    struct cfg80211_connect_params *sme)
{
	struct brcmf_if *ifp = netdev_priv(ndev);
	struct brcmf_cfg80211_profile *profile = ndev_to_prof(ndev);
	struct brcmf_pub *drvr = ifp->drvr;
	struct brcmf_cfg80211_security *sec;
	s32 pval = 0;
	s32 gval = 0;
	s32 wsec;
	s32 err = 0;
	u32 algos = 0, mask = 0;


	if (sme->crypto.n_ciphers_pairwise) {
		switch (sme->crypto.ciphers_pairwise[0]) {
		case WLAN_CIPHER_SUITE_WEP40:
		case WLAN_CIPHER_SUITE_WEP104:
			pval = WEP_ENABLED;
			break;
		case WLAN_CIPHER_SUITE_TKIP:
			pval = TKIP_ENABLED;
			break;
		case WLAN_CIPHER_SUITE_CCMP:
			pval = AES_ENABLED;
			break;
		case WLAN_CIPHER_SUITE_AES_CMAC:
			pval = AES_ENABLED;
			break;
		case WLAN_CIPHER_SUITE_GCMP_256:
			if (!brcmf_feat_is_enabled(ifp, BRCMF_FEAT_GCMP)) {
				brcmf_err("the low layer not support GCMP\n");
				return -EOPNOTSUPP;
			}
			pval = AES_ENABLED;
			algos = KEY_ALGO_MASK(CRYPTO_ALGO_AES_GCM256);
			mask = algos | KEY_ALGO_MASK(CRYPTO_ALGO_AES_CCM);
			break;
		default:
			bphy_err(drvr, "invalid cipher pairwise (%d)\n",
				 sme->crypto.ciphers_pairwise[0]);
			return -EINVAL;
		}
	}
	if (sme->crypto.cipher_group) {
		switch (sme->crypto.cipher_group) {
		case WLAN_CIPHER_SUITE_WEP40:
		case WLAN_CIPHER_SUITE_WEP104:
			gval = WEP_ENABLED;
			break;
		case WLAN_CIPHER_SUITE_TKIP:
			gval = TKIP_ENABLED;
			break;
		case WLAN_CIPHER_SUITE_CCMP:
			gval = AES_ENABLED;
			break;
		case WLAN_CIPHER_SUITE_AES_CMAC:
			gval = AES_ENABLED;
			break;
		case WLAN_CIPHER_SUITE_GCMP_256:
			if (!brcmf_feat_is_enabled(ifp, BRCMF_FEAT_GCMP)) {
				brcmf_err("the low layer not support GCMP\n");
				return -EOPNOTSUPP;
			}
			gval = AES_ENABLED;
			algos = KEY_ALGO_MASK(CRYPTO_ALGO_AES_GCM256);
			mask = algos | KEY_ALGO_MASK(CRYPTO_ALGO_AES_CCM);
			break;
		default:
			bphy_err(drvr, "invalid cipher group (%d)\n",
				 sme->crypto.cipher_group);
			return -EINVAL;
		}
	}

	brcmf_dbg(CONN, "pval (%d) gval (%d)\n", pval, gval);
	brcmf_dbg(CONN, "algos (0x%x) mask (0x%x)\n", algos, mask);
	/* In case of privacy, but no security and WPS then simulate */
	/* setting AES. WPS-2.0 allows no security                   */
	if (brcmf_find_wpsie(sme->ie, sme->ie_len) && !pval && !gval &&
	    sme->privacy)
		pval = AES_ENABLED;

	wsec = pval | gval;
	err = brcmf_fil_bsscfg_int_set(ifp, "wsec", wsec);
	if (err) {
		bphy_err(drvr, "error (%d)\n", err);
		return err;
	}

	if (brcmf_feat_is_enabled(ifp, BRCMF_FEAT_GCMP)) {
		brcmf_dbg(CONN,
			  "set_wsec_info algos (0x%x) mask (0x%x)\n",
			  algos, mask);
		err = wl_set_wsec_info_algos(ifp, algos, mask);
		if (err) {
			brcmf_err("set wsec_info error (%d)\n", err);
			return err;
		}
	}

	sec = &profile->sec;
	sec->cipher_pairwise = sme->crypto.ciphers_pairwise[0];
	sec->cipher_group = sme->crypto.cipher_group;

	return err;
}

static s32
brcmf_set_key_mgmt(struct net_device *ndev, struct cfg80211_connect_params *sme)
{
	struct brcmf_if *ifp = netdev_priv(ndev);
	struct brcmf_cfg80211_profile *profile = &ifp->vif->profile;
	struct brcmf_pub *drvr = ifp->drvr;
	s32 val;
	s32 err;
	s32 okc_enable;
	const struct brcmf_tlv *rsn_ie;
	const u8 *ie;
	u32 ie_len;
	u32 offset;
	u16 rsn_cap;
	u32 mfp;
	u16 count;
	u16 pmkid_count;
	const u8 *group_mgmt_cs = NULL;

	profile->use_fwsup = BRCMF_PROFILE_FWSUP_NONE;
	profile->is_ft = false;
	profile->is_okc = false;

	if (!sme->crypto.n_akm_suites)
		return 0;

	err = brcmf_fil_bsscfg_int_get(netdev_priv(ndev), "wpa_auth", &val);
	if (err) {
		bphy_err(drvr, "could not get wpa_auth (%d)\n", err);
		return err;
	}
	if (val & (WPA_AUTH_PSK | WPA_AUTH_UNSPECIFIED)) {
		switch (sme->crypto.akm_suites[0]) {
		case WLAN_AKM_SUITE_8021X:
			val = WPA_AUTH_UNSPECIFIED;
			if (sme->want_1x)
				profile->use_fwsup = BRCMF_PROFILE_FWSUP_1X;
			else
				profile->use_fwsup = BRCMF_PROFILE_FWSUP_ROAM;
			break;
		case WLAN_AKM_SUITE_PSK:
			val = WPA_AUTH_PSK;
			break;
		default:
			bphy_err(drvr, "invalid akm suite (%d)\n",
				 sme->crypto.akm_suites[0]);
			return -EINVAL;
		}
	} else if (val & (WPA2_AUTH_PSK | WPA2_AUTH_UNSPECIFIED | WPA3_AUTH_OWE)) {
		switch (sme->crypto.akm_suites[0]) {
		case WLAN_AKM_SUITE_8021X:
			val = WPA2_AUTH_UNSPECIFIED;
			if (sme->want_1x)
				profile->use_fwsup = BRCMF_PROFILE_FWSUP_1X;
			else
				profile->use_fwsup = BRCMF_PROFILE_FWSUP_ROAM;
			break;
		case WLAN_AKM_SUITE_8021X_SHA256:
			val = WPA2_AUTH_1X_SHA256;
			if (sme->want_1x)
				profile->use_fwsup = BRCMF_PROFILE_FWSUP_1X;
			else
				profile->use_fwsup = BRCMF_PROFILE_FWSUP_ROAM;
			break;
		case WLAN_AKM_SUITE_PSK_SHA256:
			val = WPA2_AUTH_PSK_SHA256;
			break;
		case WLAN_AKM_SUITE_PSK:
			val = WPA2_AUTH_PSK;
			break;
		case WLAN_AKM_SUITE_FT_8021X:
			val = WPA2_AUTH_UNSPECIFIED | WPA2_AUTH_FT;
			profile->is_ft = true;
			if (sme->want_1x)
				profile->use_fwsup = BRCMF_PROFILE_FWSUP_1X;
			else
				profile->use_fwsup = BRCMF_PROFILE_FWSUP_ROAM;
			break;
		case WLAN_AKM_SUITE_FT_PSK:
			val = WPA2_AUTH_PSK | WPA2_AUTH_FT;
			profile->is_ft = true;
			if (brcmf_feat_is_enabled(ifp, BRCMF_FEAT_FWSUP))
				profile->use_fwsup = BRCMF_PROFILE_FWSUP_PSK;
			else
				profile->use_fwsup = BRCMF_PROFILE_FWSUP_ROAM;
			break;
		case WLAN_AKM_SUITE_DPP:
			val = WFA_AUTH_DPP;
			profile->use_fwsup = BRCMF_PROFILE_FWSUP_NONE;
			break;
		case WLAN_AKM_SUITE_OWE:
			val = WPA3_AUTH_OWE;
			profile->use_fwsup = BRCMF_PROFILE_FWSUP_ROAM;
			break;
		case WLAN_AKM_SUITE_8021X_SUITE_B_192:
			val = WPA3_AUTH_1X_SUITE_B_SHA384;
			if (sme->want_1x)
				profile->use_fwsup = BRCMF_PROFILE_FWSUP_1X;
			else
				profile->use_fwsup = BRCMF_PROFILE_FWSUP_ROAM;

			/*Disable intrnal sup for SuiteB*/
			if (brcmf_feat_is_enabled(ifp, BRCMF_FEAT_FWSUP))
				profile->use_fwsup = BRCMF_PROFILE_FWSUP_NONE;
			break;
		default:
			bphy_err(drvr, "invalid akm suite (%d)\n",
				 sme->crypto.akm_suites[0]);
			return -EINVAL;
		}
	} else if (val & (WPA3_AUTH_SAE_PSK | WPA3_AUTH_SAE_FBT)) {
		switch (sme->crypto.akm_suites[0]) {
		case WLAN_AKM_SUITE_SAE:
			val = WPA3_AUTH_SAE_PSK;
			if (sme->crypto.sae_pwd) {
				brcmf_dbg(INFO, "using SAE offload\n");
				profile->use_fwsup = BRCMF_PROFILE_FWSUP_SAE;
			} else if (brcmf_feat_is_enabled(ifp, BRCMF_FEAT_FWSUP) &&
				brcmf_feat_is_enabled(ifp, BRCMF_FEAT_SAE_EXT)) {
				brcmf_dbg(INFO, "using EXTSAE with PSK offload\n");
				profile->use_fwsup = BRCMF_PROFILE_FWSUP_PSK;
			}
			break;
		case WLAN_AKM_SUITE_FT_OVER_SAE:
			val = WPA3_AUTH_SAE_FBT;
			profile->is_ft = true;
			if (sme->crypto.sae_pwd) {
				brcmf_dbg(INFO, "using SAE offload\n");
				profile->use_fwsup = BRCMF_PROFILE_FWSUP_SAE;
			}
			else {
				profile->use_fwsup = BRCMF_PROFILE_FWSUP_ROAM;
			}
			break;
		default:
			bphy_err(drvr, "invalid akm suite (%d)\n",
				 sme->crypto.akm_suites[0]);
			return -EINVAL;
		}
	}

	if ((profile->use_fwsup == BRCMF_PROFILE_FWSUP_1X) ||
	    (profile->use_fwsup == BRCMF_PROFILE_FWSUP_ROAM)) {
		brcmf_dbg(INFO, "using 1X offload\n");
		err = brcmf_fil_bsscfg_int_get(netdev_priv(ndev), "okc_enable",
					       &okc_enable);
		if (err) {
			bphy_err(drvr, "get okc_enable failed (%d)\n", err);
		} else {
			brcmf_dbg(INFO, "get okc_enable (%d)\n", okc_enable);
			profile->is_okc = okc_enable;
		}
	} else if (profile->use_fwsup != BRCMF_PROFILE_FWSUP_SAE &&
			(val == WPA3_AUTH_SAE_PSK)) {
		brcmf_dbg(INFO, "not using SAE offload\n");
		err = brcmf_fil_bsscfg_int_get(netdev_priv(ndev), "okc_enable",
					       &okc_enable);
		if (err) {
			bphy_err(drvr, "get okc_enable failed (%d)\n", err);
		} else {
			brcmf_dbg(INFO, "get okc_enable (%d)\n", okc_enable);
			profile->is_okc = okc_enable;
		}
	}

	if (!brcmf_feat_is_enabled(ifp, BRCMF_FEAT_MFP))
		goto skip_mfp_config;
	/* The MFP mode (1 or 2) needs to be determined, parse IEs. The
	 * IE will not be verified, just a quick search for MFP config
	 */
	rsn_ie = brcmf_parse_tlvs((const u8 *)sme->ie, sme->ie_len,
				  WLAN_EID_RSN);
	if (!rsn_ie)
		goto skip_mfp_config;
	ie = (const u8 *)rsn_ie;
	ie_len = rsn_ie->len + TLV_HDR_LEN;
	/* Skip unicast suite */
	offset = TLV_HDR_LEN + WPA_IE_VERSION_LEN + WPA_IE_MIN_OUI_LEN;
	if (offset + WPA_IE_SUITE_COUNT_LEN >= ie_len)
		goto skip_mfp_config;
	/* Skip multicast suite */
	count = ie[offset] + (ie[offset + 1] << 8);
	offset += WPA_IE_SUITE_COUNT_LEN + (count * WPA_IE_MIN_OUI_LEN);
	if (offset + WPA_IE_SUITE_COUNT_LEN >= ie_len)
		goto skip_mfp_config;
	/* Skip auth key management suite(s) */
	count = ie[offset] + (ie[offset + 1] << 8);
	offset += WPA_IE_SUITE_COUNT_LEN + (count * WPA_IE_MIN_OUI_LEN);
	if (offset + WPA_IE_SUITE_COUNT_LEN > ie_len)
		goto skip_mfp_config;
	/* Ready to read capabilities */
	mfp = BRCMF_MFP_NONE;
	rsn_cap = ie[offset] + (ie[offset + 1] << 8);
	if (rsn_cap & RSN_CAP_MFPR_MASK)
		mfp = BRCMF_MFP_REQUIRED;
	else if (rsn_cap & RSN_CAP_MFPC_MASK)
		mfp = BRCMF_MFP_CAPABLE;

	/* In case of dpp, very low tput is observed if MFPC is set in
	 * firmmare. Firmware needs to ensure that MFPC is not set when
	 * MFPR was requested from fmac. However since this change being
	 * specific to DPP, fmac needs to set wpa_auth prior to mfp, so
	 * that firmware can use this info to prevent MFPC being set in
	 * case of dpp.
	 */
	if (val == WFA_AUTH_DPP) {
		brcmf_dbg(CONN, "setting wpa_auth to 0x%0x\n", val);
		err = brcmf_fil_bsscfg_int_set(netdev_priv(ndev), "wpa_auth", val);
		if (err) {
			bphy_err(drvr, "could not set wpa_auth (%d)\n", err);
			return err;
		}
	}
	brcmf_fil_bsscfg_int_set(netdev_priv(ndev), "mfp", mfp);

	offset += RSN_CAP_LEN;
	if (mfp && (ie_len - offset >= RSN_PMKID_COUNT_LEN)) {
		pmkid_count = ie[offset] + (ie[offset + 1] << 8);
		offset += RSN_PMKID_COUNT_LEN + (pmkid_count * WLAN_PMKID_LEN);
		if (ie_len - offset >= WPA_IE_MIN_OUI_LEN) {
			group_mgmt_cs = &ie[offset];
			if (memcmp(group_mgmt_cs, RSN_OUI, TLV_OUI_LEN) == 0) {
				brcmf_fil_bsscfg_data_set(ifp, "bip",
							  (void *)group_mgmt_cs,
							  WPA_IE_MIN_OUI_LEN);
			}
		}
	}

skip_mfp_config:
	if (val != WFA_AUTH_DPP) {
		brcmf_dbg(CONN, "setting wpa_auth to 0x%0x\n", val);
		err = brcmf_fil_bsscfg_int_set(netdev_priv(ndev), "wpa_auth", val);
		if (err) {
			bphy_err(drvr, "could not set wpa_auth (%d)\n", err);
			return err;
		}
	}

	return err;
}

static s32
brcmf_set_sharedkey(struct net_device *ndev,
		    struct cfg80211_connect_params *sme)
{
	struct brcmf_if *ifp = netdev_priv(ndev);
	struct brcmf_pub *drvr = ifp->drvr;
	struct brcmf_cfg80211_profile *profile = ndev_to_prof(ndev);
	struct brcmf_cfg80211_security *sec;
	struct brcmf_wsec_key key;
	s32 val;
	s32 err = 0;

	brcmf_dbg(CONN, "key len (%d)\n", sme->key_len);

	if (sme->key_len == 0)
		return 0;

	sec = &profile->sec;
	brcmf_dbg(CONN, "wpa_versions 0x%x cipher_pairwise 0x%x\n",
		  sec->wpa_versions, sec->cipher_pairwise);

	if (sec->wpa_versions & (NL80211_WPA_VERSION_1 | NL80211_WPA_VERSION_2 |
				 NL80211_WPA_VERSION_3))
		return 0;

	if (!(sec->cipher_pairwise &
	    (WLAN_CIPHER_SUITE_WEP40 | WLAN_CIPHER_SUITE_WEP104)))
		return 0;

	memset(&key, 0, sizeof(key));
	key.len = (u32) sme->key_len;
	key.index = (u32) sme->key_idx;
	if (key.len > sizeof(key.data)) {
		bphy_err(drvr, "Too long key length (%u)\n", key.len);
		return -EINVAL;
	}
	memcpy(key.data, sme->key, key.len);
	key.flags = BRCMF_PRIMARY_KEY;
	switch (sec->cipher_pairwise) {
	case WLAN_CIPHER_SUITE_WEP40:
		key.algo = CRYPTO_ALGO_WEP1;
		break;
	case WLAN_CIPHER_SUITE_WEP104:
		key.algo = CRYPTO_ALGO_WEP128;
		break;
	default:
		bphy_err(drvr, "Invalid algorithm (%d)\n",
			 sme->crypto.ciphers_pairwise[0]);
		return -EINVAL;
	}
	/* Set the new key/index */
	brcmf_dbg(CONN, "key length (%d) key index (%d) algo (%d)\n",
		  key.len, key.index, key.algo);
	brcmf_dbg(CONN, "key \"%s\"\n", key.data);
	err = send_key_to_dongle(ifp, &key);
	if (err)
		return err;

	if (sec->auth_type == NL80211_AUTHTYPE_SHARED_KEY) {
		brcmf_dbg(CONN, "set auth_type to shared key\n");
		val = WL_AUTH_SHARED_KEY;	/* shared key */
		err = brcmf_fil_bsscfg_int_set(ifp, "auth", val);
		if (err)
			bphy_err(drvr, "set auth failed (%d)\n", err);
	}
	return err;
}

static
enum nl80211_auth_type brcmf_war_auth_type(struct brcmf_if *ifp,
					   enum nl80211_auth_type type)
{
	if (type == NL80211_AUTHTYPE_AUTOMATIC &&
	    brcmf_feat_is_quirk_enabled(ifp, BRCMF_FEAT_QUIRK_AUTO_AUTH)) {
		brcmf_dbg(CONN, "WAR: use OPEN instead of AUTO\n");
		type = NL80211_AUTHTYPE_OPEN_SYSTEM;
	}
	return type;
}

static void brcmf_set_join_pref(struct brcmf_if *ifp,
				struct cfg80211_bss_selection *bss_select)
{
	struct brcmf_pub *drvr = ifp->drvr;
	struct brcmf_join_pref_params join_pref_params[2];
	enum nl80211_band band;
	int err, i = 0;

	join_pref_params[i].len = 2;
	join_pref_params[i].rssi_gain = 0;

	if (bss_select->behaviour != NL80211_BSS_SELECT_ATTR_BAND_PREF)
		brcmf_fil_cmd_int_set(ifp, BRCMF_C_SET_ASSOC_PREFER, WLC_BAND_AUTO);

	switch (bss_select->behaviour) {
	case __NL80211_BSS_SELECT_ATTR_INVALID:
		brcmf_c_set_joinpref_default(ifp);
		return;
	case NL80211_BSS_SELECT_ATTR_BAND_PREF:
		join_pref_params[i].type = BRCMF_JOIN_PREF_BAND;
		band = bss_select->param.band_pref;
		join_pref_params[i].band = nl80211_band_to_fwil(band);
		i++;
		break;
	case NL80211_BSS_SELECT_ATTR_RSSI_ADJUST:
		join_pref_params[i].type = BRCMF_JOIN_PREF_RSSI_DELTA;
		band = bss_select->param.adjust.band;
		join_pref_params[i].band = nl80211_band_to_fwil(band);
		join_pref_params[i].rssi_gain = bss_select->param.adjust.delta;
		i++;
		break;
	case NL80211_BSS_SELECT_ATTR_RSSI:
	default:
		break;
	}
	join_pref_params[i].type = BRCMF_JOIN_PREF_RSSI;
	join_pref_params[i].len = 2;
	join_pref_params[i].rssi_gain = 0;
	join_pref_params[i].band = 0;
	err = brcmf_fil_iovar_data_set(ifp, "join_pref", join_pref_params,
				       sizeof(join_pref_params));
	if (err)
		bphy_err(drvr, "Set join_pref error (%d)\n", err);
}

static bool
wl_cfg80211_is_oce_ap(struct brcmf_if *ifp,
		      struct wiphy *wiphy, const u8 *bssid_hint)
{
	struct brcmf_pub *drvr = ifp->drvr;
	const struct brcmf_tlv *ie;
	const struct cfg80211_bss_ies *ies;
	struct cfg80211_bss *bss;
	const u8 *parse = NULL;
	u32 len;

	bss = cfg80211_get_bss(wiphy, NULL, bssid_hint, 0, 0,
			       IEEE80211_BSS_TYPE_ANY, IEEE80211_PRIVACY_ANY);
	if (!bss) {
		bphy_err(drvr, "Unable to find AP in the cache");
		return false;
	}

	if (rcu_access_pointer(bss->ies)) {
		ies = rcu_access_pointer(bss->ies);
		parse = ies->data;
		len = ies->len;
	} else {
		bphy_err(drvr, "ies is NULL");
		return false;
	}

	while ((ie = brcmf_parse_tlvs(parse, len, WLAN_EID_VENDOR_SPECIFIC))) {
		if (wl_cfgoce_is_oce_ie((const u8 *)ie,
					(u8 const **)&parse, &len) == true) {
			return true;
		}
	}
	brcmf_dbg(TRACE, "OCE IE NOT found");
	return false;
}

static s32
brcmf_cfg80211_connect(struct wiphy *wiphy, struct net_device *ndev,
		       struct cfg80211_connect_params *sme)
{
	struct brcmf_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct brcmf_if *ifp = netdev_priv(ndev);
	struct brcmf_cfg80211_profile *profile = &ifp->vif->profile;
	struct ieee80211_channel *chan = sme->channel;
	struct brcmf_pub *drvr = ifp->drvr;
	struct brcmf_join_params join_params;
	size_t join_params_size;
	const struct brcmf_tlv *rsn_ie;
	const struct brcmf_vs_tlv *wpa_ie;
	const void *ie;
	u32 ie_len;
	struct brcmf_ext_join_params_le *ext_join_params;
	u16 chanspec;
	s32 err = 0;
	u32 ssid_len;
	bool skip_hints = ifp->drvr->settings->fw_ap_select;

	brcmf_dbg(TRACE, "Enter\n");

	if (cfg->pfn_enable && cfg->pfn_connection) {
		err = brcmf_fil_cmd_data_set(ifp,
					     BRCMF_C_DISASSOC, NULL, 0);
		if (err) {
			brcmf_err("BRCMF_C_DISASSOC error:%d\n", err);
			return -1;
		}
		cfg->pfn_connection = 0;

		/* Disable pfn */
		err = brcmf_fil_iovar_int_set(ifp, "pfn", 0);
		if (err < 0) {
			brcmf_err("pfn disable error:%d\n", err);
		} else {
			/* clear pfn */
			err = brcmf_fil_iovar_data_set(ifp, "pfnclear", NULL, 0);
			if (err)
				brcmf_err("pfnclear error:%d\n", err);
		}
	}

	if (!check_vif_up(ifp->vif))
		return -EIO;

	if (!sme->ssid) {
		bphy_err(drvr, "Invalid ssid\n");
		return -EOPNOTSUPP;
	}

	/* override bssid_hint for oce networks */
	skip_hints = (skip_hints &&
			wl_cfg80211_is_oce_ap(ifp, wiphy, sme->bssid_hint));
	if (skip_hints) {
		/* Let fw choose the best AP */
		brcmf_dbg(TRACE, "Skipping bssid & channel hint\n");
	} else {
		if (sme->channel_hint)
			chan = sme->channel_hint;

		if (sme->bssid_hint)
			sme->bssid = sme->bssid_hint;
	}

	/* FT Cert: Handling the roam request from supplicant for FT roaming */
	if (sme->prev_bssid && sme->bssid &&
	    brcmf_feat_is_enabled(ifp, BRCMF_FEAT_FBT) &&
	    wpa_akm_ft(sme->crypto.akm_suites[0])) {
		/* Only reassoc IOVAR required for Roam skip additional IOVAR */
		struct brcmf_assoc_params_le ext_roam_params;

		brcmf_dbg(CONN, "Trying to REASSOC For FT\n");
		memset(&ext_roam_params, 0, sizeof(ext_roam_params));
		memcpy(&ext_roam_params.bssid, sme->bssid, ETH_ALEN);
		set_bit(BRCMF_VIF_STATUS_CONNECTING, &ifp->vif->sme_state);

		err = brcmf_fil_cmd_data_set(ifp, BRCMF_C_REASSOC,
					     &ext_roam_params,
					     sizeof(ext_roam_params));
		goto done;
	}

	if (ifp->vif == cfg->p2p.bss_idx[P2PAPI_BSSCFG_PRIMARY].vif) {
		/* A normal (non P2P) connection request setup. */
		ie = NULL;
		ie_len = 0;
		/* find the WPA_IE */
		wpa_ie = brcmf_find_wpaie((u8 *)sme->ie, sme->ie_len);
		if (wpa_ie) {
			ie = wpa_ie;
			ie_len = wpa_ie->len + TLV_HDR_LEN;
		} else {
			/* find the RSN_IE */
			rsn_ie = brcmf_parse_tlvs((const u8 *)sme->ie,
						  sme->ie_len,
						  WLAN_EID_RSN);
			if (rsn_ie) {
				ie = rsn_ie;
				ie_len = rsn_ie->len + TLV_HDR_LEN;
			}
		}
		brcmf_fil_iovar_data_set(ifp, "wpaie", ie, ie_len);
	}

	err = brcmf_vif_set_mgmt_ie(ifp->vif, BRCMF_VNDR_IE_ASSOCREQ_FLAG,
				    sme->ie, sme->ie_len);
	if (err)
		bphy_err(drvr, "Set Assoc REQ IE Failed\n");
	else
		brcmf_dbg(TRACE, "Applied Vndr IEs for Assoc request\n");

	set_bit(BRCMF_VIF_STATUS_CONNECTING, &ifp->vif->sme_state);

	if (chan) {
		cfg->channel =
			ieee80211_frequency_to_channel(chan->center_freq);
		chanspec = channel_to_chanspec(&cfg->d11inf, chan);
		brcmf_dbg(CONN, "channel=%d, center_req=%d, chanspec=0x%04x\n",
			  cfg->channel, chan->center_freq, chanspec);
	} else {
		cfg->channel = 0;
		chanspec = 0;
	}

	brcmf_dbg(INFO, "ie (%p), ie_len (%zd)\n", sme->ie, sme->ie_len);

	err = brcmf_set_wpa_version(ndev, sme);
	if (err) {
		bphy_err(drvr, "wl_set_wpa_version failed (%d)\n", err);
		goto done;
	}

	sme->auth_type = brcmf_war_auth_type(ifp, sme->auth_type);
	err = brcmf_set_auth_type(ndev, sme);
	if (err) {
		bphy_err(drvr, "wl_set_auth_type failed (%d)\n", err);
		goto done;
	}

	err = brcmf_set_wsec_mode(ndev, sme);
	if (err) {
		bphy_err(drvr, "wl_set_set_cipher failed (%d)\n", err);
		goto done;
	}

	err = brcmf_set_key_mgmt(ndev, sme);
	if (err) {
		bphy_err(drvr, "wl_set_key_mgmt failed (%d)\n", err);
		goto done;
	}

	err = brcmf_set_sharedkey(ndev, sme);
	if (err) {
		bphy_err(drvr, "brcmf_set_sharedkey failed (%d)\n", err);
		goto done;
	}

	if (brcmf_feat_is_enabled(ifp, BRCMF_FEAT_FWSUP)) {
		if (sme->crypto.psk) {
			if ((profile->use_fwsup != BRCMF_PROFILE_FWSUP_SAE) &&
				(profile->use_fwsup != BRCMF_PROFILE_FWSUP_PSK)) {
				if (WARN_ON(profile->use_fwsup !=
					BRCMF_PROFILE_FWSUP_NONE)) {
					err = -EINVAL;
					goto done;
				}
				brcmf_dbg(INFO, "using PSK offload\n");
				profile->use_fwsup = BRCMF_PROFILE_FWSUP_PSK;
			}
		}

		if (profile->use_fwsup != BRCMF_PROFILE_FWSUP_NONE) {
			/* enable firmware supplicant for this interface */
			err = brcmf_fil_iovar_int_set(ifp, "sup_wpa", 1);
			if (err < 0) {
				bphy_err(drvr, "failed to enable fw supplicant\n");
				goto done;
			}
		} else {
			err = brcmf_fil_iovar_int_set(ifp, "sup_wpa", 0);
		}

		if ((profile->use_fwsup == BRCMF_PROFILE_FWSUP_PSK) &&
			sme->crypto.psk)
			err = brcmf_set_pmk(ifp, sme->crypto.psk,
					    BRCMF_WSEC_MAX_PSK_LEN);

		/* if upper layer has passed sae_password,
		 * set it to firmware for the potential transit up roaming use.
		 */
		if (sme->crypto.sae_pwd && brcmf_feat_is_enabled(ifp, BRCMF_FEAT_SAE)) {
			/* clean up user-space RSNE */
			if (brcmf_fil_iovar_data_set(ifp, "wpaie", NULL, 0)) {
				bphy_err(drvr, "failed to clean up user-space RSNE\n");
				goto done;
			}
			err = brcmf_set_sae_password(ifp, sme->crypto.sae_pwd,
						     sme->crypto.sae_pwd_len);
			if (!err && sme->crypto.psk)
				err = brcmf_set_pmk(ifp, sme->crypto.psk,
						    BRCMF_WSEC_MAX_PSK_LEN);
		}
		if (err)
			goto done;

		if (brcmf_feat_is_enabled(ifp, BRCMF_FEAT_OWE) &&
		    sme->crypto.akm_suites[0] == WLAN_AKM_SUITE_OWE) {
			/* clean up user-space RSNE */
			if (brcmf_fil_iovar_data_set(ifp, "wpaie", NULL, 0)) {
				bphy_err(drvr, "failed to clean up user-space RSNE\n");
				goto done;
			}
		}

	}
	/* Join with specific BSSID and cached SSID
	 * If SSID is zero join based on BSSID only
	 */
	join_params_size = offsetof(struct brcmf_ext_join_params_le, assoc_le) +
		offsetof(struct brcmf_assoc_params_le, chanspec_list);
	if (cfg->channel)
		join_params_size += sizeof(u16);
	ext_join_params = kzalloc(sizeof(*ext_join_params), GFP_KERNEL);
	if (ext_join_params == NULL) {
		err = -ENOMEM;
		goto done;
	}
	ssid_len = min_t(u32, sme->ssid_len, IEEE80211_MAX_SSID_LEN);
	ext_join_params->ssid_le.SSID_len = cpu_to_le32(ssid_len);
	memcpy(&ext_join_params->ssid_le.SSID, sme->ssid, ssid_len);
	if (ssid_len < IEEE80211_MAX_SSID_LEN)
		brcmf_dbg(CONN, "SSID \"%s\", len (%d)\n",
			  ext_join_params->ssid_le.SSID, ssid_len);

	/* Set up join scan parameters */
	ext_join_params->scan_le.scan_type = -1;
	ext_join_params->scan_le.home_time = cpu_to_le32(-1);

	if (sme->bssid)
		memcpy(&ext_join_params->assoc_le.bssid, sme->bssid, ETH_ALEN);
	else
		eth_broadcast_addr(ext_join_params->assoc_le.bssid);

	if (cfg->channel) {
		ext_join_params->assoc_le.chanspec_num = cpu_to_le32(1);
		ext_join_params->assoc_le.chanspec_list[0] =
			cpu_to_le16(chanspec);

		/* Increase dwell time to receive probe response or detect
		 * beacon from target AP at a noisy air only during connect
		 * command.
		 */
		if (BRCMU_CHSPEC_IS6G(chanspec)) {
			ext_join_params->scan_le.active_time =
				cpu_to_le32(BRCMF_SCAN_JOIN_ACTIVE_DWELL_TIME_MS_6E);
			ext_join_params->scan_le.passive_time =
				cpu_to_le32(BRCMF_SCAN_JOIN_PASSIVE_DWELL_TIME_MS_6E);
		} else {
			ext_join_params->scan_le.active_time =
				cpu_to_le32(BRCMF_SCAN_JOIN_ACTIVE_DWELL_TIME_MS);
			ext_join_params->scan_le.passive_time =
				cpu_to_le32(BRCMF_SCAN_JOIN_PASSIVE_DWELL_TIME_MS);
		}

		/* To sync with presence period of VSDB GO send probe request
		 * more frequently. Probe request will be stopped when it gets
		 * probe response from target AP/GO.
		 */
		ext_join_params->scan_le.nprobes =
			cpu_to_le32(BRCMF_SCAN_JOIN_ACTIVE_DWELL_TIME_MS /
				    BRCMF_SCAN_JOIN_PROBE_INTERVAL_MS);
	} else {
		ext_join_params->scan_le.active_time = cpu_to_le32(-1);
		ext_join_params->scan_le.passive_time = cpu_to_le32(-1);
		ext_join_params->scan_le.nprobes = cpu_to_le32(-1);
	}

	brcmf_set_join_pref(ifp, &sme->bss_select);

	/* The internal supplicant judges to use assoc or reassoc itself.
	 * it is not necessary to specify REASSOC
	 */
	if ((sme->prev_bssid) && !brcmf_feat_is_enabled(ifp, BRCMF_FEAT_FWSUP)) {
		brcmf_dbg(CONN, "Trying to REASSOC\n");
		join_params_size = sizeof(ext_join_params->assoc_le);
		err = brcmf_fil_cmd_data_set(ifp, BRCMF_C_REASSOC,
					     &ext_join_params->assoc_le, join_params_size);
	} else {
		err  = brcmf_fil_bsscfg_data_set(ifp, "join", ext_join_params,
						 join_params_size);
	}
	kfree(ext_join_params);
	if (!err)
		/* This is it. join command worked, we are done */
		goto done;

	/* join command failed, fallback to set ssid */
	memset(&join_params, 0, sizeof(join_params));
	join_params_size = sizeof(join_params.ssid_le);

	memcpy(&join_params.ssid_le.SSID, sme->ssid, ssid_len);
	join_params.ssid_le.SSID_len = cpu_to_le32(ssid_len);

	if (sme->bssid)
		memcpy(join_params.params_le.bssid, sme->bssid, ETH_ALEN);
	else
		eth_broadcast_addr(join_params.params_le.bssid);

	if (cfg->channel) {
		join_params.params_le.chanspec_list[0] = cpu_to_le16(chanspec);
		join_params.params_le.chanspec_num = cpu_to_le32(1);
		join_params_size += sizeof(join_params.params_le);
	}
	err = brcmf_fil_cmd_data_set(ifp, BRCMF_C_SET_SSID,
				     &join_params, join_params_size);
	if (err)
		bphy_err(drvr, "BRCMF_C_SET_SSID failed (%d)\n", err);

done:
	if (err)
		clear_bit(BRCMF_VIF_STATUS_CONNECTING, &ifp->vif->sme_state);
	brcmf_dbg(TRACE, "Exit\n");
	return err;
}

static s32
brcmf_cfg80211_disconnect(struct wiphy *wiphy, struct net_device *ndev,
		       u16 reason_code)
{
	struct brcmf_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct brcmf_if *ifp = netdev_priv(ndev);
	struct brcmf_cfg80211_profile *profile = &ifp->vif->profile;
	struct brcmf_pub *drvr = cfg->pub;
	struct brcmf_scb_val_le scbval;
	s32 err = 0;

	brcmf_dbg(TRACE, "Enter. Reason code = %d\n", reason_code);
	if (!check_vif_up(ifp->vif))
		return -EIO;

	clear_bit(BRCMF_VIF_STATUS_CONNECTED, &ifp->vif->sme_state);
	clear_bit(BRCMF_VIF_STATUS_CONNECTING, &ifp->vif->sme_state);
	clear_bit(BRCMF_VIF_STATUS_EAP_SUCCESS, &ifp->vif->sme_state);
	clear_bit(BRCMF_VIF_STATUS_ASSOC_SUCCESS, &ifp->vif->sme_state);
	cfg80211_disconnected(ndev, reason_code, NULL, 0, true, GFP_KERNEL);

	if (cfg->pfn_enable) {
		cfg->pfn_connection = 0;
		pfn_send_network_blob_fw(wiphy, &ifp->vif->wdev);
	}

	memcpy(&scbval.ea, &profile->bssid, ETH_ALEN);
	scbval.val = cpu_to_le32(reason_code);
	err = brcmf_fil_cmd_data_set(ifp, BRCMF_C_DISASSOC,
				     &scbval, sizeof(scbval));
	if (err) {
		bphy_err(drvr, "error (%d)\n", err);
	} else {
		if (brcmf_feat_is_enabled(ifp, BRCMF_FEAT_TWT)) {
		         /* Cleanup TWT Session list */
		        brcmf_twt_cleanup_sessions(ifp);
		}
	}

	brcmf_dbg(TRACE, "Exit\n");
	return err;
}

static s32
brcmf_cfg80211_set_tx_power(struct wiphy *wiphy, struct wireless_dev *wdev,
			    enum nl80211_tx_power_setting type, s32 mbm)
{
	struct brcmf_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct net_device *ndev = cfg_to_ndev(cfg);
	struct brcmf_if *ifp = netdev_priv(ndev);
	struct brcmf_pub *drvr = cfg->pub;
	s32 err;
	s32 disable;
	u32 qdbm = 127;

	brcmf_dbg(TRACE, "Enter %d %d\n", type, mbm);
	if (!check_vif_up(ifp->vif))
		return -EIO;

	switch (type) {
	case NL80211_TX_POWER_AUTOMATIC:
		break;
	case NL80211_TX_POWER_LIMITED:
	case NL80211_TX_POWER_FIXED:
		if (mbm < 0) {
			bphy_err(drvr, "TX_POWER_FIXED - dbm is negative\n");
			err = -EINVAL;
			goto done;
		}
		qdbm =  MBM_TO_DBM(4 * mbm);
		if (qdbm > 127)
			qdbm = 127;
		qdbm |= WL_TXPWR_OVERRIDE;
		break;
	default:
		bphy_err(drvr, "Unsupported type %d\n", type);
		err = -EINVAL;
		goto done;
	}
	/* Make sure radio is off or on as far as software is concerned */
	disable = WL_RADIO_SW_DISABLE << 16;
	err = brcmf_fil_cmd_int_set(ifp, BRCMF_C_SET_RADIO, disable);
	if (err)
		bphy_err(drvr, "WLC_SET_RADIO error (%d)\n", err);

	err = brcmf_fil_iovar_int_set(ifp, "qtxpower", qdbm);
	if (err)
		bphy_err(drvr, "qtxpower error (%d)\n", err);

done:
	brcmf_dbg(TRACE, "Exit %d (qdbm)\n", qdbm & ~WL_TXPWR_OVERRIDE);
	return err;
}

static s32
brcmf_cfg80211_get_tx_power(struct wiphy *wiphy, struct wireless_dev *wdev,
			    s32 *dbm)
{
	struct brcmf_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct brcmf_cfg80211_vif *vif = wdev_to_vif(wdev);
	struct brcmf_pub *drvr = cfg->pub;
	s32 qdbm = 0;
	s32 err;

	brcmf_dbg(TRACE, "Enter\n");
	if (!check_vif_up(vif))
		return -EIO;

	err = brcmf_fil_iovar_int_get(vif->ifp, "qtxpower", &qdbm);
	if (err) {
		bphy_err(drvr, "error (%d)\n", err);
		goto done;
	}
	*dbm = (qdbm & ~WL_TXPWR_OVERRIDE) / 4;

done:
	brcmf_dbg(TRACE, "Exit (0x%x %d)\n", qdbm, *dbm);
	return err;
}

static s32
brcmf_cfg80211_config_default_key(struct wiphy *wiphy, struct net_device *ndev,
				  int link_id, u8 key_idx, bool unicast,
				  bool multicast)
{
	struct brcmf_if *ifp = netdev_priv(ndev);
	struct brcmf_pub *drvr = ifp->drvr;
	u32 index;
	u32 wsec;
	s32 err = 0;

	brcmf_dbg(TRACE, "Enter\n");
	brcmf_dbg(CONN, "key index (%d)\n", key_idx);
	if (!check_vif_up(ifp->vif))
		return -EIO;

	err = brcmf_fil_bsscfg_int_get(ifp, "wsec", &wsec);
	if (err) {
		bphy_err(drvr, "WLC_GET_WSEC error (%d)\n", err);
		goto done;
	}

	if (wsec & WEP_ENABLED) {
		/* Just select a new current key */
		index = key_idx;
		err = brcmf_fil_cmd_int_set(ifp,
					    BRCMF_C_SET_KEY_PRIMARY, index);
		if (err)
			bphy_err(drvr, "error (%d)\n", err);
	}
done:
	brcmf_dbg(TRACE, "Exit\n");
	return err;
}

static s32
brcmf_cfg80211_del_key(struct wiphy *wiphy, struct net_device *ndev,
		       int link_id, u8 key_idx, bool pairwise,
		       const u8 *mac_addr)
{
	struct brcmf_if *ifp = netdev_priv(ndev);
	struct brcmf_wsec_key *key;
	s32 err;

	brcmf_dbg(TRACE, "Enter\n");
	brcmf_dbg(CONN, "key index (%d)\n", key_idx);

	if (!check_vif_up(ifp->vif))
		return -EIO;

	if (key_idx >= BRCMF_MAX_DEFAULT_KEYS) {
		/* we ignore this key index in this case */
		return -EINVAL;
	}

	key = &ifp->vif->profile.key[key_idx];

	if (key->algo == CRYPTO_ALGO_OFF) {
		brcmf_dbg(CONN, "Ignore clearing of (never configured) key\n");
		return -EINVAL;
	}

	memset(key, 0, sizeof(*key));
	key->index = (u32)key_idx;
	key->flags = BRCMF_PRIMARY_KEY;

	/* Clear the key/index */
	err = send_key_to_dongle(ifp, key);

	brcmf_dbg(TRACE, "Exit\n");
	return err;
}

static s32
brcmf_cfg80211_add_key(struct wiphy *wiphy, struct net_device *ndev,
		       int link_id, u8 key_idx, bool pairwise,
		       const u8 *mac_addr, struct key_params *params)
{
	struct brcmf_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct brcmf_if *ifp = netdev_priv(ndev);
	struct brcmf_pub *drvr = cfg->pub;
	struct brcmf_wsec_key *key;
	s32 val;
	s32 wsec;
	s32 err;
	u8 keybuf[8];
	bool ext_key;
	u32 algos = 0, mask = 0;

	brcmf_dbg(TRACE, "Enter\n");
	brcmf_dbg(CONN, "key index (%d)\n", key_idx);
	if (!check_vif_up(ifp->vif))
		return -EIO;

	if (key_idx >= BRCMF_MAX_DEFAULT_KEYS) {
		/* we ignore this key index in this case */
		bphy_err(drvr, "invalid key index (%d)\n", key_idx);
		return -EINVAL;
	}

	if (params->key_len == 0)
		return brcmf_cfg80211_del_key(wiphy, ndev, -1, key_idx,
					      pairwise, mac_addr);

	if (params->key_len > sizeof(key->data)) {
		bphy_err(drvr, "Too long key length (%u)\n", params->key_len);
		return -EINVAL;
	}

	ext_key = false;
	if (mac_addr && (params->cipher != WLAN_CIPHER_SUITE_WEP40) &&
	    (params->cipher != WLAN_CIPHER_SUITE_WEP104)) {
		brcmf_dbg(TRACE, "Ext key, mac %pM", mac_addr);
		ext_key = true;
	}

	key = &ifp->vif->profile.key[key_idx];
	memset(key, 0, sizeof(*key));
	if ((ext_key) && (!is_multicast_ether_addr(mac_addr)))
		memcpy((char *)&key->ea, (void *)mac_addr, ETH_ALEN);
	key->len = params->key_len;
	key->index = key_idx;
	memcpy(key->data, params->key, key->len);
	if (!ext_key)
		key->flags = BRCMF_PRIMARY_KEY;

	if (params->seq && params->seq_len == 6) {
		/* rx iv */
		u8 *ivptr;

		ivptr = (u8 *)params->seq;
		key->rxiv.hi = (ivptr[5] << 24) | (ivptr[4] << 16) |
			(ivptr[3] << 8) | ivptr[2];
		key->rxiv.lo = (ivptr[1] << 8) | ivptr[0];
		key->iv_initialized = true;
	}

	switch (params->cipher) {
	case WLAN_CIPHER_SUITE_WEP40:
		key->algo = CRYPTO_ALGO_WEP1;
		val = WEP_ENABLED;
		brcmf_dbg(CONN, "WLAN_CIPHER_SUITE_WEP40\n");
		break;
	case WLAN_CIPHER_SUITE_WEP104:
		key->algo = CRYPTO_ALGO_WEP128;
		val = WEP_ENABLED;
		brcmf_dbg(CONN, "WLAN_CIPHER_SUITE_WEP104\n");
		break;
	case WLAN_CIPHER_SUITE_TKIP:
		if (!brcmf_is_apmode(ifp->vif)) {
			brcmf_dbg(CONN, "Swapping RX/TX MIC key\n");
			memcpy(keybuf, &key->data[24], sizeof(keybuf));
			memcpy(&key->data[24], &key->data[16], sizeof(keybuf));
			memcpy(&key->data[16], keybuf, sizeof(keybuf));
		}
		key->algo = CRYPTO_ALGO_TKIP;
		val = TKIP_ENABLED;
		brcmf_dbg(CONN, "WLAN_CIPHER_SUITE_TKIP\n");
		break;
	case WLAN_CIPHER_SUITE_AES_CMAC:
		key->algo = CRYPTO_ALGO_AES_CCM;
		val = AES_ENABLED;
		brcmf_dbg(CONN, "WLAN_CIPHER_SUITE_AES_CMAC\n");
		break;
	case WLAN_CIPHER_SUITE_CCMP:
		key->algo = CRYPTO_ALGO_AES_CCM;
		val = AES_ENABLED;
		brcmf_dbg(CONN, "WLAN_CIPHER_SUITE_CCMP\n");
		break;
	case WLAN_CIPHER_SUITE_GCMP_256:
		if (!brcmf_feat_is_enabled(ifp, BRCMF_FEAT_GCMP)) {
			brcmf_err("the low layer not support GCMP\n");
			err = -EOPNOTSUPP;
			goto done;
		}
		key->algo = CRYPTO_ALGO_AES_GCM256;
		val = AES_ENABLED;
		brcmf_dbg(CONN, "WLAN_CIPHER_SUITE_GCMP_256\n");
		algos = KEY_ALGO_MASK(CRYPTO_ALGO_AES_GCM256);
		mask = algos | KEY_ALGO_MASK(CRYPTO_ALGO_AES_CCM);
		break;
	case WLAN_CIPHER_SUITE_BIP_GMAC_256:
		if (!brcmf_feat_is_enabled(ifp, BRCMF_FEAT_GCMP)) {
			brcmf_err("the low layer not support GCMP\n");
			err = -EOPNOTSUPP;
			goto done;
		}
		key->algo = CRYPTO_ALGO_BIP_GMAC256;
		val = AES_ENABLED;
		algos = KEY_ALGO_MASK(CRYPTO_ALGO_BIP_GMAC256);
		mask = algos | KEY_ALGO_MASK(CRYPTO_ALGO_AES_CCM);
		brcmf_dbg(CONN, "WLAN_CIPHER_SUITE_BIP_GMAC_256\n");
		break;
	default:
		bphy_err(drvr, "Invalid cipher (0x%x)\n", params->cipher);
		err = -EINVAL;
		goto done;
	}

	err = send_key_to_dongle(ifp, key);
	if (ext_key || err)
		goto done;

	err = brcmf_fil_bsscfg_int_get(ifp, "wsec", &wsec);
	if (err) {
		bphy_err(drvr, "get wsec error (%d)\n", err);
		goto done;
	}
	wsec |= val;
	err = brcmf_fil_bsscfg_int_set(ifp, "wsec", wsec);
	if (err) {
		bphy_err(drvr, "set wsec error (%d)\n", err);
		goto done;
	}

	if (brcmf_feat_is_enabled(ifp, BRCMF_FEAT_GCMP)) {
		brcmf_dbg(CONN,
			  "set_wsdec_info algos (0x%x) mask (0x%x)\n",
			  algos, mask);
		err = wl_set_wsec_info_algos(ifp, algos, mask);
		if (err) {
			brcmf_err("set wsec_info error (%d)\n", err);
			return err;
		}
	}

done:
	brcmf_dbg(TRACE, "Exit\n");
	return err;
}

static s32
brcmf_cfg80211_get_key(struct wiphy *wiphy, struct net_device *ndev,
		       int link_id, u8 key_idx, bool pairwise,
		       const u8 *mac_addr, void *cookie,
		       void (*callback)(void *cookie,
					struct key_params *params))
{
	struct brcmf_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct key_params params;
	struct brcmf_if *ifp = netdev_priv(ndev);
	struct brcmf_cfg80211_profile *profile = &ifp->vif->profile;
	struct brcmf_pub *drvr = cfg->pub;
	struct brcmf_cfg80211_security *sec;
	s32 wsec;
	s32 err = 0;

	brcmf_dbg(TRACE, "Enter\n");
	brcmf_dbg(CONN, "key index (%d)\n", key_idx);
	if (!check_vif_up(ifp->vif))
		return -EIO;

	memset(&params, 0, sizeof(params));

	err = brcmf_fil_bsscfg_int_get(ifp, "wsec", &wsec);
	if (err) {
		bphy_err(drvr, "WLC_GET_WSEC error (%d)\n", err);
		/* Ignore this error, may happen during DISASSOC */
		err = -EAGAIN;
		goto done;
	}
	if (wsec & WEP_ENABLED) {
		sec = &profile->sec;
		if (sec->cipher_pairwise & WLAN_CIPHER_SUITE_WEP40) {
			params.cipher = WLAN_CIPHER_SUITE_WEP40;
			brcmf_dbg(CONN, "WLAN_CIPHER_SUITE_WEP40\n");
		} else if (sec->cipher_pairwise & WLAN_CIPHER_SUITE_WEP104) {
			params.cipher = WLAN_CIPHER_SUITE_WEP104;
			brcmf_dbg(CONN, "WLAN_CIPHER_SUITE_WEP104\n");
		}
	} else if (wsec & TKIP_ENABLED) {
		params.cipher = WLAN_CIPHER_SUITE_TKIP;
		brcmf_dbg(CONN, "WLAN_CIPHER_SUITE_TKIP\n");
	} else if (wsec & AES_ENABLED) {
		params.cipher = WLAN_CIPHER_SUITE_AES_CMAC;
		brcmf_dbg(CONN, "WLAN_CIPHER_SUITE_AES_CMAC\n");
	} else  {
		bphy_err(drvr, "Invalid algo (0x%x)\n", wsec);
		err = -EINVAL;
		goto done;
	}
	callback(cookie, &params);

done:
	brcmf_dbg(TRACE, "Exit\n");
	return err;
}

static s32
brcmf_cfg80211_config_default_mgmt_key(struct wiphy *wiphy,
				       struct net_device *ndev, int link_id,
				       u8 key_idx)
{
	struct brcmf_if *ifp = netdev_priv(ndev);

	brcmf_dbg(TRACE, "Enter key_idx %d\n", key_idx);

	if (brcmf_feat_is_enabled(ifp, BRCMF_FEAT_MFP))
		return 0;

	brcmf_dbg(INFO, "Not supported\n");

	return -EOPNOTSUPP;
}

static void
brcmf_cfg80211_reconfigure_wep(struct brcmf_if *ifp)
{
	struct brcmf_pub *drvr = ifp->drvr;
	s32 err;
	u8 key_idx;
	struct brcmf_wsec_key *key;
	s32 wsec;

	for (key_idx = 0; key_idx < BRCMF_MAX_DEFAULT_KEYS; key_idx++) {
		key = &ifp->vif->profile.key[key_idx];
		if ((key->algo == CRYPTO_ALGO_WEP1) ||
		    (key->algo == CRYPTO_ALGO_WEP128))
			break;
	}
	if (key_idx == BRCMF_MAX_DEFAULT_KEYS)
		return;

	err = send_key_to_dongle(ifp, key);
	if (err) {
		bphy_err(drvr, "Setting WEP key failed (%d)\n", err);
		return;
	}
	err = brcmf_fil_bsscfg_int_get(ifp, "wsec", &wsec);
	if (err) {
		bphy_err(drvr, "get wsec error (%d)\n", err);
		return;
	}
	wsec |= WEP_ENABLED;
	err = brcmf_fil_bsscfg_int_set(ifp, "wsec", wsec);
	if (err)
		bphy_err(drvr, "set wsec error (%d)\n", err);
}

static void brcmf_convert_sta_flags(u32 fw_sta_flags, struct station_info *si)
{
	struct nl80211_sta_flag_update *sfu;

	brcmf_dbg(TRACE, "flags %08x\n", fw_sta_flags);
	si->filled |= BIT_ULL(NL80211_STA_INFO_STA_FLAGS);
	sfu = &si->sta_flags;
	sfu->mask = BIT(NL80211_STA_FLAG_WME) |
		    BIT(NL80211_STA_FLAG_AUTHENTICATED) |
		    BIT(NL80211_STA_FLAG_ASSOCIATED) |
		    BIT(NL80211_STA_FLAG_AUTHORIZED);
	if (fw_sta_flags & BRCMF_STA_WME)
		sfu->set |= BIT(NL80211_STA_FLAG_WME);
	if (fw_sta_flags & BRCMF_STA_AUTHE)
		sfu->set |= BIT(NL80211_STA_FLAG_AUTHENTICATED);
	if (fw_sta_flags & BRCMF_STA_ASSOC)
		sfu->set |= BIT(NL80211_STA_FLAG_ASSOCIATED);
	if (fw_sta_flags & BRCMF_STA_AUTHO)
		sfu->set |= BIT(NL80211_STA_FLAG_AUTHORIZED);
}

static void brcmf_fill_bss_param(struct brcmf_if *ifp, struct station_info *si)
{
	struct brcmf_pub *drvr = ifp->drvr;
	struct {
		__le32 len;
		struct brcmf_bss_info_le bss_le;
	} *buf;
	u16 capability;
	int err;

	buf = kzalloc(WL_BSS_INFO_MAX, GFP_KERNEL);
	if (!buf)
		return;

	buf->len = cpu_to_le32(WL_BSS_INFO_MAX);
	err = brcmf_fil_cmd_data_get(ifp, BRCMF_C_GET_BSS_INFO, buf,
				     WL_BSS_INFO_MAX);
	if (err) {
		bphy_err(drvr, "Failed to get bss info (%d)\n", err);
		goto out_kfree;
	}
	si->filled |= BIT_ULL(NL80211_STA_INFO_BSS_PARAM);
	si->bss_param.beacon_interval = le16_to_cpu(buf->bss_le.beacon_period);
	si->bss_param.dtim_period = buf->bss_le.dtim_period;
	capability = le16_to_cpu(buf->bss_le.capability);
	if (capability & IEEE80211_HT_STBC_PARAM_DUAL_CTS_PROT)
		si->bss_param.flags |= BSS_PARAM_FLAGS_CTS_PROT;
	if (capability & WLAN_CAPABILITY_SHORT_PREAMBLE)
		si->bss_param.flags |= BSS_PARAM_FLAGS_SHORT_PREAMBLE;
	if (capability & WLAN_CAPABILITY_SHORT_SLOT_TIME)
		si->bss_param.flags |= BSS_PARAM_FLAGS_SHORT_SLOT_TIME;

out_kfree:
	kfree(buf);
}

static s32
brcmf_cfg80211_get_station_ibss(struct brcmf_if *ifp,
				struct station_info *sinfo,
				const u8 *mac)
{
	struct brcmf_pub *drvr = ifp->drvr;
	struct brcmf_scb_val_le scbval;
	struct brcmf_pktcnt_le pktcnt;
	s32 err;
	u32 rate;
	u32 rssi;

	/* Get the current tx rate */
	err = brcmf_fil_cmd_int_get(ifp, BRCMF_C_GET_RATE, &rate);
	if (err < 0) {
		bphy_err(drvr, "BRCMF_C_GET_RATE error (%d)\n", err);
		return err;
	}
	sinfo->filled |= BIT_ULL(NL80211_STA_INFO_TX_BITRATE);
	sinfo->txrate.legacy = rate * 5;

	memset(&scbval, 0, sizeof(scbval));
	memcpy(&scbval.ea[0], mac, ETH_ALEN);
	err = brcmf_fil_cmd_data_get(ifp, BRCMF_C_GET_RSSI, &scbval,
				     sizeof(scbval));
	if (err) {
		bphy_err(drvr, "BRCMF_C_GET_RSSI error (%d)\n", err);
		return err;
	}
	rssi = le32_to_cpu(scbval.val);
	sinfo->filled |= BIT_ULL(NL80211_STA_INFO_SIGNAL);
	sinfo->signal = rssi;

	err = brcmf_fil_cmd_data_get(ifp, BRCMF_C_GET_GET_PKTCNTS, &pktcnt,
				     sizeof(pktcnt));
	if (err) {
		bphy_err(drvr, "BRCMF_C_GET_GET_PKTCNTS error (%d)\n", err);
		return err;
	}
	sinfo->filled |= BIT_ULL(NL80211_STA_INFO_RX_PACKETS) |
			 BIT_ULL(NL80211_STA_INFO_RX_DROP_MISC) |
			 BIT_ULL(NL80211_STA_INFO_TX_PACKETS) |
			 BIT_ULL(NL80211_STA_INFO_TX_FAILED);
	sinfo->rx_packets = le32_to_cpu(pktcnt.rx_good_pkt);
	sinfo->rx_dropped_misc = le32_to_cpu(pktcnt.rx_bad_pkt);
	sinfo->tx_packets = le32_to_cpu(pktcnt.tx_good_pkt);
	sinfo->tx_failed  = le32_to_cpu(pktcnt.tx_bad_pkt);

	return 0;
}

static s32
brcmf_cfg80211_get_station(struct wiphy *wiphy, struct net_device *ndev,
			   const u8 *mac, struct station_info *sinfo)
{
	struct brcmf_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct brcmf_if *ifp = netdev_priv(ndev);
	struct brcmf_pub *drvr = cfg->pub;
	struct brcmf_scb_val_le scb_val;
	s32 err = 0;
	struct brcmf_sta_info_le sta_info_le;
	u32 sta_flags;
	u32 is_tdls_peer;
	s32 total_rssi_avg = 0;
	s32 total_rssi = 0;
	s32 count_rssi = 0;
	int rssi;
	u32 i;

	brcmf_dbg(TRACE, "Enter, MAC %pM\n", mac);
	if (!check_vif_up(ifp->vif))
		return -EIO;

	if (brcmf_is_ibssmode(ifp->vif))
		return brcmf_cfg80211_get_station_ibss(ifp, sinfo, mac);

	memset(&sta_info_le, 0, sizeof(sta_info_le));
	memcpy(&sta_info_le, mac, ETH_ALEN);
	err = brcmf_fil_iovar_data_get(ifp, "tdls_sta_info",
				       &sta_info_le,
				       sizeof(sta_info_le));
	is_tdls_peer = !err;
	if (err) {
		err = brcmf_fil_iovar_data_get(ifp, "sta_info",
					       &sta_info_le,
					       sizeof(sta_info_le));
		if (err < 0) {
			bphy_err(drvr, "GET STA INFO failed, %d\n", err);
			goto done;
		}
	}
	brcmf_dbg(TRACE, "version %d\n", le16_to_cpu(sta_info_le.ver));
	sinfo->filled = BIT_ULL(NL80211_STA_INFO_INACTIVE_TIME);
	sinfo->inactive_time = le32_to_cpu(sta_info_le.idle) * 1000;
	sta_flags = le32_to_cpu(sta_info_le.flags);
	brcmf_convert_sta_flags(sta_flags, sinfo);
	sinfo->sta_flags.mask |= BIT(NL80211_STA_FLAG_TDLS_PEER);
	if (is_tdls_peer)
		sinfo->sta_flags.set |= BIT(NL80211_STA_FLAG_TDLS_PEER);
	else
		sinfo->sta_flags.set &= ~BIT(NL80211_STA_FLAG_TDLS_PEER);
	if (sta_flags & BRCMF_STA_ASSOC) {
		sinfo->filled |= BIT_ULL(NL80211_STA_INFO_CONNECTED_TIME);
		sinfo->connected_time = le32_to_cpu(sta_info_le.in);
		brcmf_fill_bss_param(ifp, sinfo);
	}
	if (sta_flags & BRCMF_STA_SCBSTATS) {
		sinfo->filled |= BIT_ULL(NL80211_STA_INFO_TX_FAILED);
		sinfo->tx_failed = le32_to_cpu(sta_info_le.tx_failures);
		sinfo->filled |= BIT_ULL(NL80211_STA_INFO_TX_PACKETS);
		sinfo->tx_packets = le32_to_cpu(sta_info_le.tx_pkts);
		sinfo->tx_packets += le32_to_cpu(sta_info_le.tx_mcast_pkts);
		sinfo->filled |= BIT_ULL(NL80211_STA_INFO_RX_PACKETS);
		sinfo->rx_packets = le32_to_cpu(sta_info_le.rx_ucast_pkts);
		sinfo->rx_packets += le32_to_cpu(sta_info_le.rx_mcast_pkts);
		if (sinfo->tx_packets) {
			sinfo->filled |= BIT_ULL(NL80211_STA_INFO_TX_BITRATE);
			sinfo->txrate.legacy =
				le32_to_cpu(sta_info_le.tx_rate) / 100;
		}
		if (sinfo->rx_packets) {
			sinfo->filled |= BIT_ULL(NL80211_STA_INFO_RX_BITRATE);
			sinfo->rxrate.legacy =
				le32_to_cpu(sta_info_le.rx_rate) / 100;
		}
		if (le16_to_cpu(sta_info_le.ver) >= 4) {
			sinfo->filled |= BIT_ULL(NL80211_STA_INFO_TX_BYTES);
			sinfo->tx_bytes = le64_to_cpu(sta_info_le.tx_tot_bytes);
			sinfo->filled |= BIT_ULL(NL80211_STA_INFO_RX_BYTES);
			sinfo->rx_bytes = le64_to_cpu(sta_info_le.rx_tot_bytes);
		}
		for (i = 0; i < BRCMF_ANT_MAX; i++) {
			if (sta_info_le.rssi[i] == 0 ||
			    sta_info_le.rx_lastpkt_rssi[i] == 0)
				continue;
			sinfo->chains |= BIT(count_rssi);
			sinfo->chain_signal[count_rssi] =
				sta_info_le.rx_lastpkt_rssi[i];
			sinfo->chain_signal_avg[count_rssi] =
				sta_info_le.rssi[i];
			total_rssi += sta_info_le.rx_lastpkt_rssi[i];
			total_rssi_avg += sta_info_le.rssi[i];
			count_rssi++;
		}
		if (count_rssi) {
			sinfo->filled |= BIT_ULL(NL80211_STA_INFO_SIGNAL);
			sinfo->filled |= BIT_ULL(NL80211_STA_INFO_SIGNAL_AVG);
			sinfo->filled |= BIT_ULL(NL80211_STA_INFO_CHAIN_SIGNAL);
			sinfo->filled |=
				BIT_ULL(NL80211_STA_INFO_CHAIN_SIGNAL_AVG);
			sinfo->signal = total_rssi / count_rssi;
			sinfo->signal_avg = total_rssi_avg / count_rssi;
		} else if (test_bit(BRCMF_VIF_STATUS_CONNECTED,
			&ifp->vif->sme_state)) {
			memset(&scb_val, 0, sizeof(scb_val));
			memcpy(&scb_val.ea[0], mac, ETH_ALEN);
			err = brcmf_fil_cmd_data_get(ifp, BRCMF_C_GET_RSSI,
						     &scb_val, sizeof(scb_val));
			if (err) {
				bphy_err(drvr, "Could not get rssi (%d)\n",
					 err);
				goto done;
			} else {
				rssi = le32_to_cpu(scb_val.val);
				sinfo->filled |= BIT_ULL(NL80211_STA_INFO_SIGNAL);
				sinfo->signal = rssi;
				brcmf_dbg(CONN, "RSSI %d dBm\n", rssi);
			}
		}
	}
done:
	brcmf_dbg(TRACE, "Exit\n");
	return err;
}

static int
brcmf_cfg80211_dump_station(struct wiphy *wiphy, struct net_device *ndev,
			    int idx, u8 *mac, struct station_info *sinfo)
{
	struct brcmf_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct brcmf_if *ifp = netdev_priv(ndev);
	struct brcmf_pub *drvr = cfg->pub;
	s32 err;

	brcmf_dbg(TRACE, "Enter, idx %d\n", idx);

	if (idx == 0) {
		cfg->assoclist.count = cpu_to_le32(BRCMF_MAX_ASSOCLIST);
		err = brcmf_fil_cmd_data_get(ifp, BRCMF_C_GET_ASSOCLIST,
					     &cfg->assoclist,
					     sizeof(cfg->assoclist));
		if (err) {
			/* GET_ASSOCLIST unsupported by firmware of older chips */
			if (err == -EBADE)
				bphy_info_once(drvr, "BRCMF_C_GET_ASSOCLIST unsupported\n");
			else
				bphy_err(drvr, "BRCMF_C_GET_ASSOCLIST failed, err=%d\n",
					 err);

			cfg->assoclist.count = 0;
			return -EOPNOTSUPP;
		}
	}
	if (idx < le32_to_cpu(cfg->assoclist.count)) {
		memcpy(mac, cfg->assoclist.mac[idx], ETH_ALEN);
		return brcmf_cfg80211_get_station(wiphy, ndev, mac, sinfo);
	}
	return -ENOENT;
}

static s32
brcmf_cfg80211_set_power_mgmt(struct wiphy *wiphy, struct net_device *ndev,
			   bool enabled, s32 timeout)
{
	s32 pm;
	s32 err = 0;
	struct brcmf_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct brcmf_if *ifp = netdev_priv(ndev);
	struct brcmf_pub *drvr = cfg->pub;

	brcmf_dbg(TRACE, "Enter\n");

	/*
	 * Powersave enable/disable request is coming from the
	 * cfg80211 even before the interface is up. In that
	 * scenario, driver will be storing the power save
	 * preference in cfg struct to apply this to
	 * FW later while initializing the dongle
	 */
	cfg->pwr_save = enabled;
	if (!check_vif_up(ifp->vif)) {

		brcmf_dbg(INFO, "Device is not ready, storing the value in cfg_info struct\n");
		goto done;
	}

	pm = enabled ? ifp->drvr->settings->default_pm : PM_OFF;
	/* Do not enable the power save after assoc if it is a p2p interface */
	if (ifp->vif->wdev.iftype == NL80211_IFTYPE_P2P_CLIENT) {
		brcmf_dbg(INFO, "Do not enable power save for P2P clients\n");
		pm = PM_OFF;
	}

	brcmf_dbg(INFO, "power save %s\n", (pm ? "enabled" : "disabled"));

	err = brcmf_fil_cmd_int_set(ifp, BRCMF_C_SET_PM, pm);
	if (err) {
		if (err == -ENODEV)
			bphy_err(drvr, "net_device is not ready yet\n");
		else
			bphy_err(drvr, "error (%d)\n", err);
	}

done:
	brcmf_dbg(TRACE, "Exit\n");
	return err;
}

static s32 brcmf_inform_single_bss(struct brcmf_cfg80211_info *cfg,
				   struct brcmf_bss_info_le *bi)
{
	struct wiphy *wiphy = cfg_to_wiphy(cfg);
	struct brcmf_pub *drvr = cfg->pub;
	struct cfg80211_bss *bss;
	enum nl80211_band band;
	struct brcmu_chan ch;
	u16 channel;
	u32 freq;
	u16 notify_capability;
	u16 notify_interval;
	u8 *notify_ie;
	size_t notify_ielen;
	struct cfg80211_inform_bss bss_data = {};
	const struct brcmf_tlv *ssid = NULL;

	if (le32_to_cpu(bi->length) > WL_BSS_INFO_MAX) {
		bphy_err(drvr, "Bss info is larger than buffer. Discarding\n");
		return -EINVAL;
	}

	ch.chspec = le16_to_cpu(bi->chanspec);
	cfg->d11inf.decchspec(&ch);
	if (!bi->ctl_ch)
		bi->ctl_ch = ch.control_ch_num;

	channel = bi->ctl_ch;
	band = BRCMU_CHAN_BAND_TO_NL80211(ch.band);
	freq = ieee80211_channel_to_frequency(channel, band);
	if (!freq)
		return -EINVAL;

	bss_data.chan = ieee80211_get_channel(wiphy, freq);
	if (!bss_data.chan)
		return -EINVAL;

	bss_data.scan_width = NL80211_BSS_CHAN_WIDTH_20;
	bss_data.boottime_ns = ktime_to_ns(ktime_get_boottime());

	notify_capability = le16_to_cpu(bi->capability);
	notify_interval = le16_to_cpu(bi->beacon_period);
	notify_ie = (u8 *)bi + le16_to_cpu(bi->ie_offset);
	notify_ielen = le32_to_cpu(bi->ie_length);
	bss_data.signal = (s16)le16_to_cpu(bi->RSSI) * 100;

	ssid = brcmf_parse_tlvs(notify_ie, notify_ielen, WLAN_EID_SSID);
	if (ssid && ssid->data[0] == '\0' && ssid->len == bi->SSID_len) {
		/* Update SSID for hidden AP */
		memcpy((u8 *)ssid->data, bi->SSID, bi->SSID_len);
	}

	brcmf_dbg(CONN, "bssid: %pM\n", bi->BSSID);
	brcmf_dbg(CONN, "Channel: %d(%d)\n", channel, freq);
	brcmf_dbg(CONN, "Capability: %X\n", notify_capability);
	brcmf_dbg(CONN, "Beacon interval: %d\n", notify_interval);
	brcmf_dbg(CONN, "Signal: %d\n", bss_data.signal);

	bss = cfg80211_inform_bss_data(wiphy, &bss_data,
				       CFG80211_BSS_FTYPE_UNKNOWN,
				       (const u8 *)bi->BSSID,
				       0, notify_capability,
				       notify_interval, notify_ie,
				       notify_ielen, GFP_KERNEL);

	if (!bss)
		return -ENOMEM;

	cfg80211_put_bss(wiphy, bss);

	return 0;
}

static struct brcmf_bss_info_le *
next_bss_le(struct brcmf_scan_results *list, struct brcmf_bss_info_le *bss)
{
	if (bss == NULL)
		return list->bss_info_le;
	return (struct brcmf_bss_info_le *)((unsigned long)bss +
					    le32_to_cpu(bss->length));
}

static s32 brcmf_inform_bss(struct brcmf_cfg80211_info *cfg)
{
	struct brcmf_pub *drvr = cfg->pub;
	struct brcmf_scan_results *bss_list;
	struct brcmf_bss_info_le *bi = NULL;	/* must be initialized */
	s32 err = 0;
	int i;

	bss_list = (struct brcmf_scan_results *)cfg->escan_info.escan_buf;
	if (bss_list->count != 0 &&
	    bss_list->version != BRCMF_BSS_INFO_VERSION) {
		bphy_err(drvr, "Version %d != WL_BSS_INFO_VERSION\n",
			 bss_list->version);
		return -EOPNOTSUPP;
	}
	brcmf_dbg(SCAN, "scanned AP count (%d)\n", bss_list->count);
	for (i = 0; i < bss_list->count; i++) {
		bi = next_bss_le(bss_list, bi);
		err = brcmf_inform_single_bss(cfg, bi);
		if (err)
			break;
	}
	return err;
}

static s32 brcmf_inform_ibss(struct brcmf_cfg80211_info *cfg,
			     struct net_device *ndev, const u8 *bssid)
{
	struct wiphy *wiphy = cfg_to_wiphy(cfg);
	struct brcmf_pub *drvr = cfg->pub;
	struct ieee80211_channel *notify_channel;
	struct brcmf_bss_info_le *bi = NULL;
	struct ieee80211_supported_band *band;
	struct cfg80211_bss *bss;
	struct brcmu_chan ch;
	u8 *buf = NULL;
	s32 err = 0;
	u32 freq;
	u16 notify_capability;
	u16 notify_interval;
	u8 *notify_ie;
	size_t notify_ielen;
	s32 notify_signal;

	brcmf_dbg(TRACE, "Enter\n");

	buf = kzalloc(WL_BSS_INFO_MAX, GFP_KERNEL);
	if (buf == NULL) {
		err = -ENOMEM;
		goto cleanup;
	}

	*(__le32 *)buf = cpu_to_le32(WL_BSS_INFO_MAX);

	err = brcmf_fil_cmd_data_get(netdev_priv(ndev), BRCMF_C_GET_BSS_INFO,
				     buf, WL_BSS_INFO_MAX);
	if (err) {
		bphy_err(drvr, "WLC_GET_BSS_INFO failed: %d\n", err);
		goto cleanup;
	}

	bi = (struct brcmf_bss_info_le *)(buf + 4);

	ch.chspec = le16_to_cpu(bi->chanspec);
	cfg->d11inf.decchspec(&ch);

	band = wiphy->bands[BRCMU_CHAN_BAND_TO_NL80211(ch.band)];
	freq = ieee80211_channel_to_frequency(ch.control_ch_num, band->band);
	if (!freq) {
		err = -EINVAL;
		goto cleanup;
	}
	cfg->channel = freq;
	notify_channel = ieee80211_get_channel(wiphy, freq);
	if (!notify_channel) {
		err = -EINVAL;
		goto cleanup;
	}

	notify_capability = le16_to_cpu(bi->capability);
	notify_interval = le16_to_cpu(bi->beacon_period);
	notify_ie = (u8 *)bi + le16_to_cpu(bi->ie_offset);
	notify_ielen = le32_to_cpu(bi->ie_length);
	notify_signal = (s16)le16_to_cpu(bi->RSSI) * 100;

	brcmf_dbg(CONN, "channel: %d(%d)\n", ch.control_ch_num, freq);
	brcmf_dbg(CONN, "capability: %X\n", notify_capability);
	brcmf_dbg(CONN, "beacon interval: %d\n", notify_interval);
	brcmf_dbg(CONN, "signal: %d\n", notify_signal);

	bss = cfg80211_inform_bss(wiphy, notify_channel,
				  CFG80211_BSS_FTYPE_UNKNOWN, bssid, 0,
				  notify_capability, notify_interval,
				  notify_ie, notify_ielen, notify_signal,
				  GFP_KERNEL);

	if (!bss) {
		err = -ENOMEM;
		goto cleanup;
	}

	cfg80211_put_bss(wiphy, bss);

cleanup:

	kfree(buf);

	brcmf_dbg(TRACE, "Exit\n");

	return err;
}

static const struct brcmf_bss_info_le *
brcmf_update_bss_info(struct brcmf_cfg80211_info *cfg, struct brcmf_if *ifp)
{
	struct brcmf_pub *drvr = cfg->pub;
	struct brcmf_bss_info_le *bi = NULL;
	s32 err = 0;
	u8 null_mac[6] = {0};

	brcmf_dbg(TRACE, "Enter\n");
	if (brcmf_is_ibssmode(ifp->vif))
		return NULL;

	*(__le32 *)cfg->extra_buf = cpu_to_le32(WL_EXTRA_BUF_MAX);
	err = brcmf_fil_cmd_data_get(ifp, BRCMF_C_GET_BSS_INFO,
				     cfg->extra_buf, WL_EXTRA_BUF_MAX);
	if (err) {
		bphy_err(drvr, "Could not get bss info %d\n", err);
		goto update_bss_info_out;
	}
	bi = (struct brcmf_bss_info_le *)(cfg->extra_buf + 4);

	if (!memcmp(null_mac, bi->BSSID, ETH_ALEN)) {
		bphy_err(drvr, "NULL mac, don't update bss\n");
		goto update_bss_info_out;
	}

	err = brcmf_inform_single_bss(cfg, bi);

	brcmf_dbg(TRACE, "Exit");
	return bi;

update_bss_info_out:
	brcmf_dbg(TRACE, "Exit");
	return NULL;
}

void brcmf_abort_scanning(struct brcmf_cfg80211_info *cfg)
{
	struct escan_info *escan = &cfg->escan_info;

	set_bit(BRCMF_SCAN_STATUS_ABORT, &cfg->scan_status);
	if (cfg->int_escan_map || cfg->scan_request) {
		escan->escan_state = WL_ESCAN_STATE_IDLE;
		brcmf_notify_escan_complete(cfg, escan->ifp, true, true);
	}
	clear_bit(BRCMF_SCAN_STATUS_BUSY, &cfg->scan_status);
	clear_bit(BRCMF_SCAN_STATUS_ABORT, &cfg->scan_status);
}

static void brcmf_cfg80211_escan_timeout_worker(struct work_struct *work)
{
	struct brcmf_cfg80211_info *cfg =
			container_of(work, struct brcmf_cfg80211_info,
				     escan_timeout_work);

	if (!cfg)
		return;

	brcmf_inform_bss(cfg);
	brcmf_notify_escan_complete(cfg, cfg->escan_info.ifp, true, true);
}

static void brcmf_escan_timeout(struct timer_list *t)
{
	struct brcmf_cfg80211_info *cfg =
			from_timer(cfg, t, escan_timeout);
	struct brcmf_pub *drvr = cfg->pub;

	if (cfg->int_escan_map || cfg->scan_request) {
		bphy_err(drvr, "timer expired\n");
		schedule_work(&cfg->escan_timeout_work);
	}
}

static s32
brcmf_compare_update_same_bss(struct brcmf_cfg80211_info *cfg,
			      struct brcmf_bss_info_le *bss,
			      struct brcmf_bss_info_le *bss_info_le)
{
	struct brcmu_chan ch_bss, ch_bss_info_le;

	ch_bss.chspec = le16_to_cpu(bss->chanspec);
	cfg->d11inf.decchspec(&ch_bss);
	ch_bss_info_le.chspec = le16_to_cpu(bss_info_le->chanspec);
	cfg->d11inf.decchspec(&ch_bss_info_le);

	if (!memcmp(&bss_info_le->BSSID, &bss->BSSID, ETH_ALEN) &&
		ch_bss.band == ch_bss_info_le.band &&
		bss_info_le->SSID_len == bss->SSID_len &&
		!memcmp(bss_info_le->SSID, bss->SSID, bss_info_le->SSID_len)) {
		if ((bss->flags & BRCMF_BSS_RSSI_ON_CHANNEL) ==
			(bss_info_le->flags & BRCMF_BSS_RSSI_ON_CHANNEL)) {
			s16 bss_rssi = le16_to_cpu(bss->RSSI);
			s16 bss_info_rssi = le16_to_cpu(bss_info_le->RSSI);

			/* preserve max RSSI if the measurements are
			* both on-channel or both off-channel
			*/
			if (bss_info_rssi > bss_rssi)
				bss->RSSI = bss_info_le->RSSI;
		} else if ((bss->flags & BRCMF_BSS_RSSI_ON_CHANNEL) &&
			(bss_info_le->flags & BRCMF_BSS_RSSI_ON_CHANNEL) == 0) {
			/* preserve the on-channel rssi measurement
			* if the new measurement is off channel
			*/
			bss->RSSI = bss_info_le->RSSI;
			bss->flags |= BRCMF_BSS_RSSI_ON_CHANNEL;
		}
		return 1;
	}
	return 0;
}

static s32
brcmf_cfg80211_escan_handler(struct brcmf_if *ifp,
			     const struct brcmf_event_msg *e, void *data)
{
	struct brcmf_pub *drvr = ifp->drvr;
	struct brcmf_cfg80211_info *cfg = drvr->config;
	s32 status;
	struct brcmf_escan_result_le *escan_result_le;
	u32 escan_buflen;
	struct brcmf_bss_info_le *bss_info_le;
	struct brcmf_bss_info_le *bss = NULL;
	u32 bi_length;
	struct brcmf_scan_results *list;
	u32 i;
	bool aborted;

	status = e->status;

	if (status == BRCMF_E_STATUS_ABORT)
		goto exit;

	if (!test_bit(BRCMF_SCAN_STATUS_BUSY, &cfg->scan_status)) {
		bphy_err(drvr, "scan not ready, bsscfgidx=%d\n",
			 ifp->bsscfgidx);
		return -EPERM;
	}

	if (status == BRCMF_E_STATUS_PARTIAL) {
		brcmf_dbg(SCAN, "ESCAN Partial result\n");
		if (e->datalen < sizeof(*escan_result_le)) {
			bphy_err(drvr, "invalid event data length\n");
			goto exit;
		}
		escan_result_le = (struct brcmf_escan_result_le *) data;
		if (!escan_result_le) {
			bphy_err(drvr, "Invalid escan result (NULL pointer)\n");
			goto exit;
		}
		escan_buflen = le32_to_cpu(escan_result_le->buflen);
		if (escan_buflen > BRCMF_ESCAN_BUF_SIZE ||
		    escan_buflen > e->datalen ||
		    escan_buflen < sizeof(*escan_result_le)) {
			bphy_err(drvr, "Invalid escan buffer length: %d\n",
				 escan_buflen);
			goto exit;
		}
		if (le16_to_cpu(escan_result_le->bss_count) != 1) {
			bphy_err(drvr, "Invalid bss_count %d: ignoring\n",
				 escan_result_le->bss_count);
			goto exit;
		}
		bss_info_le = &escan_result_le->bss_info_le;

		if (brcmf_p2p_scan_finding_common_channel(cfg, bss_info_le))
			goto exit;

		if (!cfg->int_escan_map && !cfg->scan_request) {
			brcmf_dbg(SCAN, "result without cfg80211 request\n");
			goto exit;
		}

		bi_length = le32_to_cpu(bss_info_le->length);
		if (bi_length != escan_buflen -	WL_ESCAN_RESULTS_FIXED_SIZE) {
			bphy_err(drvr, "Ignoring invalid bss_info length: %d\n",
				 bi_length);
			goto exit;
		}

		if (!(cfg_to_wiphy(cfg)->interface_modes &
					BIT(NL80211_IFTYPE_ADHOC))) {
			if (le16_to_cpu(bss_info_le->capability) &
						WLAN_CAPABILITY_IBSS) {
				bphy_err(drvr, "Ignoring IBSS result\n");
				goto exit;
			}
		}

		list = (struct brcmf_scan_results *)
				cfg->escan_info.escan_buf;
		if (bi_length > BRCMF_ESCAN_BUF_SIZE - list->buflen) {
			bphy_err(drvr, "Buffer is too small: ignoring\n");
			goto exit;
		}

		for (i = 0; i < list->count; i++) {
			bss = bss ? (struct brcmf_bss_info_le *)
				((unsigned char *)bss +
				le32_to_cpu(bss->length)) : list->bss_info_le;
			if (brcmf_compare_update_same_bss(cfg, bss,
							  bss_info_le))
				goto exit;
		}
		memcpy(&cfg->escan_info.escan_buf[list->buflen], bss_info_le,
		       bi_length);
		list->version = le32_to_cpu(bss_info_le->version);
		list->buflen += bi_length;
		list->count++;
	} else {
		cfg->escan_info.escan_state = WL_ESCAN_STATE_IDLE;
		if (brcmf_p2p_scan_finding_common_channel(cfg, NULL))
			goto exit;
		if (cfg->int_escan_map || cfg->scan_request) {
			brcmf_inform_bss(cfg);
			aborted = status != BRCMF_E_STATUS_SUCCESS;
			brcmf_notify_escan_complete(cfg, ifp, aborted, false);
		} else
			brcmf_dbg(SCAN, "Ignored scan complete result 0x%x\n",
				  status);
	}
exit:
	return 0;
}

static void brcmf_init_escan(struct brcmf_cfg80211_info *cfg)
{
	brcmf_fweh_register(cfg->pub, BRCMF_E_ESCAN_RESULT,
			    brcmf_cfg80211_escan_handler);
	cfg->escan_info.escan_state = WL_ESCAN_STATE_IDLE;
	/* Init scan_timeout timer */
	timer_setup(&cfg->escan_timeout, brcmf_escan_timeout, 0);
	INIT_WORK(&cfg->escan_timeout_work,
		  brcmf_cfg80211_escan_timeout_worker);
}

static struct cfg80211_scan_request *
brcmf_alloc_internal_escan_request(struct wiphy *wiphy, u32 n_netinfo) {
	struct cfg80211_scan_request *req;
	size_t req_size;
	size_t size_sanity = ~0;

	if (n_netinfo > ((size_sanity - sizeof(*req)) /
			(sizeof(req->channels[0]) + sizeof(*req->ssids)))) {
		brcmf_err("requesting a huge count:%d\n", n_netinfo);
		return NULL;
	}

	req_size = sizeof(*req) +
		   n_netinfo * sizeof(req->channels[0]) +
		   n_netinfo * sizeof(*req->ssids);

	req = kzalloc(req_size, GFP_KERNEL);
	if (req) {
		req->wiphy = wiphy;
		req->ssids = (void *)(&req->channels[0]) +
			     n_netinfo * sizeof(req->channels[0]);
	}
	return req;
}

static int brcmf_internal_escan_add_info(struct cfg80211_scan_request *req,
					 u8 *ssid, u8 ssid_len, u8 channel)
{
	struct ieee80211_channel *chan;
	enum nl80211_band band;
	int freq, i;

	if (channel <= CH_MAX_2G_CHANNEL)
		band = NL80211_BAND_2GHZ;
	else
		band = NL80211_BAND_5GHZ;

	freq = ieee80211_channel_to_frequency(channel, band);
	if (!freq)
		return -EINVAL;

	chan = ieee80211_get_channel(req->wiphy, freq);
	if (!chan)
		return -EINVAL;

	for (i = 0; i < req->n_channels; i++) {
		if (req->channels[i] == chan)
			break;
	}
	if (i == req->n_channels)
		req->channels[req->n_channels++] = chan;

	for (i = 0; i < req->n_ssids; i++) {
		if (req->ssids[i].ssid_len == ssid_len &&
		    !memcmp(req->ssids[i].ssid, ssid, ssid_len))
			break;
	}
	if (i == req->n_ssids) {
		memcpy(req->ssids[req->n_ssids].ssid, ssid, ssid_len);
		req->ssids[req->n_ssids++].ssid_len = ssid_len;
	}
	return 0;
}

static int brcmf_start_internal_escan(struct brcmf_if *ifp, u32 fwmap,
				      struct cfg80211_scan_request *request)
{
	struct brcmf_cfg80211_info *cfg = ifp->drvr->config;
	int err;

	if (test_bit(BRCMF_SCAN_STATUS_BUSY, &cfg->scan_status)) {
		if (cfg->int_escan_map)
			brcmf_dbg(SCAN, "aborting internal scan: map=%u\n",
				  cfg->int_escan_map);
		/* Abort any on-going scan */
		brcmf_abort_scanning(cfg);
	}

	brcmf_dbg(SCAN, "start internal scan: map=%u\n", fwmap);
	set_bit(BRCMF_SCAN_STATUS_BUSY, &cfg->scan_status);
	cfg->escan_info.run = brcmf_run_escan;
	err = brcmf_do_escan(ifp, request);
	if (err) {
		clear_bit(BRCMF_SCAN_STATUS_BUSY, &cfg->scan_status);
		return err;
	}
	cfg->int_escan_map = fwmap;
	return 0;
}

static struct brcmf_pno_net_info_le *
brcmf_get_netinfo_array(struct brcmf_pno_scanresults_le *pfn_v1)
{
	struct brcmf_pno_scanresults_v2_le *pfn_v2;
	struct brcmf_pno_net_info_le *netinfo;

	switch (pfn_v1->version) {
	default:
		WARN_ON(1);
		fallthrough;
	case cpu_to_le32(1):
		netinfo = (struct brcmf_pno_net_info_le *)(pfn_v1 + 1);
		break;
	case cpu_to_le32(2):
		pfn_v2 = (struct brcmf_pno_scanresults_v2_le *)pfn_v1;
		netinfo = (struct brcmf_pno_net_info_le *)(pfn_v2 + 1);
		break;
	}

	return netinfo;
}

/* PFN result doesn't have all the info which are required by the supplicant
 * (For e.g IEs) Do a target Escan so that sched scan results are reported
 * via wl_inform_single_bss in the required format. Escan does require the
 * scan request in the form of cfg80211_scan_request. For timebeing, create
 * cfg80211_scan_request one out of the received PNO event.
 */
static s32
brcmf_notify_sched_scan_results(struct brcmf_if *ifp,
				const struct brcmf_event_msg *e, void *data)
{
	struct brcmf_pub *drvr = ifp->drvr;
	struct brcmf_cfg80211_info *cfg = drvr->config;
	struct brcmf_pno_net_info_le *netinfo, *netinfo_start;
	struct cfg80211_scan_request *request = NULL;
	struct wiphy *wiphy = cfg_to_wiphy(cfg);
	int i, err = 0;
	struct brcmf_pno_scanresults_le *pfn_result;
	u32 bucket_map;
	u32 result_count;
	u32 status;
	u32 datalen;

	brcmf_dbg(SCAN, "Enter\n");

	if (e->datalen < (sizeof(*pfn_result) + sizeof(*netinfo))) {
		brcmf_dbg(SCAN, "Event data to small. Ignore\n");
		return 0;
	}

	if (e->event_code == BRCMF_E_PFN_NET_LOST) {
		brcmf_dbg(SCAN, "PFN NET LOST event. Do Nothing\n");
		return 0;
	}

	pfn_result = (struct brcmf_pno_scanresults_le *)data;
	result_count = le32_to_cpu(pfn_result->count);
	status = le32_to_cpu(pfn_result->status);

	/* PFN event is limited to fit 512 bytes so we may get
	 * multiple NET_FOUND events. For now place a warning here.
	 */
	WARN_ON(status != BRCMF_PNO_SCAN_COMPLETE);
	brcmf_dbg(SCAN, "PFN NET FOUND event. count: %d\n", result_count);
	if (!result_count) {
		bphy_err(drvr, "FALSE PNO Event. (pfn_count == 0)\n");
		goto out_err;
	}

	netinfo_start = brcmf_get_netinfo_array(pfn_result);
	/* To make sure e->datalen is big enough */
	if (e->datalen >= ((void *)netinfo_start - (void *)pfn_result)) {
		u32 cnt_sanity = ~0;

		datalen = e->datalen - ((void *)netinfo_start - (void *)pfn_result);
		if (datalen < result_count * sizeof(*netinfo) ||
		    (result_count > cnt_sanity / sizeof(*netinfo))) {
			brcmf_err("insufficient event data\n");
			goto out_err;
		}
	} else {
		brcmf_err("insufficient event data\n");
		goto out_err;
	}

	request = brcmf_alloc_internal_escan_request(wiphy,
						     result_count);
	if (!request) {
		err = -ENOMEM;
		goto out_err;
	}

	bucket_map = 0;
	for (i = 0; i < result_count; i++) {
		netinfo = &netinfo_start[i];

		if (netinfo->SSID_len > IEEE80211_MAX_SSID_LEN)
			netinfo->SSID_len = IEEE80211_MAX_SSID_LEN;
		brcmf_dbg(SCAN, "SSID:%.32s Channel:%d\n",
			  netinfo->SSID, netinfo->channel);
		bucket_map |= brcmf_pno_get_bucket_map(cfg->pno, netinfo);
		err = brcmf_internal_escan_add_info(request,
						    netinfo->SSID,
						    netinfo->SSID_len,
						    netinfo->channel);
		if (err)
			goto out_err;
	}

	if (!bucket_map)
		goto free_req;

	err = brcmf_start_internal_escan(ifp, bucket_map, request);
	if (!err)
		goto free_req;

out_err:
	cfg80211_sched_scan_stopped(wiphy, 0);
free_req:
	kfree(request);
	return err;
}

static int
brcmf_cfg80211_sched_scan_start(struct wiphy *wiphy,
				struct net_device *ndev,
				struct cfg80211_sched_scan_request *req)
{
	struct brcmf_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct brcmf_if *ifp = netdev_priv(ndev);
	struct brcmf_pub *drvr = cfg->pub;

	brcmf_dbg(SCAN, "Enter: n_match_sets=%d n_ssids=%d\n",
		  req->n_match_sets, req->n_ssids);

	if (test_bit(BRCMF_SCAN_STATUS_SUPPRESS, &cfg->scan_status)) {
		bphy_err(drvr, "Scanning suppressed: status=%lu\n",
			 cfg->scan_status);
		return -EAGAIN;
	}

	if (req->n_match_sets <= 0) {
		brcmf_dbg(SCAN, "invalid number of matchsets specified: %d\n",
			  req->n_match_sets);
		return -EINVAL;
	}

	return brcmf_pno_start_sched_scan(ifp, req);
}

static int brcmf_cfg80211_sched_scan_stop(struct wiphy *wiphy,
					  struct net_device *ndev, u64 reqid)
{
	struct brcmf_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct brcmf_if *ifp = netdev_priv(ndev);

	brcmf_dbg(SCAN, "enter\n");
	brcmf_pno_stop_sched_scan(ifp, reqid);
	if (cfg->int_escan_map)
		brcmf_notify_escan_complete(cfg, ifp, true, true);
	return 0;
}

static __always_inline void brcmf_delay(u32 ms)
{
	if (ms < 1000 / HZ) {
		cond_resched();
		mdelay(ms);
	} else {
		msleep(ms);
	}
}

static s32 brcmf_config_wowl_pattern(struct brcmf_if *ifp, u8 cmd[4],
				     u8 *pattern, u32 patternsize, u8 *mask,
				     u32 packet_offset)
{
	struct brcmf_fil_wowl_pattern_le *filter;
	u32 masksize;
	u32 patternoffset;
	u8 *buf;
	u32 bufsize;
	s32 ret;

	masksize = (patternsize + 7) / 8;
	patternoffset = sizeof(*filter) - sizeof(filter->cmd) + masksize;

	bufsize = sizeof(*filter) + patternsize + masksize;
	buf = kzalloc(bufsize, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	filter = (struct brcmf_fil_wowl_pattern_le *)buf;

	memcpy(filter->cmd, cmd, 4);
	filter->masksize = cpu_to_le32(masksize);
	filter->offset = cpu_to_le32(packet_offset);
	filter->patternoffset = cpu_to_le32(patternoffset);
	filter->patternsize = cpu_to_le32(patternsize);
	filter->type = cpu_to_le32(BRCMF_WOWL_PATTERN_TYPE_BITMAP);

	if ((mask) && (masksize))
		memcpy(buf + sizeof(*filter), mask, masksize);
	if ((pattern) && (patternsize))
		memcpy(buf + sizeof(*filter) + masksize, pattern, patternsize);

	ret = brcmf_fil_iovar_data_set(ifp, "wowl_pattern", buf, bufsize);

	kfree(buf);
	return ret;
}

static s32
brcmf_wowl_nd_results(struct brcmf_if *ifp, const struct brcmf_event_msg *e,
		      void *data)
{
	struct brcmf_pub *drvr = ifp->drvr;
	struct brcmf_cfg80211_info *cfg = drvr->config;
	struct brcmf_pno_scanresults_le *pfn_result;
	struct brcmf_pno_net_info_le *netinfo;

	brcmf_dbg(SCAN, "Enter\n");

	if (e->datalen < (sizeof(*pfn_result) + sizeof(*netinfo))) {
		brcmf_dbg(SCAN, "Event data to small. Ignore\n");
		return 0;
	}

	pfn_result = (struct brcmf_pno_scanresults_le *)data;

	if (e->event_code == BRCMF_E_PFN_NET_LOST) {
		brcmf_dbg(SCAN, "PFN NET LOST event. Ignore\n");
		return 0;
	}

	if (le32_to_cpu(pfn_result->count) < 1) {
		bphy_err(drvr, "Invalid result count, expected 1 (%d)\n",
			 le32_to_cpu(pfn_result->count));
		return -EINVAL;
	}

	netinfo = brcmf_get_netinfo_array(pfn_result);
	if (netinfo->SSID_len > IEEE80211_MAX_SSID_LEN)
		netinfo->SSID_len = IEEE80211_MAX_SSID_LEN;
	memcpy(cfg->wowl.nd->ssid.ssid, netinfo->SSID, netinfo->SSID_len);
	cfg->wowl.nd->ssid.ssid_len = netinfo->SSID_len;
	cfg->wowl.nd->n_channels = 1;
	cfg->wowl.nd->channels[0] =
		ieee80211_channel_to_frequency(netinfo->channel,
			netinfo->channel <= CH_MAX_2G_CHANNEL ?
					NL80211_BAND_2GHZ : NL80211_BAND_5GHZ);
	cfg->wowl.nd_info->n_matches = 1;
	cfg->wowl.nd_info->matches[0] = cfg->wowl.nd;

	/* Inform (the resume task) that the net detect information was recvd */
	cfg->wowl.nd_data_completed = true;
	wake_up(&cfg->wowl.nd_data_wait);

	return 0;
}

#ifdef CONFIG_PM

static void brcmf_report_wowl_wakeind(struct wiphy *wiphy, struct brcmf_if *ifp)
{
	struct brcmf_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct brcmf_pub *drvr = cfg->pub;
	struct brcmf_wowl_wakeind_le wake_ind_le;
	struct cfg80211_wowlan_wakeup wakeup_data;
	struct cfg80211_wowlan_wakeup *wakeup;
	u32 wakeind;
	s32 err;
	int timeout;

	err = brcmf_fil_iovar_data_get(ifp, "wowl_wakeind", &wake_ind_le,
				       sizeof(wake_ind_le));
	if (err) {
		bphy_err(drvr, "Get wowl_wakeind failed, err = %d\n", err);
		return;
	}

	wakeind = le32_to_cpu(wake_ind_le.ucode_wakeind);
	if (wakeind & (BRCMF_WOWL_MAGIC | BRCMF_WOWL_DIS | BRCMF_WOWL_BCN |
		       BRCMF_WOWL_RETR | BRCMF_WOWL_NET |
		       BRCMF_WOWL_PFN_FOUND)) {
		wakeup = &wakeup_data;
		memset(&wakeup_data, 0, sizeof(wakeup_data));
		wakeup_data.pattern_idx = -1;

		if (wakeind & BRCMF_WOWL_MAGIC) {
			brcmf_dbg(INFO, "WOWL Wake indicator: BRCMF_WOWL_MAGIC\n");
			wakeup_data.magic_pkt = true;
		}
		if (wakeind & BRCMF_WOWL_DIS) {
			brcmf_dbg(INFO, "WOWL Wake indicator: BRCMF_WOWL_DIS\n");
			wakeup_data.disconnect = true;
		}
		if (wakeind & BRCMF_WOWL_BCN) {
			brcmf_dbg(INFO, "WOWL Wake indicator: BRCMF_WOWL_BCN\n");
			wakeup_data.disconnect = true;
		}
		if (wakeind & BRCMF_WOWL_RETR) {
			brcmf_dbg(INFO, "WOWL Wake indicator: BRCMF_WOWL_RETR\n");
			wakeup_data.disconnect = true;
		}
		if (wakeind & BRCMF_WOWL_NET) {
			brcmf_dbg(INFO, "WOWL Wake indicator: BRCMF_WOWL_NET\n");
			/* For now always map to pattern 0, no API to get
			 * correct information available at the moment.
			 */
			wakeup_data.pattern_idx = 0;
		}
		if (wakeind & BRCMF_WOWL_PFN_FOUND) {
			brcmf_dbg(INFO, "WOWL Wake indicator: BRCMF_WOWL_PFN_FOUND\n");
			timeout = wait_event_timeout(cfg->wowl.nd_data_wait,
				cfg->wowl.nd_data_completed,
				BRCMF_ND_INFO_TIMEOUT);
			if (!timeout)
				bphy_err(drvr, "No result for wowl net detect\n");
			else
				wakeup_data.net_detect = cfg->wowl.nd_info;
		}
		if (wakeind & BRCMF_WOWL_GTK_FAILURE) {
			brcmf_dbg(INFO, "WOWL Wake indicator: BRCMF_WOWL_GTK_FAILURE\n");
			wakeup_data.gtk_rekey_failure = true;
		}
	} else {
		wakeup = NULL;
	}
	cfg80211_report_wowlan_wakeup(&ifp->vif->wdev, wakeup, GFP_KERNEL);
}

#else

static void brcmf_report_wowl_wakeind(struct wiphy *wiphy, struct brcmf_if *ifp)
{
}

#endif /* CONFIG_PM */

static s32 brcmf_cfg80211_resume(struct wiphy *wiphy)
{
	struct brcmf_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct net_device *ndev = cfg_to_ndev(cfg);
	struct brcmf_if *ifp = netdev_priv(ndev);
	struct brcmf_pub *drvr = ifp->drvr;
	struct brcmf_bus *bus_if = drvr->bus_if;
	struct brcmf_cfg80211_info *config = drvr->config;
	int retry = BRCMF_PM_WAIT_MAXRETRY;
	s32 power_mode;

	power_mode = cfg->pwr_save ? ifp->drvr->settings->default_pm : PM_OFF;

	brcmf_dbg(TRACE, "Enter\n");

	config->pm_state = BRCMF_CFG80211_PM_STATE_RESUMING;

	if (cfg->wowl.active) {
		/* wait for bus resumed */
		while (retry && bus_if->state != BRCMF_BUS_UP) {
			usleep_range(10000, 20000);
			retry--;
		}
		if (!retry && bus_if->state != BRCMF_BUS_UP)
			brcmf_err("timed out wait for bus resume\n");

		brcmf_report_wowl_wakeind(wiphy, ifp);
		brcmf_fil_iovar_int_set(ifp, "wowl_clear", 0);
		brcmf_config_wowl_pattern(ifp, "clr", NULL, 0, NULL, 0);
		if (!brcmf_feat_is_enabled(ifp, BRCMF_FEAT_WOWL_ARP_ND))
			brcmf_configure_arp_nd_offload(ifp, true);
		brcmf_fil_cmd_int_set(ifp, BRCMF_C_SET_PM,
				      power_mode);
		cfg->wowl.active = false;
		if (cfg->wowl.nd_enabled) {
			brcmf_cfg80211_sched_scan_stop(cfg->wiphy, ifp->ndev, 0);
			brcmf_fweh_unregister(cfg->pub, BRCMF_E_PFN_NET_FOUND);
			brcmf_fweh_register(cfg->pub, BRCMF_E_PFN_NET_FOUND,
					    brcmf_notify_sched_scan_results);
			cfg->wowl.nd_enabled = false;
		}

		/* disable packet filters */
		brcmf_pktfilter_enable(ifp->ndev, false);

	}
	/* During resume, disable all offload modules which are enabled
	 * previously while entering suspend.
	 */
	if (brcmf_feat_is_enabled(ifp, BRCMF_FEAT_OFFLOADS))
		brcmf_generic_offload_enable(ifp, brcmf_offload_feat, false);

	config->pm_state = BRCMF_CFG80211_PM_STATE_RESUMED;
	return 0;
}

static void brcmf_configure_wowl(struct brcmf_cfg80211_info *cfg,
				 struct brcmf_if *ifp,
				 struct cfg80211_wowlan *wowl)
{
	u32 wowl_config;
	struct brcmf_wowl_wakeind_le wowl_wakeind;
	u32 i;

	brcmf_dbg(TRACE, "Suspend, wowl config.\n");

	if (!brcmf_feat_is_enabled(ifp, BRCMF_FEAT_WOWL_ARP_ND))
		brcmf_configure_arp_nd_offload(ifp, false);
	brcmf_fil_cmd_int_set(ifp, BRCMF_C_SET_PM, PM_MAX);

	wowl_config = 0;
	if (wowl->disconnect)
		wowl_config = BRCMF_WOWL_DIS | BRCMF_WOWL_BCN | BRCMF_WOWL_RETR;
	if (wowl->magic_pkt)
		wowl_config |= BRCMF_WOWL_MAGIC;
	if ((wowl->patterns) && (wowl->n_patterns)) {
		wowl_config |= BRCMF_WOWL_NET;
		for (i = 0; i < wowl->n_patterns; i++) {
			brcmf_config_wowl_pattern(ifp, "add",
				(u8 *)wowl->patterns[i].pattern,
				wowl->patterns[i].pattern_len,
				(u8 *)wowl->patterns[i].mask,
				wowl->patterns[i].pkt_offset);
		}
	}
	if (wowl->nd_config) {
		brcmf_cfg80211_sched_scan_start(cfg->wiphy, ifp->ndev,
						wowl->nd_config);
		wowl_config |= BRCMF_WOWL_PFN_FOUND;

		cfg->wowl.nd_data_completed = false;
		cfg->wowl.nd_enabled = true;
		/* Now reroute the event for PFN to the wowl function. */
		brcmf_fweh_unregister(cfg->pub, BRCMF_E_PFN_NET_FOUND);
		brcmf_fweh_register(cfg->pub, BRCMF_E_PFN_NET_FOUND,
				    brcmf_wowl_nd_results);
	}
	if (wowl->gtk_rekey_failure)
		wowl_config |= BRCMF_WOWL_GTK_FAILURE;
	if (!test_bit(BRCMF_VIF_STATUS_CONNECTED, &ifp->vif->sme_state))
		wowl_config |= BRCMF_WOWL_UNASSOC;

	memcpy(&wowl_wakeind, "clear", 6);
	brcmf_fil_iovar_data_set(ifp, "wowl_wakeind", &wowl_wakeind,
				 sizeof(wowl_wakeind));
	brcmf_fil_iovar_int_set(ifp, "wowl", wowl_config);
	brcmf_fil_iovar_int_set(ifp, "wowl_activate", 1);
	brcmf_bus_wowl_config(cfg->pub->bus_if, true);
	cfg->wowl.active = true;

	/* enable packet filters */
	brcmf_pktfilter_enable(ifp->ndev, true);
}

static int brcmf_keepalive_start(struct brcmf_if *ifp, unsigned int interval)
{
	struct brcmf_mkeep_alive_pkt_le kalive = {0};
	int ret = 0;

	/* Configure Null function/data keepalive */
	kalive.version = cpu_to_le16(1);
	kalive.period_msec = cpu_to_le32(interval * MSEC_PER_SEC);
	kalive.len_bytes = cpu_to_le16(0);
	kalive.keep_alive_id = 0;

	ret = brcmf_fil_iovar_data_set(ifp, "mkeep_alive", &kalive, sizeof(kalive));
	if (ret)
		brcmf_err("keep-alive packet config failed, ret=%d\n", ret);

	return ret;
}

static s32 brcmf_cfg80211_suspend(struct wiphy *wiphy,
				  struct cfg80211_wowlan *wowl)
{
	struct brcmf_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct net_device *ndev = cfg_to_ndev(cfg);
	struct brcmf_if *ifp = netdev_priv(ndev);
	struct brcmf_cfg80211_vif *vif;
	struct brcmf_cfg80211_info *config = ifp->drvr->config;

	brcmf_dbg(TRACE, "Enter\n");

	config->pm_state = BRCMF_CFG80211_PM_STATE_SUSPENDING;

	/* if the primary net_device is not READY there is nothing
	 * we can do but pray resume goes smoothly.
	 */
	if (!check_vif_up(ifp->vif))
		goto exit;

	/* Stop scheduled scan */
	if (brcmf_feat_is_enabled(ifp, BRCMF_FEAT_PNO))
		brcmf_cfg80211_sched_scan_stop(wiphy, ndev, 0);

	/* end any scanning */
	if (test_bit(BRCMF_SCAN_STATUS_BUSY, &cfg->scan_status))
		brcmf_abort_scanning(cfg);

	/* Enable offload features that were not in default (LOW) or user selected
	 * power profile but should be offloaded to fw in suspend as host goes to
	 * sleep. These will be disabled on resume.
	 */
	if (brcmf_feat_is_enabled(ifp, BRCMF_FEAT_OFFLOADS))
		brcmf_generic_offload_enable(ifp, brcmf_offload_feat, true);

	if (!wowl || !test_bit(BRCMF_VIF_STATUS_CONNECTED,
			       &ifp->vif->sme_state)) {
		brcmf_bus_wowl_config(cfg->pub->bus_if, false);
		list_for_each_entry(vif, &cfg->vif_list, list) {
			if (!test_bit(BRCMF_VIF_STATUS_READY, &vif->sme_state))
				continue;
			/* While going to suspend if associated with AP
			 * disassociate from AP to save power while system is
			 * in suspended state
			 */
			brcmf_link_down(vif, WLAN_REASON_UNSPECIFIED, true);
			/* Make sure WPA_Supplicant receives all the event
			 * generated due to DISASSOC call to the fw to keep
			 * the state fw and WPA_Supplicant state consistent
			 */
			brcmf_delay(500);
		}
		/* Configure MPC */
		brcmf_set_mpc(ifp, 1);

	} else {
		if (brcmf_feat_is_enabled(ifp, BRCMF_FEAT_WOWL)) {
			/* Configure WOWL parameters */
			brcmf_configure_wowl(cfg, ifp, wowl);

			/* Prevent disassociation due to inactivity with keep-alive */
			brcmf_keepalive_start(ifp, 30);
		}
		if (brcmf_feat_is_enabled(ifp, BRCMF_FEAT_OFFLOADS))
			brcmf_generic_offload_enable(ifp, BRCMF_OL_WOWLPF, true);
	}

exit:
	/* set cfg80211 pm state to cfg80211 suspended state */
	config->pm_state = BRCMF_CFG80211_PM_STATE_SUSPENDED;

	/* clear any scanning activity */
	cfg->scan_status = 0;

	brcmf_dbg(TRACE, "Exit\n");
	return 0;
}

static __used s32
brcmf_update_pmklist(struct brcmf_cfg80211_info *cfg, struct brcmf_if *ifp)
{
	struct brcmf_pmk_list_le *pmk_list;
	int i;
	u32 npmk;

	pmk_list = &cfg->pmk_list;
	npmk = le32_to_cpu(pmk_list->npmk);

	brcmf_dbg(CONN, "No of elements %d\n", npmk);
	for (i = 0; i < npmk; i++)
		brcmf_dbg(CONN, "PMK[%d]: %pM\n", i, &pmk_list->pmk[i].bssid);

	return brcmf_fil_iovar_data_set(ifp, "pmkid_info", pmk_list,
			sizeof(*pmk_list));
}

static s32 
brcmf_update_pmksa(struct brcmf_cfg80211_info *cfg,
		   struct brcmf_if *ifp,
		   const u8 *bssid,
		   const u8 *pmkid,
		   enum brcmf_pmksa_action action)
{
	struct brcmf_pmksa *pmk = &cfg->pmk_list.pmk[0];
	struct brcmf_pub *drvr = cfg->pub;
	s32 err;
	u32 npmk, i;

	if (!check_vif_up(ifp->vif))
		return -EIO;

	switch (action) {
	case PMKSA_SET:
		npmk = le32_to_cpu(cfg->pmk_list.npmk);
		for (i = 0; i < npmk; i++)
			if (!memcmp(bssid, pmk[i].bssid, ETH_ALEN))
				break;
		if (i < BRCMF_MAXPMKID) {
			memcpy(pmk[i].bssid, bssid, ETH_ALEN);
			memcpy(pmk[i].pmkid, pmkid, WLAN_PMKID_LEN);
			if (i == npmk) {
				npmk++;
				cfg->pmk_list.npmk = cpu_to_le32(npmk);
			}
		} else {
			bphy_err(drvr, "Too many PMKSA entries cached %d\n", npmk);
			return -EINVAL;
		}

		brcmf_dbg(CONN, "set_pmksa - PMK bssid: %pM =\n", pmk[i].bssid);
		brcmf_dbg(CONN, "%*ph\n", WLAN_PMKID_LEN, pmk[i].pmkid);

		err = brcmf_update_pmklist(cfg, ifp);
		break;
	case PMKSA_DELETE:
		npmk = le32_to_cpu(cfg->pmk_list.npmk);
		for (i = 0; i < npmk; i++)
			if (!memcmp(bssid, pmk[i].bssid, ETH_ALEN))
				break;

		if (npmk > 0 && i < npmk) {
			for (; i < (npmk - 1); i++) {
				memcpy(&pmk[i].bssid, &pmk[i + 1].bssid, ETH_ALEN);
				memcpy(&pmk[i].pmkid, &pmk[i + 1].pmkid,
				       WLAN_PMKID_LEN);
			}
			memset(&pmk[i], 0, sizeof(*pmk));
			cfg->pmk_list.npmk = cpu_to_le32(npmk - 1);
		} else {
			bphy_err(drvr, "Cache entry not found\n");
			return -EINVAL;
		}

		err = brcmf_update_pmklist(cfg, ifp);
		break;
	default:
		err = -EINVAL;
	}

	return err;
}

static s32
brcmf_cfg80211_set_pmksa(struct wiphy *wiphy, struct net_device *ndev,
			 struct cfg80211_pmksa *pmksa)
{
	struct brcmf_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct brcmf_if *ifp = netdev_priv(ndev);
	struct brcmf_pub *drvr = cfg->pub;
	s32 err;

	brcmf_dbg(TRACE, "Enter\n");
	if (!check_vif_up(ifp->vif))
		return -EIO;

	err = brcmf_update_pmksa(cfg, ifp, pmksa->bssid, pmksa->pmkid, PMKSA_SET);
	if (err < 0) {
		bphy_err(drvr,
			 "PMKSA_SET brcmf_update_pmksa failed: ret=%d\n",
			 err);
		goto exit;
	}

	if (pmksa->pmk_len && pmksa->pmk_len < BRCMF_WSEC_PMK_LEN_SUITEB_192) {
		/* external supplicant stores SUITEB-192 PMK */
		if (ifp->vif->profile.is_okc) {
			err = brcmf_fil_iovar_data_set(ifp, "okc_info_pmk", pmksa->pmk,
						       pmksa->pmk_len);
			if (err < 0)
				bphy_err(drvr, "okc_info_pmk iovar failed: ret=%d\n", err);
		} else {
			brcmf_set_pmk(ifp, pmksa->pmk, pmksa->pmk_len);
		}
	}

exit:
	brcmf_dbg(TRACE, "Exit\n");
	return err;
}

static s32
brcmf_cfg80211_del_pmksa(struct wiphy *wiphy, struct net_device *ndev,
			 struct cfg80211_pmksa *pmksa)
{
	struct brcmf_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct brcmf_if *ifp = netdev_priv(ndev);
	struct brcmf_pub *drvr = cfg->pub;
	s32 err;

	brcmf_dbg(TRACE, "Enter\n");
	if (!check_vif_up(ifp->vif))
		return -EIO;

	brcmf_dbg(CONN, "del_pmksa - PMK bssid = %pM\n", pmksa->bssid);
	err = brcmf_update_pmksa(cfg, ifp, pmksa->bssid, pmksa->pmkid, PMKSA_DELETE);
	if (err < 0) {
		bphy_err(drvr,
			 "PMKSA_DELETE brcmf_update_pmksa failed: ret=%d\n",
			 err);
		return err;
	}

	brcmf_dbg(TRACE, "Exit\n");
	return err;
}

static s32
brcmf_cfg80211_flush_pmksa(struct wiphy *wiphy, struct net_device *ndev)
{
	struct brcmf_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct brcmf_if *ifp = netdev_priv(ndev);
	s32 err;

	brcmf_dbg(TRACE, "Enter\n");
	if (!check_vif_up(ifp->vif))
		return -EIO;

	memset(&cfg->pmk_list, 0, sizeof(cfg->pmk_list));
	err = brcmf_update_pmklist(cfg, ifp);

	brcmf_dbg(TRACE, "Exit\n");
	return err;
}

static s32 brcmf_configure_opensecurity(struct brcmf_if *ifp)
{
	struct brcmf_pub *drvr = ifp->drvr;
	s32 err;
	s32 wpa_val;

	/* set auth */
	err = brcmf_fil_bsscfg_int_set(ifp, "auth", 0);
	if (err < 0) {
		bphy_err(drvr, "auth error %d\n", err);
		return err;
	}
	/* set wsec */
	err = brcmf_fil_bsscfg_int_set(ifp, "wsec", 0);
	if (err < 0) {
		bphy_err(drvr, "wsec error %d\n", err);
		return err;
	}
	/* set upper-layer auth */
	if (brcmf_is_ibssmode(ifp->vif))
		wpa_val = WPA_AUTH_NONE;
	else
		wpa_val = WPA_AUTH_DISABLED;
	err = brcmf_fil_bsscfg_int_set(ifp, "wpa_auth", wpa_val);
	if (err < 0) {
		bphy_err(drvr, "wpa_auth error %d\n", err);
		return err;
	}

	return 0;
}

static bool brcmf_valid_wpa_oui(u8 *oui, bool is_rsn_ie)
{
	if (is_rsn_ie)
		return (memcmp(oui, RSN_OUI, TLV_OUI_LEN) == 0);

	return (memcmp(oui, WPA_OUI, TLV_OUI_LEN) == 0);
}

static bool brcmf_valid_dpp_suite(u8 *oui)
{
	return (memcmp(oui, WFA_OUI, TLV_OUI_LEN) == 0 &&
		*(oui + TLV_OUI_LEN) == DPP_AKM_SUITE_TYPE);
}

static s32
brcmf_configure_wpaie(struct brcmf_if *ifp,
		      const struct brcmf_vs_tlv *wpa_ie,
		      bool is_rsn_ie)
{
	struct brcmf_pub *drvr = ifp->drvr;
	u32 auth = 0; /* d11 open authentication */
	u16 count;
	s32 err = 0;
	s32 len;
	u32 i;
	u32 wsec;
	u32 pval = 0;
	u32 gval = 0;
	u32 wpa_auth = 0;
	u32 offset;
	u8 *data;
	u16 rsn_cap;
	u32 wme_bss_disable;
	u32 mfp;

	brcmf_dbg(TRACE, "Enter\n");
	if (wpa_ie == NULL)
		goto exit;

	len = wpa_ie->len + TLV_HDR_LEN;
	data = (u8 *)wpa_ie;
	offset = TLV_HDR_LEN;
	if (!is_rsn_ie)
		offset += VS_IE_FIXED_HDR_LEN;
	else
		offset += WPA_IE_VERSION_LEN;

	/* check for multicast cipher suite */
	if (offset + WPA_IE_MIN_OUI_LEN > len) {
		err = -EINVAL;
		bphy_err(drvr, "no multicast cipher suite\n");
		goto exit;
	}

	if (!brcmf_valid_wpa_oui(&data[offset], is_rsn_ie)) {
		err = -EINVAL;
		bphy_err(drvr, "ivalid OUI\n");
		goto exit;
	}
	offset += TLV_OUI_LEN;

	/* pick up multicast cipher */
	switch (data[offset]) {
	case WPA_CIPHER_NONE:
		gval = 0;
		break;
	case WPA_CIPHER_WEP_40:
	case WPA_CIPHER_WEP_104:
		gval = WEP_ENABLED;
		break;
	case WPA_CIPHER_TKIP:
		gval = TKIP_ENABLED;
		break;
	case WPA_CIPHER_AES_CCM:
		gval = AES_ENABLED;
		break;
	default:
		err = -EINVAL;
		bphy_err(drvr, "Invalid multi cast cipher info\n");
		goto exit;
	}

	offset++;
	/* walk thru unicast cipher list and pick up what we recognize */
	count = data[offset] + (data[offset + 1] << 8);
	offset += WPA_IE_SUITE_COUNT_LEN;
	/* Check for unicast suite(s) */
	if (offset + (WPA_IE_MIN_OUI_LEN * count) > len) {
		err = -EINVAL;
		bphy_err(drvr, "no unicast cipher suite\n");
		goto exit;
	}
	for (i = 0; i < count; i++) {
		if (!brcmf_valid_wpa_oui(&data[offset], is_rsn_ie)) {
			err = -EINVAL;
			bphy_err(drvr, "ivalid OUI\n");
			goto exit;
		}
		offset += TLV_OUI_LEN;
		switch (data[offset]) {
		case WPA_CIPHER_NONE:
			break;
		case WPA_CIPHER_WEP_40:
		case WPA_CIPHER_WEP_104:
			pval |= WEP_ENABLED;
			break;
		case WPA_CIPHER_TKIP:
			pval |= TKIP_ENABLED;
			break;
		case WPA_CIPHER_AES_CCM:
			pval |= AES_ENABLED;
			break;
		default:
			bphy_err(drvr, "Invalid unicast security info\n");
		}
		offset++;
	}
	/* walk thru auth management suite list and pick up what we recognize */
	count = data[offset] + (data[offset + 1] << 8);
	offset += WPA_IE_SUITE_COUNT_LEN;
	/* Check for auth key management suite(s) */
	if (offset + (WPA_IE_MIN_OUI_LEN * count) > len) {
		err = -EINVAL;
		bphy_err(drvr, "no auth key mgmt suite\n");
		goto exit;
	}
	for (i = 0; i < count; i++) {
		if (brcmf_valid_dpp_suite(&data[offset])) {
			wpa_auth |= WFA_AUTH_DPP;
			offset += TLV_OUI_LEN;
		} else if (brcmf_valid_wpa_oui(&data[offset], is_rsn_ie)) {
			offset += TLV_OUI_LEN;
			switch (data[offset]) {
			case RSN_AKM_NONE:
				brcmf_dbg(TRACE, "RSN_AKM_NONE\n");
				wpa_auth |= WPA_AUTH_NONE;
				break;
			case RSN_AKM_UNSPECIFIED:
				brcmf_dbg(TRACE, "RSN_AKM_UNSPECIFIED\n");
				is_rsn_ie ?
					(wpa_auth |= WPA2_AUTH_UNSPECIFIED) :
					(wpa_auth |= WPA_AUTH_UNSPECIFIED);
				break;
			case RSN_AKM_PSK:
				brcmf_dbg(TRACE, "RSN_AKM_PSK\n");
				is_rsn_ie ? (wpa_auth |= WPA2_AUTH_PSK) :
					    (wpa_auth |= WPA_AUTH_PSK);
				break;
			case RSN_AKM_SHA256_PSK:
				brcmf_dbg(TRACE, "RSN_AKM_MFP_PSK\n");
				wpa_auth |= WPA2_AUTH_PSK_SHA256;
				break;
			case RSN_AKM_SHA256_1X:
				brcmf_dbg(TRACE, "RSN_AKM_MFP_1X\n");
				wpa_auth |= WPA2_AUTH_1X_SHA256;
				break;
			case RSN_AKM_SAE:
				brcmf_dbg(TRACE, "RSN_AKM_SAE\n");
				wpa_auth |= WPA3_AUTH_SAE_PSK;
				break;
			case RSN_AKM_OWE:
				brcmf_dbg(TRACE, "RSN_AKM_OWE\n");
				wpa_auth |= WPA3_AUTH_OWE;
				break;
			default:
				bphy_err(drvr, "Invalid key mgmt info\n");
			}
		} else {
			err = -EINVAL;
			bphy_err(drvr, "ivalid OUI\n");
			goto exit;
		}
		offset++;
	}

	mfp = BRCMF_MFP_NONE;
	if (is_rsn_ie) {
		wme_bss_disable = 1;
		if ((offset + RSN_CAP_LEN) <= len) {
			rsn_cap = data[offset] + (data[offset + 1] << 8);
			if (rsn_cap & RSN_CAP_PTK_REPLAY_CNTR_MASK)
				wme_bss_disable = 0;
			if (rsn_cap & RSN_CAP_MFPR_MASK) {
				brcmf_dbg(TRACE, "MFP Required\n");
				mfp = BRCMF_MFP_REQUIRED;
				/* Firmware only supports mfp required in
				 * combination with WPA2_AUTH_PSK_SHA256,
				 * WPA2_AUTH_1X_SHA256, or WPA3_AUTH_SAE_PSK.
				 */
				if (!(wpa_auth & (WPA2_AUTH_PSK_SHA256 |
						  WPA2_AUTH_1X_SHA256 |
						  WFA_AUTH_DPP |
						  WPA3_AUTH_SAE_PSK |
						  WPA3_AUTH_OWE))) {
					err = -EINVAL;
					goto exit;
				}

				/* Firmware has requirement that WPA2_AUTH_PSK/
				 * WPA2_AUTH_UNSPECIFIED be set, if SHA256 OUI
				 * is to be included in the rsn ie.
				 */
				if (wpa_auth & WPA2_AUTH_PSK_SHA256)
					wpa_auth |= WPA2_AUTH_PSK;
				else if (wpa_auth & WPA2_AUTH_1X_SHA256)
					wpa_auth |= WPA2_AUTH_UNSPECIFIED;
			} else if (rsn_cap & RSN_CAP_MFPC_MASK) {
				brcmf_dbg(TRACE, "MFP Capable\n");
				mfp = BRCMF_MFP_CAPABLE;
			}
		}
		offset += RSN_CAP_LEN;
		/* set wme_bss_disable to sync RSN Capabilities */
		err = brcmf_fil_bsscfg_int_set(ifp, "wme_bss_disable",
					       wme_bss_disable);
		if (err < 0) {
			bphy_err(drvr, "wme_bss_disable error %d\n", err);
			goto exit;
		}

		/* Skip PMKID cnt as it is know to be 0 for AP. */
		offset += RSN_PMKID_COUNT_LEN;

		/* See if there is BIP wpa suite left for MFP */
		if (brcmf_feat_is_enabled(ifp, BRCMF_FEAT_MFP) &&
		    ((offset + WPA_IE_MIN_OUI_LEN) <= len)) {
			err = brcmf_fil_bsscfg_data_set(ifp, "bip",
							&data[offset],
							WPA_IE_MIN_OUI_LEN);
			if (err < 0) {
				bphy_err(drvr, "bip error %d\n", err);
				goto exit;
			}
		}
	}
	/* FOR WPS , set SES_OW_ENABLED */
	wsec = (pval | gval | SES_OW_ENABLED);

	/* set auth */
	err = brcmf_fil_bsscfg_int_set(ifp, "auth", auth);
	if (err < 0) {
		bphy_err(drvr, "auth error %d\n", err);
		goto exit;
	}
	/* set wsec */
	err = brcmf_fil_bsscfg_int_set(ifp, "wsec", wsec);
	if (err < 0) {
		bphy_err(drvr, "wsec error %d\n", err);
		goto exit;
	}
	/* Configure MFP, this needs to go after wsec otherwise the wsec command
	 * will overwrite the values set by MFP
	 */
	if (brcmf_feat_is_enabled(ifp, BRCMF_FEAT_MFP)) {
		err = brcmf_fil_bsscfg_int_set(ifp, "mfp", mfp);
		if (err < 0) {
			bphy_err(drvr, "mfp error %d\n", err);
			goto exit;
		}
	}
	/* set upper-layer auth */
	err = brcmf_fil_bsscfg_int_set(ifp, "wpa_auth", wpa_auth);
	if (err < 0) {
		bphy_err(drvr, "wpa_auth error %d\n", err);
		goto exit;
	}

exit:
	return err;
}

static s32
brcmf_parse_vndr_ies(const u8 *vndr_ie_buf, u32 vndr_ie_len,
		     struct parsed_vndr_ies *vndr_ies)
{
	struct brcmf_vs_tlv *vndrie;
	struct brcmf_tlv *ie;
	struct parsed_vndr_ie_info *parsed_info;
	s32 remaining_len;

	remaining_len = (s32)vndr_ie_len;
	memset(vndr_ies, 0, sizeof(*vndr_ies));

	ie = (struct brcmf_tlv *)vndr_ie_buf;
	while (ie) {
		if (ie->id != WLAN_EID_VENDOR_SPECIFIC)
			goto next;
		vndrie = (struct brcmf_vs_tlv *)ie;
		/* len should be bigger than OUI length + one */
		if (vndrie->len < (VS_IE_FIXED_HDR_LEN - TLV_HDR_LEN + 1)) {
			brcmf_err("invalid vndr ie. length is too small %d\n",
				  vndrie->len);
			goto next;
		}
		/* if wpa or wme ie, do not add ie */
		if (!memcmp(vndrie->oui, (u8 *)WPA_OUI, TLV_OUI_LEN) &&
		    ((vndrie->oui_type == WPA_OUI_TYPE) ||
		    (vndrie->oui_type == WME_OUI_TYPE))) {
			brcmf_dbg(TRACE, "Found WPA/WME oui. Do not add it\n");
			goto next;
		}

		parsed_info = &vndr_ies->ie_info[vndr_ies->count];

		/* save vndr ie information */
		parsed_info->ie_ptr = (char *)vndrie;
		parsed_info->ie_len = vndrie->len + TLV_HDR_LEN;
		memcpy(&parsed_info->vndrie, vndrie, sizeof(*vndrie));

		vndr_ies->count++;

		brcmf_dbg(TRACE, "** OUI %3ph, type 0x%02x\n",
			  parsed_info->vndrie.oui,
			  parsed_info->vndrie.oui_type);

		if (vndr_ies->count >= VNDR_IE_PARSE_LIMIT)
			break;
next:
		remaining_len -= (ie->len + TLV_HDR_LEN);
		if (remaining_len <= TLV_HDR_LEN)
			ie = NULL;
		else
			ie = (struct brcmf_tlv *)(((u8 *)ie) + ie->len +
				TLV_HDR_LEN);
	}
	return 0;
}

static u32
brcmf_vndr_ie(u8 *iebuf, s32 pktflag, u8 *ie_ptr, u32 ie_len, s8 *add_del_cmd)
{
	strscpy(iebuf, add_del_cmd, VNDR_IE_CMD_LEN);

	put_unaligned_le32(1, &iebuf[VNDR_IE_COUNT_OFFSET]);

	put_unaligned_le32(pktflag, &iebuf[VNDR_IE_PKTFLAG_OFFSET]);

	memcpy(&iebuf[VNDR_IE_VSIE_OFFSET], ie_ptr, ie_len);

	return ie_len + VNDR_IE_HDR_SIZE;
}

static s32
brcmf_parse_extension_ies(const u8 *extension_ie_buf, u32 extension_ie_len,
			  struct parsed_extension_ies *extension_ies)
{
	struct brcmf_ext_tlv *ext_ie;
	struct brcmf_tlv *ie;
	struct parsed_ext_ie_info *parsed_info;
	s32 remaining_len;

	remaining_len = (s32)extension_ie_len;
	memset(extension_ies, 0, sizeof(*extension_ies));

	ie = (struct brcmf_tlv *)extension_ie_buf;
	while (ie) {
		if (ie->id != WLAN_EID_EXTENSION)
			goto next;
		ext_ie = (struct brcmf_ext_tlv *)ie;

		/* len should be bigger than ext_id + one data */
		if (ext_ie->len < 2) {
			brcmf_err("invalid ext_ie ie. length is too small %d\n",
				  ext_ie->len);
			goto next;
		}

		/* skip parsing the HE capab, HE_6G_capa & oper IE from upper layer
		 * to avoid sending it to the FW, as these IEs will be
		 * added by the FW based on the MAC & PHY capab if HE
		 * is enabled.
		 */
		if (ext_ie->ext_id == WLAN_EID_EXT_HE_CAPABILITY ||
		    ext_ie->ext_id == WLAN_EID_EXT_HE_OPERATION ||
		    ext_ie->ext_id == WLAN_EID_EXT_HE_6GHZ_CAPA)
			goto next;

		parsed_info = &extension_ies->ie_info[extension_ies->count];

		parsed_info->ie_ptr = (char *)ext_ie;
		parsed_info->ie_len = ext_ie->len + TLV_HDR_LEN;
		memcpy(&parsed_info->ie_data, ext_ie, sizeof(*ext_ie));

		extension_ies->count++;

		brcmf_dbg(TRACE, "** EXT_IE %d, len 0x%02x EXT_ID: %d\n",
			  parsed_info->ie_data.id,
			  parsed_info->ie_data.len,
			  parsed_info->ie_data.ext_id);

		/* temperory parsing at most 5 EXT_ID, will review it.*/
		if (extension_ies->count >= VNDR_IE_PARSE_LIMIT)
			break;
next:
		remaining_len -= (ie->len + TLV_HDR_LEN);
		if (remaining_len <= TLV_HDR_LEN)
			ie = NULL;
		else
			ie = (struct brcmf_tlv *)(((u8 *)ie) + ie->len +
				TLV_HDR_LEN);
	}
	return 0;
}

s32 brcmf_vif_set_mgmt_ie(struct brcmf_cfg80211_vif *vif, s32 pktflag,
			  const u8 *vndr_ie_buf, u32 vndr_ie_len)
{
	struct brcmf_pub *drvr;
	struct brcmf_if *ifp;
	struct vif_saved_ie *saved_ie;
	s32 err = 0;
	u8  *iovar_ie_buf;
	u8  *curr_ie_buf;
	u8  *mgmt_ie_buf = NULL;
	int mgmt_ie_buf_len;
	u32 *mgmt_ie_len;
	u32 del_add_ie_buf_len = 0;
	u32 total_ie_buf_len = 0;
	u32 parsed_ie_buf_len = 0;
	struct parsed_vndr_ies old_vndr_ies;
	struct parsed_vndr_ies new_vndr_ies;
	struct parsed_vndr_ie_info *vndrie_info;
	s32 i;
	u8 *ptr;
	int remained_buf_len;
	struct parsed_extension_ies new_ext_ies;
	struct parsed_extension_ies old_ext_ies;
	struct parsed_ext_ie_info *extie_info;

	if (!vif)
		return -ENODEV;
	ifp = vif->ifp;
	drvr = ifp->drvr;
	saved_ie = &vif->saved_ie;

	brcmf_dbg(TRACE, "bsscfgidx %d, pktflag : 0x%02X\n", ifp->bsscfgidx,
		  pktflag);
	iovar_ie_buf = kzalloc(WL_EXTRA_BUF_MAX, GFP_KERNEL);
	if (!iovar_ie_buf)
		return -ENOMEM;
	curr_ie_buf = iovar_ie_buf;
	switch (pktflag) {
	case BRCMF_VNDR_IE_PRBREQ_FLAG:
		mgmt_ie_buf = saved_ie->probe_req_ie;
		mgmt_ie_len = &saved_ie->probe_req_ie_len;
		mgmt_ie_buf_len = sizeof(saved_ie->probe_req_ie);
		break;
	case BRCMF_VNDR_IE_PRBRSP_FLAG:
		mgmt_ie_buf = saved_ie->probe_res_ie;
		mgmt_ie_len = &saved_ie->probe_res_ie_len;
		mgmt_ie_buf_len = sizeof(saved_ie->probe_res_ie);
		break;
	case BRCMF_VNDR_IE_BEACON_FLAG:
		mgmt_ie_buf = saved_ie->beacon_ie;
		mgmt_ie_len = &saved_ie->beacon_ie_len;
		mgmt_ie_buf_len = sizeof(saved_ie->beacon_ie);
		break;
	case BRCMF_VNDR_IE_ASSOCREQ_FLAG:
		mgmt_ie_buf = saved_ie->assoc_req_ie;
		mgmt_ie_len = &saved_ie->assoc_req_ie_len;
		mgmt_ie_buf_len = sizeof(saved_ie->assoc_req_ie);
		break;
	case BRCMF_VNDR_IE_ASSOCRSP_FLAG:
		mgmt_ie_buf = saved_ie->assoc_res_ie;
		mgmt_ie_len = &saved_ie->assoc_res_ie_len;
		mgmt_ie_buf_len = sizeof(saved_ie->assoc_res_ie);
		break;
	default:
		err = -EPERM;
		bphy_err(drvr, "not suitable type\n");
		goto exit;
	}

	if (vndr_ie_len > mgmt_ie_buf_len) {
		err = -ENOMEM;
		bphy_err(drvr, "extra IE size too big\n");
		goto exit;
	}

	/* parse and save new vndr_ie in curr_ie_buff before comparing it */
	if (vndr_ie_buf && vndr_ie_len && curr_ie_buf) {
		ptr = curr_ie_buf;
		brcmf_parse_vndr_ies(vndr_ie_buf, vndr_ie_len, &new_vndr_ies);
		for (i = 0; i < new_vndr_ies.count; i++) {
			vndrie_info = &new_vndr_ies.ie_info[i];
			memcpy(ptr + parsed_ie_buf_len, vndrie_info->ie_ptr,
			       vndrie_info->ie_len);
			parsed_ie_buf_len += vndrie_info->ie_len;
		}
		brcmf_parse_extension_ies(vndr_ie_buf, vndr_ie_len, &new_ext_ies);
		for (i = 0; i < new_ext_ies.count; i++) {
			extie_info = &new_ext_ies.ie_info[i];
			memcpy(ptr + parsed_ie_buf_len, extie_info->ie_ptr,
			       extie_info->ie_len);
			parsed_ie_buf_len += extie_info->ie_len;
		}
	}

	if (mgmt_ie_buf && *mgmt_ie_len) {
		if (parsed_ie_buf_len && (parsed_ie_buf_len == *mgmt_ie_len) &&
		    (memcmp(mgmt_ie_buf, curr_ie_buf,
			    parsed_ie_buf_len) == 0)) {
			brcmf_dbg(TRACE, "Previous mgmt IE equals to current IE\n");
			goto exit;
		}

		/* parse old vndr_ie */
		brcmf_parse_vndr_ies(mgmt_ie_buf, *mgmt_ie_len, &old_vndr_ies);
		/* parse old ext_ie */
		brcmf_parse_extension_ies(mgmt_ie_buf, *mgmt_ie_len, &old_ext_ies);

		/* make a command to delete old ie */
		for (i = 0; i < old_vndr_ies.count; i++) {
			vndrie_info = &old_vndr_ies.ie_info[i];

			brcmf_dbg(TRACE, "DEL ID : %d, Len: %d , OUI:%3ph\n",
				  vndrie_info->vndrie.id,
				  vndrie_info->vndrie.len,
				  vndrie_info->vndrie.oui);

			del_add_ie_buf_len = brcmf_vndr_ie(curr_ie_buf, pktflag,
							   vndrie_info->ie_ptr,
							   vndrie_info->ie_len,
							   "del");
			curr_ie_buf += del_add_ie_buf_len;
			total_ie_buf_len += del_add_ie_buf_len;
		}
		/* make a command to delete old extension ie */
		for (i = 0; i < old_ext_ies.count; i++) {
			extie_info = &old_ext_ies.ie_info[i];

			brcmf_dbg(TRACE, "DEL EXT_IE : %d, Len: %d , ext_id:%d\n",
				  extie_info->ie_data.id,
				  extie_info->ie_data.len,
				  extie_info->ie_data.ext_id);

			del_add_ie_buf_len = brcmf_vndr_ie(curr_ie_buf,
							   pktflag | BRCMF_VNDR_IE_CUSTOM_FLAG,
							   extie_info->ie_ptr,
							   extie_info->ie_len,
							   "del");
			curr_ie_buf += del_add_ie_buf_len;
			total_ie_buf_len += del_add_ie_buf_len;
		}
	}

	*mgmt_ie_len = 0;
	/* Add if there is any extra IE */
	if (mgmt_ie_buf && parsed_ie_buf_len) {
		ptr = mgmt_ie_buf;

		remained_buf_len = mgmt_ie_buf_len;

		/* make a command to add new ie */
		for (i = 0; i < new_vndr_ies.count; i++) {
			vndrie_info = &new_vndr_ies.ie_info[i];

			/* verify remained buf size before copy data */
			if (remained_buf_len < (vndrie_info->vndrie.len +
							VNDR_IE_VSIE_OFFSET)) {
				bphy_err(drvr, "no space in mgmt_ie_buf: len left %d",
					 remained_buf_len);
				break;
			}
			remained_buf_len -= (vndrie_info->ie_len +
					     VNDR_IE_VSIE_OFFSET);

			brcmf_dbg(TRACE, "ADDED ID : %d, Len: %d, OUI:%3ph\n",
				  vndrie_info->vndrie.id,
				  vndrie_info->vndrie.len,
				  vndrie_info->vndrie.oui);

			del_add_ie_buf_len = brcmf_vndr_ie(curr_ie_buf, pktflag,
							   vndrie_info->ie_ptr,
							   vndrie_info->ie_len,
							   "add");

			/* save the parsed IE in wl struct */
			memcpy(ptr + (*mgmt_ie_len), vndrie_info->ie_ptr,
			       vndrie_info->ie_len);
			*mgmt_ie_len += vndrie_info->ie_len;

			curr_ie_buf += del_add_ie_buf_len;
			total_ie_buf_len += del_add_ie_buf_len;
		}
		/* make a command to add new EXT ie */
		for (i = 0; i < new_ext_ies.count; i++) {
			extie_info = &new_ext_ies.ie_info[i];

			/* verify remained buf size before copy data */
			if (remained_buf_len < (extie_info->ie_data.len +
							VNDR_IE_VSIE_OFFSET)) {
				bphy_err(drvr, "no space in mgmt_ie_buf: len left %d",
					 remained_buf_len);
				break;
			}
			remained_buf_len -= (extie_info->ie_len +
					     VNDR_IE_VSIE_OFFSET);

			brcmf_dbg(TRACE, "ADDED EXT ID : %d, Len: %d, OUI:%d\n",
				  extie_info->ie_data.id,
				  extie_info->ie_data.len,
				  extie_info->ie_data.ext_id);

			del_add_ie_buf_len = brcmf_vndr_ie(curr_ie_buf,
							   pktflag | BRCMF_VNDR_IE_CUSTOM_FLAG,
							   extie_info->ie_ptr,
							   extie_info->ie_len,
							   "add");

			/* save the parsed IE in wl struct */
			memcpy(ptr + (*mgmt_ie_len), extie_info->ie_ptr,
			       extie_info->ie_len);
			*mgmt_ie_len += extie_info->ie_len;

			curr_ie_buf += del_add_ie_buf_len;
			total_ie_buf_len += del_add_ie_buf_len;
		}
	}
	if (total_ie_buf_len) {
		err  = brcmf_fil_bsscfg_data_set(ifp, "vndr_ie", iovar_ie_buf,
						 total_ie_buf_len);
		if (err)
			bphy_err(drvr, "vndr ie set error : %d\n", err);
	}

exit:
	kfree(iovar_ie_buf);
	return err;
}

s32 brcmf_vif_clear_mgmt_ies(struct brcmf_cfg80211_vif *vif)
{
	static const s32 pktflags[] = {
		BRCMF_VNDR_IE_PRBREQ_FLAG,
		BRCMF_VNDR_IE_PRBRSP_FLAG,
		BRCMF_VNDR_IE_BEACON_FLAG,
		BRCMF_VNDR_IE_ASSOCRSP_FLAG
	};
	int i;

	for (i = 0; i < ARRAY_SIZE(pktflags); i++)
		brcmf_vif_set_mgmt_ie(vif, pktflags[i], NULL, 0);

	memset(&vif->saved_ie, 0, sizeof(vif->saved_ie));
	return 0;
}

static s32
brcmf_config_ap_mgmt_ie(struct brcmf_cfg80211_vif *vif,
			struct cfg80211_beacon_data *beacon)
{
	struct brcmf_pub *drvr = vif->ifp->drvr;
	s32 err;

	/* Set Beacon IEs to FW */
	err = brcmf_vif_set_mgmt_ie(vif, BRCMF_VNDR_IE_BEACON_FLAG,
				    beacon->tail, beacon->tail_len);
	if (err) {
		bphy_err(drvr, "Set Beacon IE Failed\n");
		return err;
	}
	brcmf_dbg(TRACE, "Applied Vndr IEs for Beacon\n");

	/* Set Probe Response IEs to FW */
	err = brcmf_vif_set_mgmt_ie(vif, BRCMF_VNDR_IE_PRBRSP_FLAG,
				    beacon->proberesp_ies,
				    beacon->proberesp_ies_len);
	if (err)
		bphy_err(drvr, "Set Probe Resp IE Failed\n");
	else
		brcmf_dbg(TRACE, "Applied Vndr IEs for Probe Resp\n");

	/* Set Assoc Response IEs to FW */
	err = brcmf_vif_set_mgmt_ie(vif, BRCMF_VNDR_IE_ASSOCRSP_FLAG,
				    beacon->assocresp_ies,
				    beacon->assocresp_ies_len);
	if (err)
		brcmf_err("Set Assoc Resp IE Failed\n");
	else
		brcmf_dbg(TRACE, "Applied Vndr IEs for Assoc Resp\n");

	return err;
}

static s32
brcmf_parse_configure_sae_pwe(struct brcmf_if *ifp,
			      struct cfg80211_ap_settings *settings)
{
	s32 err = 0;
	const struct brcmf_tlv *rsnx_ie;
	const struct brcmf_tlv *ext_rate_ie;
	const struct brcmf_tlv *supp_rate_ie;
	u8 ie_len, i;
	bool support_sae_h2e = false, must_sae_h2e = false;
	u32 wpa_auth = 0;

	/* get configured wpa_auth */
	err = brcmf_fil_bsscfg_int_get(ifp, "wpa_auth", &wpa_auth);
	if ((wpa_auth & WPA3_AUTH_SAE_PSK) == 0) {
		/* wpa_auth is not SAE, ignore sae_pwe. */
		brcmf_dbg(INFO, "wpa_auth is not SAE:0x%x\n", wpa_auth);
		return 0;
	}

	if (brcmf_feat_is_enabled(ifp, BRCMF_FEAT_SAE_EXT)) {
		err = brcmf_fil_iovar_int_set(ifp, "extsae_pwe", 0);
		if (err) {
			brcmf_err("extsae_pwe iovar is not supported\n");
			return -EOPNOTSUPP;
		}

		rsnx_ie = brcmf_parse_tlvs((u8 *)settings->beacon.tail,
					   settings->beacon.tail_len,
					   WLAN_EID_RSNX);
		if (rsnx_ie) {
			ie_len = rsnx_ie->len;
			if (ie_len) {
				if (rsnx_ie->data[0] & WLAN_RSNX_CAPA_SAE_H2E)
					support_sae_h2e = true;
			}
			brcmf_dbg(INFO, "found RSNX IE, support_sae_h2e:%d\n",
				  support_sae_h2e);
		}

		/* found rsnx_ie with SAE_H2E, check the bss selector to know if it is a H2E only */
		if (support_sae_h2e) {
			supp_rate_ie = brcmf_parse_tlvs((u8 *)settings->beacon.head,
							settings->beacon.head_len,
							WLAN_EID_SUPP_RATES);
			ext_rate_ie = brcmf_parse_tlvs((u8 *)settings->beacon.tail,
						       settings->beacon.tail_len,
						       WLAN_EID_EXT_SUPP_RATES);
			if (ext_rate_ie) {
				ie_len = ext_rate_ie->len;
				for (i = 0; i < ie_len; i++) {
					if (ext_rate_ie->data[i] == SAE_H2E_ONLY_ENABLE) {
						must_sae_h2e = true;
						break;
					}
				}
			}

			/* if we cannot found H2E only selector in ext_supp_rate ie.
			 * traversal supp_rate ie to make sure it really doesn't exist.
			 */
			if (!must_sae_h2e && supp_rate_ie) {
				ie_len = supp_rate_ie->len;
				for (i = 0; i < ie_len; i++) {
					if (supp_rate_ie->data[i] == SAE_H2E_ONLY_ENABLE) {
						must_sae_h2e = true;
						break;
					}
				}
			}
			brcmf_dbg(INFO, "must_sae_h2e:%d\n", must_sae_h2e);
		}

		if (must_sae_h2e) /* support SAE H2E only */
			err = brcmf_fil_iovar_int_set(ifp, "extsae_pwe", 1);
		else if (support_sae_h2e) /* support SAE P&H and H2E both */
			err = brcmf_fil_iovar_int_set(ifp, "extsae_pwe", 2);
		else /* support SAE P&H only */
			err = brcmf_fil_iovar_int_set(ifp, "extsae_pwe", 0);
	}

	return err;
}

static s32
brcmf_parse_configure_security(struct brcmf_if *ifp,
			       struct cfg80211_ap_settings *settings,
			       enum nl80211_iftype dev_role)
{
	const struct brcmf_tlv *rsn_ie;
	const struct brcmf_vs_tlv *wpa_ie;
	s32 err = 0;

	/* find the RSN_IE */
	rsn_ie = brcmf_parse_tlvs((u8 *)settings->beacon.tail,
				  settings->beacon.tail_len, WLAN_EID_RSN);

	/* find the WPA_IE */
	wpa_ie = brcmf_find_wpaie((u8 *)settings->beacon.tail,
				  settings->beacon.tail_len);

	if (wpa_ie || rsn_ie) {
		brcmf_dbg(TRACE, "WPA(2) IE is found\n");
		if (wpa_ie) {
			/* WPA IE */
			err = brcmf_configure_wpaie(ifp, wpa_ie, false);
			if (err < 0)
				return err;
		} else {
			struct brcmf_vs_tlv *tmp_ie;

			tmp_ie = (struct brcmf_vs_tlv *)rsn_ie;

			/* RSN IE */
			err = brcmf_configure_wpaie(ifp, tmp_ie, true);
			if (err < 0)
				return err;

			err = brcmf_parse_configure_sae_pwe(ifp, settings);
			if (err < 0)
				return err;
		}
	} else {
		brcmf_dbg(TRACE, "No WPA(2) IEs found\n");
		brcmf_configure_opensecurity(ifp);
	}

	return err;
}

static s32
brcmf_cfg80211_start_ap(struct wiphy *wiphy, struct net_device *ndev,
			struct cfg80211_ap_settings *settings)
{
	s32 ie_offset;
	struct brcmf_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct brcmf_if *ifp = netdev_priv(ndev);
	struct brcmf_pub *drvr = cfg->pub;
	struct brcmf_cfg80211_profile *profile = &ifp->vif->profile;
	struct cfg80211_crypto_settings *crypto = &settings->crypto;
	const struct brcmf_tlv *ssid_ie;
	const struct brcmf_tlv *country_ie;
	struct brcmf_ssid_le ssid_le;
	s32 err = -EPERM;
	struct brcmf_join_params join_params;
	enum nl80211_iftype dev_role;
	struct brcmf_fil_bss_enable_le bss_enable;
	u16 chanspec = chandef_to_chanspec(&cfg->d11inf, &settings->chandef);
	bool mbss = false;
	int is_11d;
	bool supports_11d;
	struct bcm_xtlv *he_tlv;
	struct brcmf_p2p_info *p2p = &cfg->p2p;

	brcmf_dbg(TRACE, "ctrlchn=%d, center=%d, bw=%d, beacon_interval=%d, dtim_period=%d,\n",
		  settings->chandef.chan->hw_value,
		  settings->chandef.center_freq1, settings->chandef.width,
		  settings->beacon_interval, settings->dtim_period);
	brcmf_dbg(TRACE, "ssid=%s(%zu), auth_type=%d, inactivity_timeout=%d\n",
		  settings->ssid, settings->ssid_len, settings->auth_type,
		  settings->inactivity_timeout);
	dev_role = ifp->vif->wdev.iftype;

	if (dev_role == NL80211_IFTYPE_AP &&
	    brcmf_feat_is_enabled(ifp, BRCMF_FEAT_MBSS)) {
		struct brcmf_cfg80211_vif *vif_walk;

		list_for_each_entry(vif_walk, &cfg->vif_list, list) {
			if (brcmf_is_apmode(vif_walk) &&
			    check_vif_up(vif_walk) &&
			    vif_walk != ifp->vif) {
				/* found a vif is with the 1st AP type,
				 * and it doesn't equal to the currect vif calls start_ap.
				 * then it is mbss case.
				 */
				mbss = true;
				break;
			}
		}
	}
	brcmf_dbg(TRACE, "mbss %s\n", mbss ? "enabled" : "disabled");

	/* store current 11d setting */
	if (brcmf_fil_cmd_int_get(ifp, BRCMF_C_GET_REGULATORY,
				  &ifp->vif->is_11d)) {
		is_11d = supports_11d = false;
	} else {
		country_ie = brcmf_parse_tlvs((u8 *)settings->beacon.tail,
					      settings->beacon.tail_len,
					      WLAN_EID_COUNTRY);
		is_11d = country_ie ? 1 : 0;
		supports_11d = true;
	}

	memset(&ssid_le, 0, sizeof(ssid_le));
	if (settings->ssid == NULL || settings->ssid_len == 0) {
		ie_offset = DOT11_MGMT_HDR_LEN + DOT11_BCN_PRB_FIXED_LEN;
		ssid_ie = brcmf_parse_tlvs(
				(u8 *)&settings->beacon.head[ie_offset],
				settings->beacon.head_len - ie_offset,
				WLAN_EID_SSID);
		if (!ssid_ie || ssid_ie->len > IEEE80211_MAX_SSID_LEN)
			return -EINVAL;

		memcpy(ssid_le.SSID, ssid_ie->data, ssid_ie->len);
		ssid_le.SSID_len = cpu_to_le32(ssid_ie->len);
		brcmf_dbg(TRACE, "SSID is (%s) in Head\n", ssid_le.SSID);
	} else {
		memcpy(ssid_le.SSID, settings->ssid, settings->ssid_len);
		ssid_le.SSID_len = cpu_to_le32((u32)settings->ssid_len);
	}

	if (!mbss) {
		brcmf_set_mpc(ifp, 0);
		brcmf_configure_arp_nd_offload(ifp, false);
	}

	/* Parameters shared by all radio interfaces */
	if (!mbss) {
		if ((supports_11d) && (is_11d != ifp->vif->is_11d)) {
			err = brcmf_fil_cmd_int_set(ifp, BRCMF_C_SET_REGULATORY,
						    is_11d);
			if (err < 0) {
				bphy_err(drvr, "Regulatory Set Error, %d\n",
					 err);
				goto exit;
			}
		}
		if (settings->beacon_interval) {
			err = brcmf_fil_cmd_int_set(ifp, BRCMF_C_SET_BCNPRD,
						    settings->beacon_interval);
			if (err < 0) {
				bphy_err(drvr, "Beacon Interval Set Error, %d\n",
					 err);
				goto exit;
			}
		}
		if (settings->dtim_period) {
			err = brcmf_fil_cmd_int_set(ifp, BRCMF_C_SET_DTIMPRD,
						    settings->dtim_period);
			if (err < 0) {
				bphy_err(drvr, "DTIM Interval Set Error, %d\n",
					 err);
				goto exit;
			}
		}

		if ((dev_role == NL80211_IFTYPE_AP) &&
		    ((ifp->ifidx == 0) ||
		     (!brcmf_feat_is_enabled(ifp, BRCMF_FEAT_RSDB) &&
		      !brcmf_feat_is_enabled(ifp, BRCMF_FEAT_MCHAN)))) {
			err = brcmf_fil_cmd_int_set(ifp, BRCMF_C_DOWN, 1);
			if (err < 0) {
				bphy_err(drvr, "BRCMF_C_DOWN error %d\n",
					 err);
				goto exit;
			}
			brcmf_fil_iovar_int_set(ifp, "apsta", 0);
		}

		err = brcmf_fil_cmd_int_set(ifp, BRCMF_C_SET_INFRA, 1);
		if (err < 0) {
			bphy_err(drvr, "SET INFRA error %d\n", err);
			goto exit;
		}
	} else if (WARN_ON(supports_11d && (is_11d != ifp->vif->is_11d))) {
		/* Multiple-BSS should use same 11d configuration */
		err = -EINVAL;
		goto exit;
	}
	ifp->isap = false;
	/* Interface specific setup */
	if (dev_role == NL80211_IFTYPE_AP) {
		u32 is_up;

		if ((brcmf_feat_is_enabled(ifp, BRCMF_FEAT_MBSS)) && !mbss) {
			err = brcmf_fil_cmd_int_get(ifp, BRCMF_C_GET_UP, &is_up);
			if (err < 0) {
				bphy_err(drvr, "BRCMF_C_GET_UP error (%d)\n", err);
				goto exit;
			}

			/* mbss must be set in DOWN state. */
			if (is_up) {
				err = brcmf_fil_cmd_int_set(ifp, BRCMF_C_DOWN, 1);
				if (err < 0) {
					bphy_err(drvr, "BRCMF_C_DOWN error (%d)\n", err);
					goto exit;
				}
			}
			err = brcmf_fil_iovar_int_set(ifp, "mbss", 1);
			if (err < 0) {
				bphy_err(drvr, "set mbss error (%d)\n", err);
				goto exit;
			}
		}

		if (!test_bit(BRCMF_VIF_STATUS_AP_CREATED, &ifp->vif->sme_state)) {
			bss_enable.bsscfgidx = cpu_to_le32(ifp->bsscfgidx);
			bss_enable.enable = cpu_to_le32(WL_IOV_OP_MANUAL_AP_BSSCFG_CREATE);
			err = brcmf_fil_iovar_data_set(ifp, "bss", &bss_enable,
						       sizeof(bss_enable));
			if (err < 0) {
				bphy_err(drvr, "bss_enable config failed %d\n", err);
				goto exit;
			}
		}

		err = brcmf_fil_cmd_int_set(ifp, BRCMF_C_SET_AP, 1);
		if (err < 0) {
			bphy_err(drvr, "setting AP mode failed %d\n",
				 err);
			goto exit;
		}

		/* Firmware 10.x requires setting channel after enabling
		 * AP and before bringing interface up.
		 */
		err = brcmf_fil_iovar_int_set(ifp, "chanspec", chanspec);
		if (err < 0) {
			bphy_err(drvr, "Set Channel failed: chspec=%d, %d\n",
				 chanspec, err);
			goto exit;
		}

		err = brcmf_fil_cmd_int_get(ifp, BRCMF_C_GET_UP, &is_up);
		if (err < 0) {
			bphy_err(drvr, "BRCMF_C_GET_UP error (%d)\n", err);
			goto exit;
		}

		if (!is_up)
			err = brcmf_fil_cmd_int_set(ifp, BRCMF_C_UP, 1);
		if (err < 0) {
			bphy_err(drvr, "BRCMF_C_UP error (%d)\n", err);
			goto exit;
		}

		if (crypto->psk) {
			brcmf_dbg(INFO, "using PSK offload\n");
			profile->use_fwauth |= BIT(BRCMF_PROFILE_FWAUTH_PSK);
			err = brcmf_set_pmk(ifp, crypto->psk,
					    BRCMF_WSEC_MAX_PSK_LEN);
			if (err < 0)
				goto exit;
		}
		if (crypto->sae_pwd) {
			brcmf_dbg(INFO, "using SAE offload\n");
			profile->use_fwauth |= BIT(BRCMF_PROFILE_FWAUTH_SAE);
			err = brcmf_set_sae_password(ifp, crypto->sae_pwd,
						     crypto->sae_pwd_len);
			if (err < 0)
				goto exit;
		}
		if (profile->use_fwauth == 0)
			profile->use_fwauth = BIT(BRCMF_PROFILE_FWAUTH_NONE);

		err = brcmf_parse_configure_security(ifp, settings,
						     NL80211_IFTYPE_AP);
		if (err < 0) {
			bphy_err(drvr, "brcmf_parse_configure_security error\n");
			goto exit;
		}

		/* On DOWN the firmware removes the WEP keys, reconfigure
		 * them if they were set.
		 */
		brcmf_cfg80211_reconfigure_wep(ifp);

		memset(&join_params, 0, sizeof(join_params));
		/* join parameters starts with ssid */
		memcpy(&join_params.ssid_le, &ssid_le, sizeof(ssid_le));
		/* create softap */
		err = brcmf_fil_cmd_data_set(ifp, BRCMF_C_SET_SSID,
					     &join_params, sizeof(join_params));
		if (err < 0) {
			bphy_err(drvr, "SET SSID error (%d)\n", err);
			goto exit;
		}

		err = brcmf_fil_iovar_int_set(ifp, "closednet",
					      settings->hidden_ssid);
		if (err) {
			bphy_err(drvr, "%s closednet error (%d)\n",
				 settings->hidden_ssid ?
				 "enabled" : "disabled",
				 err);
			goto exit;
		}
		ifp->isap = true;
		brcmf_dbg(TRACE, "AP mode configuration complete\n");
	} else if (dev_role == NL80211_IFTYPE_P2P_GO) {
		err = brcmf_fil_iovar_int_set(ifp, "chanspec", chanspec);
		if (err < 0) {
			bphy_err(drvr, "Set Channel failed: chspec=%d, %d\n",
				 chanspec, err);
			goto exit;
		}

		err = brcmf_parse_configure_security(ifp, settings,
						     NL80211_IFTYPE_P2P_GO);
		if (err < 0) {
			brcmf_err("brcmf_parse_configure_security error\n");
			goto exit;
		}

		err = brcmf_fil_bsscfg_data_set(ifp, "ssid", &ssid_le,
						sizeof(ssid_le));
		if (err < 0) {
			bphy_err(drvr, "setting ssid failed %d\n", err);
			goto exit;
		}
		bss_enable.bsscfgidx = cpu_to_le32(ifp->bsscfgidx);
		bss_enable.enable = cpu_to_le32(WL_IOV_OP_BSSCFG_ENABLE);
		err = brcmf_fil_iovar_data_set(ifp, "bss", &bss_enable,
					       sizeof(bss_enable));
		if (err < 0) {
			bphy_err(drvr, "bss_enable config failed %d\n", err);
			goto exit;
		}

		p2p->afx_hdl.my_listen_chan = chanspec;
		ifp->isap = true;
		brcmf_dbg(TRACE, "GO mode configuration complete\n");
	} else {
		WARN_ON(1);
	}
	/* Set he_bss_color in hostapd */
	if (settings->beacon.he_bss_color.enabled) {
		u8 param[8] = {0};

		he_tlv = (struct bcm_xtlv *)param;
		he_tlv->id = cpu_to_le16(IFX_HE_CMD_BSSCOLOR);
		he_tlv->len = cpu_to_le16(1);
		memcpy(he_tlv->data, &settings->beacon.he_bss_color.color, sizeof(u8));
		err = brcmf_fil_iovar_data_set(ifp, "he", param, sizeof(param));

		if (err)
			brcmf_err("set he bss_color error:%d\n", err);
	}

	brcmf_vif_clear_mgmt_ies(ifp->vif);
	brcmf_config_ap_mgmt_ie(ifp->vif, &settings->beacon);
	set_bit(BRCMF_VIF_STATUS_AP_CREATED, &ifp->vif->sme_state);
	brcmf_net_setcarrier(ifp, true);

exit:
	if ((err) && (!mbss)) {
		brcmf_set_mpc(ifp, 1);
		brcmf_configure_arp_nd_offload(ifp, true);
	} else {
		cfg->num_softap++;
		brcmf_dbg(TRACE, "Num of SoftAP %u\n", cfg->num_softap);
	}
	return err;
}

static int brcmf_cfg80211_stop_ap(struct wiphy *wiphy, struct net_device *ndev,
				  unsigned int link_id)
{
	struct brcmf_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct brcmf_if *ifp = netdev_priv(ndev);
	struct brcmf_pub *drvr = cfg->pub;
	struct brcmf_cfg80211_profile *profile = &ifp->vif->profile;
	s32 err;
	struct brcmf_fil_bss_enable_le bss_enable;
	struct brcmf_join_params join_params;
	s32 apsta = 0;

	brcmf_dbg(TRACE, "Enter\n");

	if (ifp->vif->wdev.iftype == NL80211_IFTYPE_AP) {
		/* Due to most likely deauths outstanding we sleep */
		/* first to make sure they get processed by fw. */
		msleep(400);

		if (profile->use_fwauth != BIT(BRCMF_PROFILE_FWAUTH_NONE)) {
			if (profile->use_fwauth & BIT(BRCMF_PROFILE_FWAUTH_PSK))
				brcmf_set_pmk(ifp, NULL, 0);
			if (profile->use_fwauth & BIT(BRCMF_PROFILE_FWAUTH_SAE))
				brcmf_set_sae_password(ifp, NULL, 0);
			profile->use_fwauth = BIT(BRCMF_PROFILE_FWAUTH_NONE);
		}

		cfg->num_softap--;

		/* Clear bss configuration and SSID */
		bss_enable.bsscfgidx = cpu_to_le32(ifp->bsscfgidx);
		bss_enable.enable = cpu_to_le32(WL_IOV_OP_BSSCFG_DISABLE);
		err = brcmf_fil_iovar_data_set(ifp, "bss", &bss_enable,
					       sizeof(bss_enable));
		if (err < 0)
			brcmf_err("bss_enable config failed %d\n", err);

		memset(&join_params, 0, sizeof(join_params));
		err = brcmf_fil_cmd_data_set(ifp, BRCMF_C_SET_SSID,
					     &join_params, sizeof(join_params));
		if (err < 0)
			bphy_err(drvr, "SET SSID error (%d)\n", err);

		if (cfg->num_softap) {
			brcmf_dbg(TRACE, "Num of SoftAP %u\n", cfg->num_softap);
			return 0;
		}

		/* First BSS doesn't get a full reset */
		if (ifp->bsscfgidx == 0)
			brcmf_fil_iovar_int_set(ifp, "closednet", 0);

		err = brcmf_fil_iovar_int_get(ifp, "apsta", &apsta);
		if (err < 0)
			brcmf_err("wl apsta failed (%d)\n", err);

		if (!apsta) {
			err = brcmf_fil_cmd_int_set(ifp, BRCMF_C_DOWN, 1);
			if (err < 0)
				bphy_err(drvr, "BRCMF_C_DOWN error %d\n", err);
			err = brcmf_fil_cmd_int_set(ifp, BRCMF_C_SET_AP, 0);
			if (err < 0)
				bphy_err(drvr, "Set AP mode error %d\n", err);
		}
		if (brcmf_feat_is_enabled(ifp, BRCMF_FEAT_MBSS))
			brcmf_fil_iovar_int_set(ifp, "mbss", 0);
		brcmf_fil_cmd_int_set(ifp, BRCMF_C_SET_REGULATORY,
				      ifp->vif->is_11d);
		/* Bring device back up so it can be used again */
		err = brcmf_fil_cmd_int_set(ifp, BRCMF_C_UP, 1);
		if (err < 0)
			bphy_err(drvr, "BRCMF_C_UP error %d\n", err);

		brcmf_vif_clear_mgmt_ies(ifp->vif);
	} else {
		bss_enable.bsscfgidx = cpu_to_le32(ifp->bsscfgidx);
		bss_enable.enable = cpu_to_le32(WL_IOV_OP_BSSCFG_DISABLE);
		err = brcmf_fil_iovar_data_set(ifp, "bss", &bss_enable,
					       sizeof(bss_enable));
		if (err < 0)
			bphy_err(drvr, "bss_enable config failed %d\n", err);
	}
	brcmf_set_mpc(ifp, 1);
	clear_bit(BRCMF_VIF_STATUS_AP_CREATED, &ifp->vif->sme_state);
	brcmf_configure_arp_nd_offload(ifp, true);
	brcmf_net_setcarrier(ifp, false);

	return err;
}

static s32
brcmf_cfg80211_change_beacon(struct wiphy *wiphy, struct net_device *ndev,
			     struct cfg80211_beacon_data *info)
{
	struct brcmf_if *ifp = netdev_priv(ndev);

	brcmf_dbg(TRACE, "Enter\n");

	return brcmf_config_ap_mgmt_ie(ifp->vif, info);
}

static int
brcmf_cfg80211_del_station(struct wiphy *wiphy, struct net_device *ndev,
			   struct station_del_parameters *params)
{
	struct brcmf_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct brcmf_pub *drvr = cfg->pub;
	struct brcmf_scb_val_le scbval;
	struct brcmf_if *ifp = netdev_priv(ndev);
	s32 err;

	if (!params->mac)
		return -EFAULT;

	brcmf_dbg(TRACE, "Enter %pM\n", params->mac);

	if (ifp->vif == cfg->p2p.bss_idx[P2PAPI_BSSCFG_DEVICE].vif)
		ifp = cfg->p2p.bss_idx[P2PAPI_BSSCFG_PRIMARY].vif->ifp;
	if (!check_vif_up(ifp->vif))
		return -EIO;

	memcpy(&scbval.ea, params->mac, ETH_ALEN);
	scbval.val = cpu_to_le32(params->reason_code);
	err = brcmf_fil_cmd_data_set(ifp, BRCMF_C_SCB_DEAUTHENTICATE_FOR_REASON,
				     &scbval, sizeof(scbval));
	if (err)
		bphy_err(drvr, "SCB_DEAUTHENTICATE_FOR_REASON failed %d\n",
			 err);

	brcmf_dbg(TRACE, "Exit\n");
	return err;
}

static int
brcmf_cfg80211_change_station(struct wiphy *wiphy, struct net_device *ndev,
			      const u8 *mac, struct station_parameters *params)
{
	struct brcmf_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct brcmf_pub *drvr = cfg->pub;
	struct brcmf_if *ifp = netdev_priv(ndev);
	s32 err;

	brcmf_dbg(TRACE, "Enter, MAC %pM, mask 0x%04x set 0x%04x\n", mac,
		  params->sta_flags_mask, params->sta_flags_set);

	/* Ignore all 00 MAC */
	if (is_zero_ether_addr(mac))
		return 0;

	if (!(params->sta_flags_mask & BIT(NL80211_STA_FLAG_AUTHORIZED)))
		return 0;

	if (params->sta_flags_set & BIT(NL80211_STA_FLAG_AUTHORIZED))
		err = brcmf_fil_cmd_data_set(ifp, BRCMF_C_SET_SCB_AUTHORIZE,
					     (void *)mac, ETH_ALEN);
	else
		err = brcmf_fil_cmd_data_set(ifp, BRCMF_C_SET_SCB_DEAUTHORIZE,
					     (void *)mac, ETH_ALEN);
	if (err < 0)
		bphy_err(drvr, "Setting SCB (de-)authorize failed, %d\n", err);

	return err;
}

static void
brcmf_cfg80211_update_mgmt_frame_registrations(struct wiphy *wiphy,
					       struct wireless_dev *wdev,
					       struct mgmt_frame_regs *upd)
{
	struct brcmf_cfg80211_vif *vif;

	vif = container_of(wdev, struct brcmf_cfg80211_vif, wdev);

	vif->mgmt_rx_reg = upd->interface_stypes;
}


static int
brcmf_cfg80211_mgmt_tx(struct wiphy *wiphy, struct wireless_dev *wdev,
		       struct cfg80211_mgmt_tx_params *params, u64 *cookie)
{
	struct brcmf_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct ieee80211_channel *chan = params->chan;
	struct brcmf_pub *drvr = cfg->pub;
	const u8 *buf = params->buf;
	size_t len = params->len;
	const struct ieee80211_mgmt *mgmt;
	struct brcmf_cfg80211_vif *vif;
	s32 err = 0;
	s32 ie_offset;
	s32 ie_len;
	struct brcmf_fil_action_frame_le *action_frame;
	struct brcmf_fil_af_params_le *af_params;
	bool ack = false;
	s32 chan_nr;
	u32 freq;
	struct brcmf_mf_params_le *mf_params;
	u32 mf_params_len;
	s32 timeout;
	u32 hw_channel;

	brcmf_dbg(TRACE, "Enter\n");

	*cookie = 0;

	mgmt = (const struct ieee80211_mgmt *)buf;

	if (!ieee80211_is_mgmt(mgmt->frame_control)) {
		bphy_err(drvr, "Driver only allows MGMT packet type\n");
		return -EPERM;
	}

	vif = container_of(wdev, struct brcmf_cfg80211_vif, wdev);

	if (ieee80211_is_probe_resp(mgmt->frame_control)) {
		/* Right now the only reason to get a probe response */
		/* is for p2p listen response or for p2p GO from     */
		/* wpa_supplicant. Unfortunately the probe is send   */
		/* on primary ndev, while dongle wants it on the p2p */
		/* vif. Since this is only reason for a probe        */
		/* response to be sent, the vif is taken from cfg.   */
		/* If ever desired to send proberesp for non p2p     */
		/* response then data should be checked for          */
		/* "DIRECT-". Note in future supplicant will take    */
		/* dedicated p2p wdev to do this and then this 'hack'*/
		/* is not needed anymore.                            */
		ie_offset =  DOT11_MGMT_HDR_LEN +
			     DOT11_BCN_PRB_FIXED_LEN;
		ie_len = len - ie_offset;
		if (vif == cfg->p2p.bss_idx[P2PAPI_BSSCFG_PRIMARY].vif)
			vif = cfg->p2p.bss_idx[P2PAPI_BSSCFG_DEVICE].vif;
		err = brcmf_vif_set_mgmt_ie(vif,
					    BRCMF_VNDR_IE_PRBRSP_FLAG,
					    &buf[ie_offset],
					    ie_len);
		cfg80211_mgmt_tx_status(wdev, *cookie, buf, len, true,
					GFP_KERNEL);
	} else if (ieee80211_is_action(mgmt->frame_control)) {
		if (len > BRCMF_FIL_ACTION_FRAME_SIZE + DOT11_MGMT_HDR_LEN) {
			bphy_err(drvr, "invalid action frame length\n");
			err = -EINVAL;
			goto exit;
		}
		af_params = kzalloc(sizeof(*af_params), GFP_KERNEL);
		if (af_params == NULL) {
			bphy_err(drvr, "unable to allocate frame\n");
			err = -ENOMEM;
			goto exit;
		}
		action_frame = &af_params->action_frame;
		/* Add the packet Id */
		action_frame->packet_id = cpu_to_le32(*cookie);
		/* Add BSSID */
		memcpy(&action_frame->da[0], &mgmt->da[0], ETH_ALEN);
		memcpy(&af_params->bssid[0], &mgmt->bssid[0], ETH_ALEN);
		/* Add the length exepted for 802.11 header  */
		action_frame->len = cpu_to_le16(len - DOT11_MGMT_HDR_LEN);
		/* Add the channel. Use the one specified as parameter if any or
		 * the current one (got from the firmware) otherwise
		 */
		if (chan) {
			freq = chan->center_freq;
			chan_nr = ieee80211_frequency_to_channel(freq);
			af_params->channel = cpu_to_le32(chan_nr);
		} else {
			brcmf_fil_cmd_int_get(vif->ifp, BRCMF_C_GET_CHANNEL,
					      &hw_channel);
			af_params->channel = hw_channel;
		}

		af_params->dwell_time = cpu_to_le32(params->wait);
		memcpy(action_frame->data, &buf[DOT11_MGMT_HDR_LEN],
		       le16_to_cpu(action_frame->len));

		brcmf_dbg(TRACE, "Action frame, cookie=%lld, len=%d, ch=%d\n",
			  *cookie, le16_to_cpu(action_frame->len), af_params->channel);

		ack = brcmf_p2p_send_action_frame(cfg, cfg_to_ndev(cfg),
						  af_params, vif, chan);

		cfg80211_mgmt_tx_status(wdev, *cookie, buf, len, ack,
					GFP_KERNEL);
		kfree(af_params);
	} else if (ieee80211_is_auth(mgmt->frame_control)) {
		reinit_completion(&vif->mgmt_tx);
		clear_bit(BRCMF_MGMT_TX_ACK, &vif->mgmt_tx_status);
		clear_bit(BRCMF_MGMT_TX_NOACK, &vif->mgmt_tx_status);
		clear_bit(BRCMF_MGMT_TX_OFF_CHAN_COMPLETED,
			  &vif->mgmt_tx_status);

		mf_params_len = offsetof(struct brcmf_mf_params_le, data) +
				(len - DOT11_MGMT_HDR_LEN);
		mf_params = kzalloc(mf_params_len, GFP_KERNEL);
		if (!mf_params) {
			err = -ENOMEM;
			goto exit;
		}

		mf_params->dwell_time = cpu_to_le32(MGMT_AUTH_FRAME_DWELL_TIME);
		mf_params->len = cpu_to_le16(len - DOT11_MGMT_HDR_LEN);
		mf_params->frame_control = mgmt->frame_control;

		if (chan) {
			freq = chan->center_freq;
			chan_nr = ieee80211_frequency_to_channel(freq);
			mf_params->channel = cpu_to_le32(chan_nr);
		} else {
			brcmf_fil_cmd_int_get(vif->ifp, BRCMF_C_GET_CHANNEL,
					      &hw_channel);
			mf_params->channel = hw_channel;
		}

		memcpy(&mf_params->da[0], &mgmt->da[0], ETH_ALEN);
		memcpy(&mf_params->bssid[0], &mgmt->bssid[0], ETH_ALEN);
		*cookie = (u64)mf_params->data;
		mf_params->packet_id = cpu_to_le32(*cookie);
		memcpy(mf_params->data, &buf[DOT11_MGMT_HDR_LEN],
		       le16_to_cpu(mf_params->len));

		brcmf_dbg(TRACE, "Auth frame, cookie=%d, fc=%04x, len=%d, channel=%d\n",
			  le32_to_cpu(mf_params->packet_id),
			  le16_to_cpu(mf_params->frame_control),
			  le16_to_cpu(mf_params->len),
			  le32_to_cpu(mf_params->channel));

		vif->mgmt_tx_id = le32_to_cpu(mf_params->packet_id);
		set_bit(BRCMF_MGMT_TX_SEND_FRAME, &vif->mgmt_tx_status);

		err = brcmf_fil_bsscfg_data_set(vif->ifp, "mgmt_frame",
						mf_params, mf_params_len);
		if (err) {
			bphy_err(drvr, "Failed to send Auth frame: err=%d\n",
				 err);
			goto tx_status;
		}

		timeout =
			wait_for_completion_timeout(&vif->mgmt_tx,
						    MGMT_AUTH_FRAME_WAIT_TIME);
		if (test_bit(BRCMF_MGMT_TX_ACK, &vif->mgmt_tx_status)) {
			brcmf_dbg(TRACE, "TX Auth frame operation is success\n");
			ack = true;
		} else {
			bphy_err(drvr, "TX Auth frame operation is failed: status=%ld)\n",
				 vif->mgmt_tx_status);
		}

tx_status:
		cfg80211_mgmt_tx_status(wdev, *cookie, buf, len, ack,
					GFP_KERNEL);
		kfree(mf_params);

	} else {
		brcmf_dbg(TRACE, "Unhandled, fc=%04x!!\n", mgmt->frame_control);
		brcmf_dbg_hex_dump(true, buf, len, "payload, len=%zu\n", len);
	}

exit:
	return err;
}

static int brcmf_cfg80211_set_cqm_rssi_range_config(struct wiphy *wiphy,
						    struct net_device *ndev,
						    s32 rssi_low, s32 rssi_high)
{
	struct brcmf_cfg80211_vif *vif;
	struct brcmf_if *ifp;
	int err = 0;

	brcmf_dbg(TRACE, "low=%d high=%d", rssi_low, rssi_high);

	ifp = netdev_priv(ndev);
	vif = ifp->vif;

	if (rssi_low != vif->cqm_rssi_low || rssi_high != vif->cqm_rssi_high) {
		/* The firmware will send an event when the RSSI is less than or
		 * equal to a configured level and the previous RSSI event was
		 * less than or equal to a different level. Set a third level
		 * so that we also detect the transition from rssi <= rssi_high
		 * to rssi > rssi_high.
		 */
		struct brcmf_rssi_event_le config = {
			.rate_limit_msec = cpu_to_le32(0),
			.rssi_level_num = 3,
			.rssi_levels = {
				clamp_val(rssi_low, S8_MIN, S8_MAX - 2),
				clamp_val(rssi_high, S8_MIN + 1, S8_MAX - 1),
				S8_MAX,
			},
		};

		err = brcmf_fil_iovar_data_set(ifp, "rssi_event", &config,
					       sizeof(config));
		if (err) {
			err = -EINVAL;
		} else {
			vif->cqm_rssi_low = rssi_low;
			vif->cqm_rssi_high = rssi_high;
		}
	}

	return err;
}

static int
brcmf_cfg80211_cancel_remain_on_channel(struct wiphy *wiphy,
					struct wireless_dev *wdev,
					u64 cookie)
{
	struct brcmf_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct brcmf_pub *drvr = cfg->pub;
	struct brcmf_cfg80211_vif *vif;
	int err = 0;

	brcmf_dbg(TRACE, "Enter p2p listen cancel\n");

	vif = cfg->p2p.bss_idx[P2PAPI_BSSCFG_DEVICE].vif;
	if (vif == NULL) {
		bphy_err(drvr, "No p2p device available for probe response\n");
		err = -ENODEV;
		goto exit;
	}
	brcmf_p2p_cancel_remain_on_channel(vif->ifp);
exit:
	return err;
}

static int brcmf_cfg80211_get_channel(struct wiphy *wiphy,
				      struct wireless_dev *wdev,
				      unsigned int link_id,
				      struct cfg80211_chan_def *chandef)
{
	struct brcmf_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct brcmf_cfg80211_vif *vif = wdev_to_vif(wdev);
	struct net_device *ndev = wdev->netdev;
	struct brcmf_pub *drvr = cfg->pub;
	struct brcmu_chan ch;
	enum nl80211_band band = 0;
	enum nl80211_chan_width width = 0;
	u32 chanspec;
	int freq, err;

	if (!ndev || drvr->bus_if->state != BRCMF_BUS_UP)
		return -ENODEV;
	if (!check_vif_up(vif))
		return -EIO;
	err = brcmf_fil_iovar_int_get(netdev_priv(ndev), "chanspec", &chanspec);
	if (err) {
		bphy_err(drvr, "chanspec failed (%d)\n", err);
		return err;
	}

	ch.chspec = chanspec;
	cfg->d11inf.decchspec(&ch);
	band = BRCMU_CHAN_BAND_TO_NL80211(ch.band);

	switch (ch.bw) {
	case BRCMU_CHAN_BW_80:
		width = NL80211_CHAN_WIDTH_80;
		break;
	case BRCMU_CHAN_BW_40:
		width = NL80211_CHAN_WIDTH_40;
		break;
	case BRCMU_CHAN_BW_20:
		width = NL80211_CHAN_WIDTH_20;
		break;
	case BRCMU_CHAN_BW_80P80:
		width = NL80211_CHAN_WIDTH_80P80;
		break;
	case BRCMU_CHAN_BW_160:
		width = NL80211_CHAN_WIDTH_160;
		break;
	}

	freq = ieee80211_channel_to_frequency(ch.control_ch_num, band);
	if (!freq)
		return -EINVAL;
	chandef->chan = ieee80211_get_channel(wiphy, freq);
	if (!chandef->chan)
		return -EINVAL;
	chandef->width = width;
	chandef->center_freq1 = ieee80211_channel_to_frequency(ch.chnum, band);
	chandef->center_freq2 = 0;

	return 0;
}

static s32
brcmf_notify_csa_completion_ind(struct brcmf_if *ifp,
				const struct brcmf_event_msg *e, void *data)
{
	struct brcmf_cfg80211_info *cfg;
	struct net_device *ndev;
	struct wiphy *wiphy;
	struct cfg80211_chan_def chandef;
	struct wireless_dev *wdev;

	int error = 0;

	brcmf_dbg(TRACE, "Enter\n");

	if (unlikely(e->status)) {
		brcmf_err("status:0x%x\n", e->status);
		return -EINVAL;
	}

	if (!ifp)
		return -EINVAL;
	else if (!ifp->drvr)
		return -EINVAL;

	cfg = ifp->drvr->config;
	ndev = ifp->ndev;
	wiphy = cfg_to_wiphy(cfg);

	if (!cfg || !ndev || !wiphy)
		return -EINVAL;

	wdev = ndev->ieee80211_ptr;
	if (!wdev)
		return -EINVAL;

	if (!wdev->u.ibss.current_bss) {
		brcmf_err("Got csa_completion event while no connection\n");
		return -EINVAL;
	}

	memset(&chandef, 0, sizeof(chandef));
	/* Reuse cfg80211 call to get chandef */
	error = brcmf_cfg80211_get_channel(wiphy, wdev, 0, &chandef);
	if (unlikely(error)) {
		brcmf_err("Get chandef error: %d \n", error);
		return -EINVAL;
	}

	/* Send channel switch notification only for STA mode */
	if (wdev->iftype == NL80211_IFTYPE_STATION) {
		cfg80211_ch_switch_notify(ndev, &chandef, 0);
		brcmf_dbg(TRACE, "CSA sent upstream\n");
	}

	return 0;
}

static int brcmf_cfg80211_crit_proto_start(struct wiphy *wiphy,
					   struct wireless_dev *wdev,
					   enum nl80211_crit_proto_id proto,
					   u16 duration)
{
	struct brcmf_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct brcmf_cfg80211_vif *vif;

	vif = container_of(wdev, struct brcmf_cfg80211_vif, wdev);

	/* only DHCP support for now */
	if (proto != NL80211_CRIT_PROTO_DHCP)
		return -EINVAL;

	/* suppress and abort scanning */
	set_bit(BRCMF_SCAN_STATUS_SUPPRESS, &cfg->scan_status);
	brcmf_abort_scanning(cfg);

	return brcmf_btcoex_set_mode(vif, BRCMF_BTCOEX_DISABLED, duration);
}

static void brcmf_cfg80211_crit_proto_stop(struct wiphy *wiphy,
					   struct wireless_dev *wdev)
{
	struct brcmf_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct brcmf_cfg80211_vif *vif;

	vif = container_of(wdev, struct brcmf_cfg80211_vif, wdev);

	brcmf_btcoex_set_mode(vif, BRCMF_BTCOEX_ENABLED, 0);
	clear_bit(BRCMF_SCAN_STATUS_SUPPRESS, &cfg->scan_status);
}

static s32
brcmf_notify_tdls_peer_event(struct brcmf_if *ifp,
			     const struct brcmf_event_msg *e, void *data)
{
	switch (e->reason) {
	case BRCMF_E_REASON_TDLS_PEER_DISCOVERED:
		brcmf_dbg(TRACE, "TDLS Peer Discovered\n");
		break;
	case BRCMF_E_REASON_TDLS_PEER_CONNECTED:
		brcmf_dbg(TRACE, "TDLS Peer Connected\n");
		brcmf_proto_add_tdls_peer(ifp->drvr, ifp->ifidx, (u8 *)e->addr);
		break;
	case BRCMF_E_REASON_TDLS_PEER_DISCONNECTED:
		brcmf_dbg(TRACE, "TDLS Peer Disconnected\n");
		brcmf_proto_delete_peer(ifp->drvr, ifp->ifidx, (u8 *)e->addr);
		break;
	}

	return 0;
}

static int brcmf_convert_nl80211_tdls_oper(enum nl80211_tdls_operation oper)
{
	int ret;

	switch (oper) {
	case NL80211_TDLS_DISCOVERY_REQ:
		ret = BRCMF_TDLS_MANUAL_EP_DISCOVERY;
		break;
	case NL80211_TDLS_SETUP:
		ret = BRCMF_TDLS_MANUAL_EP_CREATE;
		break;
	case NL80211_TDLS_TEARDOWN:
		ret = BRCMF_TDLS_MANUAL_EP_DELETE;
		break;
	default:
		brcmf_err("unsupported operation: %d\n", oper);
		ret = -EOPNOTSUPP;
	}
	return ret;
}

static int brcmf_cfg80211_tdls_oper(struct wiphy *wiphy,
				    struct net_device *ndev, const u8 *peer,
				    enum nl80211_tdls_operation oper)
{
	struct brcmf_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct brcmf_pub *drvr = cfg->pub;
	struct brcmf_if *ifp;
	struct brcmf_tdls_iovar_le info;
	int ret = 0;

	ret = brcmf_convert_nl80211_tdls_oper(oper);
	if (ret < 0)
		return ret;

	ifp = netdev_priv(ndev);
	memset(&info, 0, sizeof(info));
	info.mode = (u8)ret;
	if (peer)
		memcpy(info.ea, peer, ETH_ALEN);

	ret = brcmf_fil_iovar_data_set(ifp, "tdls_endpoint",
				       &info, sizeof(info));
	if (ret < 0)
		bphy_err(drvr, "tdls_endpoint iovar failed: ret=%d\n", ret);

	return ret;
}

static int
brcmf_cfg80211_update_conn_params(struct wiphy *wiphy,
				  struct net_device *ndev,
				  struct cfg80211_connect_params *sme,
				  u32 changed)
{
	struct brcmf_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct brcmf_pub *drvr = cfg->pub;
	struct brcmf_if *ifp;
	int err;

	if (!(changed & UPDATE_ASSOC_IES))
		return 0;

	ifp = netdev_priv(ndev);
	err = brcmf_vif_set_mgmt_ie(ifp->vif, BRCMF_VNDR_IE_ASSOCREQ_FLAG,
				    sme->ie, sme->ie_len);
	if (err)
		bphy_err(drvr, "Set Assoc REQ IE Failed\n");
	else
		brcmf_dbg(TRACE, "Applied Vndr IEs for Assoc request\n");

	return err;
}

#ifdef CONFIG_PM
static int
brcmf_cfg80211_set_rekey_data(struct wiphy *wiphy, struct net_device *ndev,
			      struct cfg80211_gtk_rekey_data *gtk)
{
	struct brcmf_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct brcmf_pub *drvr = cfg->pub;
	struct brcmf_if *ifp = netdev_priv(ndev);
	struct brcmf_gtk_keyinfo_le gtk_le;
	int ret;

	brcmf_dbg(TRACE, "Enter, bssidx=%d\n", ifp->bsscfgidx);

	memcpy(gtk_le.kck, gtk->kck, sizeof(gtk_le.kck));
	memcpy(gtk_le.kek, gtk->kek, sizeof(gtk_le.kek));
	memcpy(gtk_le.replay_counter, gtk->replay_ctr,
	       sizeof(gtk_le.replay_counter));

	ret = brcmf_fil_iovar_data_set(ifp, "gtk_key_info", &gtk_le,
				       sizeof(gtk_le));
	if (ret < 0)
		bphy_err(drvr, "gtk_key_info iovar failed: ret=%d\n", ret);

	return ret;
}
#endif

static int brcmf_cfg80211_set_pmk(struct wiphy *wiphy, struct net_device *dev,
				  const struct cfg80211_pmk_conf *conf)
{
	struct brcmf_if *ifp;
	struct brcmf_pub *drvr;
	int ret;

	brcmf_dbg(TRACE, "enter\n");

	/* expect using firmware supplicant for 1X */
	ifp = netdev_priv(dev);
	drvr = ifp->drvr;
	if (WARN_ON((ifp->vif->profile.use_fwsup != BRCMF_PROFILE_FWSUP_1X) &&
			(ifp->vif->profile.use_fwsup != BRCMF_PROFILE_FWSUP_ROAM) &&
			(ifp->vif->profile.is_ft != true) &&
			(ifp->vif->profile.is_okc != true)))
		return -EINVAL;

	if (conf->pmk_len > BRCMF_WSEC_MAX_PMK_LEN)
		return -ERANGE;

	if (ifp->vif->profile.is_okc) {
		ret = brcmf_fil_iovar_data_set(ifp, "okc_info_pmk", conf->pmk,
					       conf->pmk_len);
		if (ret < 0)
			bphy_err(drvr, "okc_info_pmk iovar failed: ret=%d\n", ret);
	}

	return brcmf_set_pmk(ifp, conf->pmk, conf->pmk_len);
}

static int brcmf_cfg80211_del_pmk(struct wiphy *wiphy, struct net_device *dev,
				  const u8 *aa)
{
	struct brcmf_if *ifp;

	brcmf_dbg(TRACE, "enter\n");
	ifp = netdev_priv(dev);
	if (WARN_ON(ifp->vif->profile.use_fwsup != BRCMF_PROFILE_FWSUP_1X))
		return -EINVAL;

	return brcmf_set_pmk(ifp, NULL, 0);
}

static int
brcmf_cfg80211_change_bss(struct wiphy *wiphy, struct net_device *dev,
			  struct bss_parameters *params)
{
	struct brcmf_if *ifp;
	int ret = 0;
	u32 ap_isolate, val;

	brcmf_dbg(TRACE, "Enter\n");
	ifp = netdev_priv(dev);
	if (params->ap_isolate >= 0) {
		ap_isolate = (u32)params->ap_isolate;
		ret = brcmf_fil_iovar_int_set(ifp, "ap_isolate", ap_isolate);
		if (ret < 0)
			brcmf_err("ap_isolate iovar failed: ret=%d\n", ret);
	}

	/* Get ap_isolate value from firmware to detemine whether fmac */
	/* driver supports packet forwarding. */
	if (brcmf_fil_iovar_int_get(ifp, "ap_isolate", &val) == 0) {
		ifp->fmac_pkt_fwd_en =
			((params->ap_isolate == 0) && (val == 1)) ?
			true : false;
	} else {
		brcmf_err("get ap_isolate iovar failed: ret=%d\n", ret);
		ifp->fmac_pkt_fwd_en = false;
	}

	return ret;
}

static int
brcmf_cfg80211_external_auth(struct wiphy *wiphy, struct net_device *dev,
			     struct cfg80211_external_auth_params *params)
{
	struct brcmf_if *ifp;
	struct brcmf_pub *drvr;
	struct brcmf_auth_req_status_le auth_status;
	int ret = 0;
	struct brcmf_cfg80211_info *cfg = wiphy_to_cfg(wiphy);

	brcmf_dbg(TRACE, "Enter\n");

	ifp = netdev_priv(dev);
	drvr = ifp->drvr;
	if (params->status == WLAN_STATUS_SUCCESS) {
		auth_status.flags = cpu_to_le16(BRCMF_EXTAUTH_SUCCESS);
	} else {
		bphy_err(drvr, "External authentication failed: status=%d\n",
			 params->status);
		auth_status.flags = cpu_to_le16(BRCMF_EXTAUTH_FAIL);
	}

	memcpy(auth_status.peer_mac, params->bssid, ETH_ALEN);
	auth_status.ssid_len = cpu_to_le32(min_t(u8, params->ssid.ssid_len,
						 IEEE80211_MAX_SSID_LEN));
	memcpy(auth_status.ssid, params->ssid.ssid, auth_status.ssid_len);
	memset(auth_status.pmkid, 0, WLAN_PMKID_LEN);
	if (params->pmkid)
		memcpy(auth_status.pmkid, params->pmkid, WLAN_PMKID_LEN);

	ret = brcmf_fil_iovar_data_set(ifp, "auth_status", &auth_status,
				       sizeof(auth_status));
	if (ret < 0)
		bphy_err(drvr, "auth_status iovar failed: ret=%d\n", ret);

	if (params->pmkid) {
		ret = brcmf_update_pmksa(cfg,
					 ifp,
					 params->bssid,
					 params->pmkid,
					 PMKSA_SET);
		if (ret < 0) {
			bphy_err(drvr,
				 "PMKSA_SET brcmf_update_pmksa failed: ret=%d\n",
				 ret);
		}
	}

	return ret;
}

static int
brcmf_cfg80211_set_bitrate(struct wiphy *wiphy, struct net_device *ndev,
			   unsigned int link_id, const u8 *addr,
			   const struct cfg80211_bitrate_mask *mask)
{
	struct brcmf_if *ifp;
	u32 he[2] = {0, 0};
	u32 rspec = 0;
	s32 ret = TIME_OK;
	uint hegi;
	u16 mcs_mask;
	u8 band, mcs = 0;

	ifp = netdev_priv(ndev);
	ret = brcmf_fil_iovar_data_get(ifp, "he", he, sizeof(he));
	if (unlikely(ret)) {
		brcmf_dbg(INFO, "error reading he (%d)\n", ret);
		return -EOPNOTSUPP;
	}

	if (!he[0]) {
		brcmf_dbg(INFO, "Only HE supported\n");
		return -EOPNOTSUPP;
	}

	for (band = 0; band < NUM_NL80211_BANDS; band++) {
		if (band != NL80211_BAND_2GHZ && band != NL80211_BAND_5GHZ &&
		    band != NL80211_BAND_6GHZ) {
			continue;
		}

		/* Skip setting HE rates if legacy rate set is called from userspace.
		 * Also if any one of 2.4, 5 or 6GHz is being called then other two will have
		 * an invalid he mask of 0xFFF so skip setting he rates for other two bands.
		 */
		if (!mask->control[band].he_mcs[0] || mask->control[band].he_mcs[0] == 0xFFF)
			continue;

		mcs_mask = mask->control[band].he_mcs[0];
		mcs_mask = (mcs_mask ^ ((mcs_mask - 1) & mcs_mask));
		if (mcs_mask != mask->control[band].he_mcs[0])
			continue;

		while (mcs_mask) {
			mcs++;
			mcs_mask >>= 1;
		}

		rspec = WL_RSPEC_ENCODE_HE;     /* 11ax HE */
		rspec |= (WL_RSPEC_HE_NSS_UNSPECIFIED << WL_RSPEC_HE_NSS_SHIFT) | (mcs - 1);
		/* set the other rspec fields */
		hegi = mask->control[band].he_gi + 1;
		rspec |= ((hegi != 0xFF) ? HE_GI_TO_RSPEC(hegi) : 0);

		if (band == NL80211_BAND_2GHZ)
			ret = brcmf_fil_iovar_data_set(ifp, "2g_rate", (char *)&rspec, 4);

		if (band == NL80211_BAND_5GHZ)
			ret = brcmf_fil_iovar_data_set(ifp, "5g_rate", (char *)&rspec, 4);

		if (band == NL80211_BAND_6GHZ)
			ret = brcmf_fil_iovar_data_set(ifp, "6g_rate", (char *)&rspec, 4);

		if (unlikely(ret)) {
			brcmf_dbg(INFO, "%s: set rate failed, retcode = %d\n",
				  __func__, ret);
			return ret;
		}
	}
	return ret;
}

static int
brcmf_cfg80211_set_cqm_rssi_config(struct wiphy *wiphy, struct net_device *dev,
				   s32 rssi_thold, u32 rssi_hyst)
{
	struct brcmf_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct brcmf_if *ifp;
	struct wl_rssi_event rssi;
	int err = 0;

	ifp = netdev_priv(dev);
	if (rssi_thold == cfg->cqm_info.rssi_threshold)
		return err;

	if (rssi_thold == 0) {
		rssi.rate_limit_msec = cpu_to_le32(0);
		rssi.num_rssi_levels = 0;
		rssi.version = WL_RSSI_EVENT_IFX_VERSION;
	} else {
		rssi.rate_limit_msec = cpu_to_le32(0);
		rssi.num_rssi_levels = 3;
		rssi.rssi_levels[0] = S8_MIN;
		rssi.rssi_levels[1] = rssi_thold;
		rssi.rssi_levels[2] = S8_MAX;
		rssi.version = WL_RSSI_EVENT_IFX_VERSION;
	}

	err = brcmf_fil_iovar_data_set(ifp, "rssi_event", &rssi, sizeof(rssi));
	if (err < 0) {
		brcmf_err("set rssi_event iovar failed (%d)\n", err);
	} else {
		cfg->cqm_info.enable = rssi_thold ? 1 : 0;
		cfg->cqm_info.rssi_threshold = rssi_thold;
	}

	brcmf_dbg(TRACE, "enable = %d, rssi_threshold = %d\n",
		cfg->cqm_info.enable, cfg->cqm_info.rssi_threshold);
	return err;
}

int brcmf_cfg80211_update_owe_info(struct wiphy *wiphy, struct net_device *dev,
				   struct cfg80211_update_owe_info *owe_info)
{
	struct brcmf_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct brcmf_if *ifp;
	int err = 0;
	struct brcmf_owe_info_buf *owe_info_buf;
	u8  *curr_ie_buf;
	struct parsed_extension_ies owe_ecdh_ie;
	struct parsed_ext_ie_info *extie_info;
	u32 del_add_ie_buf_len = 0;
	u32 total_owe_info_len = 0;
	u32 pmkid_offset = 0;
	struct brcmf_pub *drvr;

	ifp = netdev_priv(dev);
	if (owe_info) {
		owe_info_buf = kzalloc(WL_EXTRA_BUF_MAX, GFP_KERNEL);
		if (!owe_info_buf)
			return -ENOMEM;

		curr_ie_buf = owe_info_buf->ecdh_ie_info;

		memcpy(owe_info_buf->peer_mac, owe_info->peer, ETH_ALEN);
		owe_info_buf->status_le16 = cpu_to_le16(owe_info->status);

		owe_info_buf->with_ecdh = false;
		if (owe_info->ie) {
			drvr = ifp->drvr;
			if (brcmf_has_pmkid(owe_info->ie,
					    owe_info->ie_len,
					    &pmkid_offset)) {
				err = brcmf_update_pmksa(cfg,
							 ifp,
							 owe_info_buf->peer_mac,
							 owe_info->ie + pmkid_offset,
							 PMKSA_SET);
				if (err < 0) {
					bphy_err(drvr,
						 "PMKSA_SET brcmf_update_pmksa failed: ret=%d\n",
						 err);
					return err;
				}

				owe_info_buf->with_pmkid = true;
				memcpy(owe_info_buf->pmkid,
				       owe_info->ie + pmkid_offset,
				       WLAN_PMKID_LEN);
			}

			brcmf_parse_extension_ies(owe_info->ie, owe_info->ie_len, &owe_ecdh_ie);
			if (owe_ecdh_ie.count > 1) {
				brcmf_err("more ecdh_cnt found in info: %d\n", owe_ecdh_ie.count);
				return -EINVAL;
			}

			if (owe_ecdh_ie.count == 1) {
				owe_info_buf->with_ecdh = true;
				extie_info = &owe_ecdh_ie.ie_info[0];

				del_add_ie_buf_len = brcmf_vndr_ie(curr_ie_buf,
								   BRCMF_VNDR_IE_ASSOCRSP_FLAG |
								   BRCMF_VNDR_IE_CUSTOM_FLAG,
								   extie_info->ie_ptr,
								   extie_info->ie_len,
								   "add");
			}
		}

		total_owe_info_len = sizeof(struct brcmf_owe_info_buf) + del_add_ie_buf_len;
		err = brcmf_fil_bsscfg_data_set(ifp, "owe_info", owe_info_buf,
						total_owe_info_len);

		kfree(owe_info_buf);
	}

	if (err)
		brcmf_err("update owe_info error :%d\n", err);

	return err;
}

static struct cfg80211_ops brcmf_cfg80211_ops = {
	.add_virtual_intf = brcmf_cfg80211_add_iface,
	.del_virtual_intf = brcmf_cfg80211_del_iface,
	.change_virtual_intf = brcmf_cfg80211_change_iface,
	.scan = brcmf_cfg80211_scan,
	.set_wiphy_params = brcmf_cfg80211_set_wiphy_params,
	.join_ibss = brcmf_cfg80211_join_ibss,
	.leave_ibss = brcmf_cfg80211_leave_ibss,
	.get_station = brcmf_cfg80211_get_station,
	.dump_station = brcmf_cfg80211_dump_station,
	.set_tx_power = brcmf_cfg80211_set_tx_power,
	.get_tx_power = brcmf_cfg80211_get_tx_power,
	.add_key = brcmf_cfg80211_add_key,
	.del_key = brcmf_cfg80211_del_key,
	.get_key = brcmf_cfg80211_get_key,
	.set_default_key = brcmf_cfg80211_config_default_key,
	.set_default_mgmt_key = brcmf_cfg80211_config_default_mgmt_key,
	.set_power_mgmt = brcmf_cfg80211_set_power_mgmt,
	.connect = brcmf_cfg80211_connect,
	.disconnect = brcmf_cfg80211_disconnect,
	.suspend = brcmf_cfg80211_suspend,
	.resume = brcmf_cfg80211_resume,
	.set_pmksa = brcmf_cfg80211_set_pmksa,
	.del_pmksa = brcmf_cfg80211_del_pmksa,
	.flush_pmksa = brcmf_cfg80211_flush_pmksa,
	.start_ap = brcmf_cfg80211_start_ap,
	.stop_ap = brcmf_cfg80211_stop_ap,
	.change_beacon = brcmf_cfg80211_change_beacon,
	.set_bitrate_mask = brcmf_cfg80211_set_bitrate,
	.del_station = brcmf_cfg80211_del_station,
	.change_station = brcmf_cfg80211_change_station,
	.sched_scan_start = brcmf_cfg80211_sched_scan_start,
	.sched_scan_stop = brcmf_cfg80211_sched_scan_stop,
	.update_mgmt_frame_registrations =
		brcmf_cfg80211_update_mgmt_frame_registrations,
	.mgmt_tx = brcmf_cfg80211_mgmt_tx,
	.set_cqm_rssi_range_config = brcmf_cfg80211_set_cqm_rssi_range_config,
	.remain_on_channel = brcmf_p2p_remain_on_channel,
	.cancel_remain_on_channel = brcmf_cfg80211_cancel_remain_on_channel,
	.get_channel = brcmf_cfg80211_get_channel,
	.start_p2p_device = brcmf_p2p_start_device,
	.stop_p2p_device = brcmf_p2p_stop_device,
	.crit_proto_start = brcmf_cfg80211_crit_proto_start,
	.crit_proto_stop = brcmf_cfg80211_crit_proto_stop,
	.tdls_oper = brcmf_cfg80211_tdls_oper,
	.update_connect_params = brcmf_cfg80211_update_conn_params,
	.set_pmk = brcmf_cfg80211_set_pmk,
	.del_pmk = brcmf_cfg80211_del_pmk,
	.change_bss = brcmf_cfg80211_change_bss,
	.external_auth = brcmf_cfg80211_external_auth,
	.set_cqm_rssi_config = brcmf_cfg80211_set_cqm_rssi_config,
	.update_owe_info = brcmf_cfg80211_update_owe_info,
};

struct cfg80211_ops *brcmf_cfg80211_get_ops(struct brcmf_mp_device *settings)
{
	struct cfg80211_ops *ops;

	ops = kmemdup(&brcmf_cfg80211_ops, sizeof(brcmf_cfg80211_ops),
		       GFP_KERNEL);

	if (ops && settings->roamoff)
		ops->update_connect_params = NULL;

	return ops;
}

struct brcmf_cfg80211_vif *brcmf_alloc_vif(struct brcmf_cfg80211_info *cfg,
					   enum nl80211_iftype type)
{
	struct brcmf_cfg80211_vif *vif;

	brcmf_dbg(TRACE, "allocating virtual interface (size=%zu)\n",
		  sizeof(*vif));
	vif = kzalloc(sizeof(*vif), GFP_KERNEL);
	if (!vif)
		return ERR_PTR(-ENOMEM);

	vif->wdev.wiphy = cfg->wiphy;
	vif->wdev.iftype = type;

	brcmf_init_prof(&vif->profile);
	init_completion(&vif->mgmt_tx);
	list_add_tail(&vif->list, &cfg->vif_list);
	return vif;
}

void brcmf_free_vif(struct brcmf_cfg80211_vif *vif)
{
	list_del(&vif->list);
	kfree(vif);
}

void brcmf_cfg80211_free_netdev(struct net_device *ndev)
{
	struct brcmf_cfg80211_vif *vif;
	struct brcmf_if *ifp;

	ifp = netdev_priv(ndev);
	vif = ifp->vif;

	if (vif) {
		brcmf_free_vif(vif);
		ifp->vif = NULL;
	}
}

static bool brcmf_is_linkup(struct brcmf_cfg80211_vif *vif,
			    const struct brcmf_event_msg *e)
{
	u32 event = e->event_code;
	u32 status = e->status;

	if ((vif->profile.use_fwsup == BRCMF_PROFILE_FWSUP_PSK ||
	     vif->profile.use_fwsup == BRCMF_PROFILE_FWSUP_SAE) &&
	    event == BRCMF_E_PSK_SUP &&
	    status == BRCMF_E_STATUS_FWSUP_COMPLETED)
		set_bit(BRCMF_VIF_STATUS_EAP_SUCCESS, &vif->sme_state);
	if (event == BRCMF_E_LINK && status == BRCMF_E_STATUS_SUCCESS &&
	    (e->flags & BRCMF_EVENT_MSG_LINK)) {
		brcmf_dbg(CONN, "Processing set ssid\n");
		memcpy(vif->profile.bssid, e->addr, ETH_ALEN);
		if (vif->profile.use_fwsup != BRCMF_PROFILE_FWSUP_PSK &&
		    vif->profile.use_fwsup != BRCMF_PROFILE_FWSUP_SAE)
			return true;

		set_bit(BRCMF_VIF_STATUS_ASSOC_SUCCESS, &vif->sme_state);
	}

	if (test_bit(BRCMF_VIF_STATUS_EAP_SUCCESS, &vif->sme_state) &&
	    test_bit(BRCMF_VIF_STATUS_ASSOC_SUCCESS, &vif->sme_state)) {
		clear_bit(BRCMF_VIF_STATUS_EAP_SUCCESS, &vif->sme_state);
		clear_bit(BRCMF_VIF_STATUS_ASSOC_SUCCESS, &vif->sme_state);
		return true;
	}
	return false;
}

static bool brcmf_is_linkdown(struct brcmf_cfg80211_vif *vif,
			    const struct brcmf_event_msg *e)
{
	u32 event = e->event_code;
	u16 flags = e->flags;
	u32 status = e->status;

	if ((event == BRCMF_E_DEAUTH) || (event == BRCMF_E_DEAUTH_IND) ||
	    (event == BRCMF_E_DISASSOC_IND) ||
	    ((event == BRCMF_E_LINK) && (!(flags & BRCMF_EVENT_MSG_LINK))) ||
	    (event == BRCMF_E_SET_SSID && status != BRCMF_E_STATUS_SUCCESS)) {
		brcmf_dbg(CONN, "Processing link down\n");
		clear_bit(BRCMF_VIF_STATUS_EAP_SUCCESS, &vif->sme_state);
		clear_bit(BRCMF_VIF_STATUS_ASSOC_SUCCESS, &vif->sme_state);
		return true;
	}
	return false;
}

static bool brcmf_is_nonetwork(struct brcmf_cfg80211_info *cfg,
			       const struct brcmf_event_msg *e)
{
	u32 event = e->event_code;
	u32 status = e->status;

	if (event == BRCMF_E_LINK && status == BRCMF_E_STATUS_NO_NETWORKS) {
		brcmf_dbg(CONN, "Processing Link %s & no network found\n",
			  e->flags & BRCMF_EVENT_MSG_LINK ? "up" : "down");
		return true;
	}

	if (event == BRCMF_E_SET_SSID && status != BRCMF_E_STATUS_SUCCESS) {
		brcmf_dbg(CONN, "Processing connecting & no network found\n");
		return true;
	}

	if (event == BRCMF_E_PSK_SUP &&
	    status != BRCMF_E_STATUS_FWSUP_COMPLETED) {
		brcmf_dbg(CONN, "Processing failed supplicant state: %u\n",
			  status);
		return true;
	}

	return false;
}

static void brcmf_clear_assoc_ies(struct brcmf_cfg80211_info *cfg)
{
	struct brcmf_cfg80211_connect_info *conn_info = cfg_to_conn(cfg);

	kfree(conn_info->req_ie);
	conn_info->req_ie = NULL;
	conn_info->req_ie_len = 0;
	kfree(conn_info->resp_ie);
	conn_info->resp_ie = NULL;
	conn_info->resp_ie_len = 0;
}

static void brcmf_clear_assoc_req_ie(struct brcmf_cfg80211_info *cfg)
{
	struct brcmf_cfg80211_connect_info *conn_info = cfg_to_conn(cfg);

	kfree(conn_info->req_ie);
	conn_info->req_ie = NULL;
	conn_info->req_ie_len = 0;
}

static void brcmf_clear_assoc_resp_ie(struct brcmf_cfg80211_info *cfg)
{
	struct brcmf_cfg80211_connect_info *conn_info = cfg_to_conn(cfg);

	kfree(conn_info->resp_ie);
	conn_info->resp_ie = NULL;
	conn_info->resp_ie_len = 0;
}

u8 brcmf_map_prio_to_prec(void *config, u8 prio)
{
	struct brcmf_cfg80211_info *cfg = (struct brcmf_cfg80211_info *)config;

	if (!cfg)
		return (prio == PRIO_8021D_NONE || prio == PRIO_8021D_BE) ?
		       (prio ^ 2) : prio;

	/* For those AC(s) with ACM flag set to 1, convert its 4-level priority
	 * to an 8-level precedence which is the same as BE's
	 */
	if (prio > PRIO_8021D_EE &&
	    cfg->ac_priority[prio] == cfg->ac_priority[PRIO_8021D_BE])
		return cfg->ac_priority[prio] * 2;

	/* Conversion of 4-level priority to 8-level precedence */
	if (prio == PRIO_8021D_BE || prio == PRIO_8021D_BK ||
	    prio == PRIO_8021D_CL || prio == PRIO_8021D_VO)
		return cfg->ac_priority[prio] * 2;
	else
		return cfg->ac_priority[prio] * 2 + 1;
}

u8 brcmf_map_prio_to_aci(void *config, u8 prio)
{
	/* Prio here refers to the 802.1d priority in range of 0 to 7.
	 * ACI here refers to the WLAN AC Index in range of 0 to 3.
	 * This function will return ACI corresponding to input prio.
	 */
	struct brcmf_cfg80211_info *cfg = (struct brcmf_cfg80211_info *)config;

	if (cfg)
		return cfg->ac_priority[prio];

	return prio;
}

static void brcmf_init_wmm_prio(u8 *priority)
{
	/* Initialize AC priority array to default
	 * 802.1d priority as per following table:
	 * 802.1d prio 0,3 maps to BE
	 * 802.1d prio 1,2 maps to BK
	 * 802.1d prio 4,5 maps to VI
	 * 802.1d prio 6,7 maps to VO
	 */
	priority[0] = BRCMF_FWS_FIFO_AC_BE;
	priority[3] = BRCMF_FWS_FIFO_AC_BE;
	priority[1] = BRCMF_FWS_FIFO_AC_BK;
	priority[2] = BRCMF_FWS_FIFO_AC_BK;
	priority[4] = BRCMF_FWS_FIFO_AC_VI;
	priority[5] = BRCMF_FWS_FIFO_AC_VI;
	priority[6] = BRCMF_FWS_FIFO_AC_VO;
	priority[7] = BRCMF_FWS_FIFO_AC_VO;
}

static void brcmf_wifi_prioritize_acparams(const
	struct brcmf_cfg80211_edcf_acparam *acp, u8 *priority)
{
	u8 aci;
	u8 aifsn;
	u8 ecwmin;
	u8 ecwmax;
	u8 acm;
	u8 ranking_basis[EDCF_AC_COUNT];
	u8 aci_prio[EDCF_AC_COUNT]; /* AC_BE, AC_BK, AC_VI, AC_VO */
	u8 index;

	for (aci = 0; aci < EDCF_AC_COUNT; aci++, acp++) {
		aifsn  = acp->ACI & EDCF_AIFSN_MASK;
		acm = (acp->ACI & EDCF_ACM_MASK) ? 1 : 0;
		ecwmin = acp->ECW & EDCF_ECWMIN_MASK;
		ecwmax = (acp->ECW & EDCF_ECWMAX_MASK) >> EDCF_ECWMAX_SHIFT;
		brcmf_dbg(CONN, "ACI %d aifsn %d acm %d ecwmin %d ecwmax %d\n",
			  aci, aifsn, acm, ecwmin, ecwmax);
		/* Default AC_VO will be the lowest ranking value */
		ranking_basis[aci] = aifsn + ecwmin + ecwmax;
		/* Initialise priority starting at 0 (AC_BE) */
		aci_prio[aci] = 0;

		/* If ACM is set, STA can't use this AC as per 802.11.
		 * Change the ranking to BE
		 */
		if (aci != AC_BE && aci != AC_BK && acm == 1)
			ranking_basis[aci] = ranking_basis[AC_BE];
	}

	/* Ranking method which works for AC priority
	 * swapping when values for cwmin, cwmax and aifsn are varied
	 * Compare each aci_prio against each other aci_prio
	 */
	for (aci = 0; aci < EDCF_AC_COUNT; aci++) {
		for (index = 0; index < EDCF_AC_COUNT; index++) {
			if (index != aci) {
				/* Smaller ranking value has higher priority,
				 * so increment priority for each ACI which has
				 * a higher ranking value
				 */
				if (ranking_basis[aci] < ranking_basis[index])
					aci_prio[aci]++;
			}
		}
	}

	/* By now, aci_prio[] will be in range of 0 to 3.
	 * Use ACI prio to get the new priority value for
	 * each 802.1d traffic type, in this range.
	 */
	if (!(aci_prio[AC_BE] == aci_prio[AC_BK] &&
	      aci_prio[AC_BK] == aci_prio[AC_VI] &&
	      aci_prio[AC_VI] == aci_prio[AC_VO])) {
		/* 802.1d 0,3 maps to BE */
		priority[0] = aci_prio[AC_BE];
		priority[3] = aci_prio[AC_BE];

		/* 802.1d 1,2 maps to BK */
		priority[1] = aci_prio[AC_BK];
		priority[2] = aci_prio[AC_BK];

		/* 802.1d 4,5 maps to VO */
		priority[4] = aci_prio[AC_VI];
		priority[5] = aci_prio[AC_VI];

		/* 802.1d 6,7 maps to VO */
		priority[6] = aci_prio[AC_VO];
		priority[7] = aci_prio[AC_VO];
	} else {
		/* Initialize to default priority */
		brcmf_init_wmm_prio(priority);
	}

	brcmf_dbg(CONN, "Adj prio BE 0->%d, BK 1->%d, BK 2->%d, BE 3->%d\n",
		  priority[0], priority[1], priority[2], priority[3]);

	brcmf_dbg(CONN, "Adj prio VI 4->%d, VI 5->%d, VO 6->%d, VO 7->%d\n",
		  priority[4], priority[5], priority[6], priority[7]);
}

static s32 brcmf_get_assoc_ies(struct brcmf_cfg80211_info *cfg,
			       struct brcmf_if *ifp)
{
	struct brcmf_pub *drvr = cfg->pub;
	struct brcmf_cfg80211_assoc_ielen_le *assoc_info;
	struct brcmf_cfg80211_connect_info *conn_info = cfg_to_conn(cfg);
	struct brcmf_cfg80211_edcf_acparam edcf_acparam_info[EDCF_AC_COUNT];
	u32 req_len;
	u32 resp_len;
	u32 flags;
	s32 err = 0;

	brcmf_dbg(CONN, "req: %p, req len (%d) resp: %p resp len (%d)\n", conn_info->req_ie,
		  conn_info->req_ie_len, conn_info->resp_ie, conn_info->resp_ie_len);

	if (conn_info->req_ie_len && conn_info->resp_ie_len &&
	    conn_info->req_ie && conn_info->resp_ie)
		return 0;

	brcmf_clear_assoc_ies(cfg);

	memset(cfg->extra_buf, '\0', WL_EXTRA_BUF_MAX);
	err = brcmf_fil_iovar_data_get(ifp, "assoc_info",
				       cfg->extra_buf, WL_ASSOC_INFO_MAX);
	if (err) {
		bphy_err(drvr, "could not get assoc info (%d)\n", err);
		return err;
	}
	assoc_info =
		(struct brcmf_cfg80211_assoc_ielen_le *)cfg->extra_buf;
	req_len = le32_to_cpu(assoc_info->req_len);
	resp_len = le32_to_cpu(assoc_info->resp_len);
	flags = le32_to_cpu(assoc_info->flags);
	if (req_len > WL_EXTRA_BUF_MAX || resp_len > WL_EXTRA_BUF_MAX) {
		bphy_err(drvr, "invalid lengths in assoc info: req %u resp %u\n",
			 req_len, resp_len);
		return -EINVAL;
	}
	if (req_len) {
		memset(cfg->extra_buf, '\0', WL_EXTRA_BUF_MAX);
		err = brcmf_fil_iovar_data_get(ifp, "assoc_req_ies",
					       cfg->extra_buf,
					       WL_ASSOC_INFO_MAX);
		if (err) {
			bphy_err(drvr, "could not get assoc req (%d)\n", err);
			return err;
		}

		if (flags & BRCMF_ASSOC_REQ_IS_REASSOC)
			conn_info->req_ie_len = req_len - sizeof(struct dot11_reassoc_req);
		else
			conn_info->req_ie_len = req_len - sizeof(struct dot11_assoc_req);

		conn_info->req_ie =
		    kmemdup(cfg->extra_buf, conn_info->req_ie_len,
			    GFP_KERNEL);
		if (!conn_info->req_ie)
			conn_info->req_ie_len = 0;
	} else {
		conn_info->req_ie_len = 0;
		conn_info->req_ie = NULL;
	}

	/* resp_len is the total length of assoc resp
	 * which includes 6 bytes of aid/status code/capabilities.
	 * the assoc_resp_ie length should minus the 6 bytes which starts from rate_ie.
	 */
	if (resp_len) {
		memset(cfg->extra_buf, '\0', WL_EXTRA_BUF_MAX);
		err = brcmf_fil_iovar_data_get(ifp, "assoc_resp_ies",
					       cfg->extra_buf,
					       WL_ASSOC_INFO_MAX);
		if (err) {
			bphy_err(drvr, "could not get assoc resp (%d)\n", err);
			return err;
		}
		conn_info->resp_ie_len = resp_len - sizeof(struct dot11_assoc_resp);
		conn_info->resp_ie =
		    kmemdup(cfg->extra_buf, conn_info->resp_ie_len,
			    GFP_KERNEL);
		if (!conn_info->resp_ie)
			conn_info->resp_ie_len = 0;

		err = brcmf_fil_iovar_data_get(ifp, "wme_ac_sta",
					       edcf_acparam_info,
					       sizeof(edcf_acparam_info));
		if (err) {
			brcmf_err("could not get wme_ac_sta (%d)\n", err);
			return err;
		}

		brcmf_wifi_prioritize_acparams(edcf_acparam_info,
					       cfg->ac_priority);
	} else {
		conn_info->resp_ie_len = 0;
		conn_info->resp_ie = NULL;
	}
	brcmf_dbg(CONN, "req len (%d) resp len (%d)\n",
		  conn_info->req_ie_len, conn_info->resp_ie_len);

	return err;
}

static bool
brcmf_has_pmkid(const u8 *parse, u32 len, u32 *offset_in_ie)
{
	const struct brcmf_tlv *rsn_ie;
	const u8 *ie;
	u32 ie_len;
	u32 offset;
	u16 count;

	rsn_ie = brcmf_parse_tlvs(parse, len, WLAN_EID_RSN);
	if (!rsn_ie)
		goto done;
	ie = (const u8 *)rsn_ie;
	ie_len = rsn_ie->len + TLV_HDR_LEN;
	/* Skip group data cipher suite */
	offset = TLV_HDR_LEN + WPA_IE_VERSION_LEN + WPA_IE_MIN_OUI_LEN;
	if (offset + WPA_IE_SUITE_COUNT_LEN >= ie_len)
		goto done;
	/* Skip pairwise cipher suite(s) */
	count = ie[offset] + (ie[offset + 1] << 8);
	offset += WPA_IE_SUITE_COUNT_LEN + (count * WPA_IE_MIN_OUI_LEN);
	if (offset + WPA_IE_SUITE_COUNT_LEN >= ie_len)
		goto done;
	/* Skip auth key management suite(s) */
	count = ie[offset] + (ie[offset + 1] << 8);
	offset += WPA_IE_SUITE_COUNT_LEN + (count * WPA_IE_MIN_OUI_LEN);
	if (offset + RSN_CAP_LEN >= ie_len)
		goto done;
	/* Skip rsn capabilities */
	offset += RSN_CAP_LEN;
	if (offset + RSN_PMKID_COUNT_LEN > ie_len)
		goto done;
	/* Extract PMKID count */
	count = ie[offset] + (ie[offset + 1] << 8);
	if (count) {
		if (offset_in_ie)
			*offset_in_ie = offset + RSN_PMKID_COUNT_LEN;
		return true;
	}

done:
	if (offset_in_ie)
		*offset_in_ie = 0;
	return false;
}

static s32
brcmf_bss_roaming_done(struct brcmf_cfg80211_info *cfg,
		       struct net_device *ndev,
		       const struct brcmf_event_msg *e)
{
	struct brcmf_if *ifp = netdev_priv(ndev);
	struct brcmf_cfg80211_profile *profile = &ifp->vif->profile;
	struct brcmf_cfg80211_connect_info *conn_info = cfg_to_conn(cfg);
	struct wiphy *wiphy = cfg_to_wiphy(cfg);
	struct ieee80211_channel *notify_channel = NULL;
	struct ieee80211_supported_band *band;
	struct brcmf_bss_info_le *bi;
	struct brcmu_chan ch;
	struct cfg80211_roam_info roam_info = {};
	u32 freq;
	s32 err = 0;

	brcmf_dbg(TRACE, "Enter\n");

	brcmf_get_assoc_ies(cfg, ifp);
	memcpy(profile->bssid, e->addr, ETH_ALEN);
	bi = (struct brcmf_bss_info_le *)brcmf_update_bss_info(cfg, ifp);
	if (!bi)
		goto done;

	ch.chspec = le16_to_cpu(bi->chanspec);
	cfg->d11inf.decchspec(&ch);

	band = wiphy->bands[BRCMU_CHAN_BAND_TO_NL80211(ch.band)];
	freq = ieee80211_channel_to_frequency(ch.control_ch_num, band->band);
	if (!freq)
		err = -EINVAL;
	notify_channel = ieee80211_get_channel(wiphy, freq);
	if (!notify_channel)
		err = -EINVAL;

done:

	roam_info.links[0].channel = notify_channel;
	roam_info.links[0].bssid = profile->bssid;
	roam_info.req_ie = conn_info->req_ie;
	roam_info.req_ie_len = conn_info->req_ie_len;
	roam_info.resp_ie = conn_info->resp_ie;
	roam_info.resp_ie_len = conn_info->resp_ie_len;

	if (((profile->use_fwsup == BRCMF_PROFILE_FWSUP_1X ||
	      profile->use_fwsup == BRCMF_PROFILE_FWSUP_ROAM) &&
	    (brcmf_has_pmkid(roam_info.req_ie, roam_info.req_ie_len, NULL) ||
	     profile->is_ft || profile->is_okc)) ||
	     profile->use_fwsup == BRCMF_PROFILE_FWSUP_PSK ||
	     profile->use_fwsup == BRCMF_PROFILE_FWSUP_SAE)
		roam_info.authorized = true;

	cfg80211_roamed(ndev, &roam_info, GFP_KERNEL);
	brcmf_dbg(CONN, "Report roaming result, authorized is %s\n",
		  roam_info.authorized ? "true" : "false");

	clear_bit(BRCMF_VIF_STATUS_CONNECTING, &ifp->vif->sme_state);
	set_bit(BRCMF_VIF_STATUS_CONNECTED, &ifp->vif->sme_state);
	brcmf_dbg(TRACE, "Exit\n");
	return err;
}

static s32
brcmf_bss_connect_done(struct brcmf_cfg80211_info *cfg,
		       struct net_device *ndev, const struct brcmf_event_msg *e,
		       bool completed)
{
	struct brcmf_if *ifp = netdev_priv(ndev);
	struct brcmf_cfg80211_profile *profile = &ifp->vif->profile;
	struct brcmf_cfg80211_connect_info *conn_info = cfg_to_conn(cfg);
	struct cfg80211_connect_resp_params conn_params;

	brcmf_dbg(TRACE, "Enter cfg->pfn_enable %d\n", cfg->pfn_enable);

	if (test_and_clear_bit(BRCMF_VIF_STATUS_CONNECTING,
			       &ifp->vif->sme_state)) {
		memset(&conn_params, 0, sizeof(conn_params));
		if (completed) {
			brcmf_get_assoc_ies(cfg, ifp);
			brcmf_update_bss_info(cfg, ifp);
			set_bit(BRCMF_VIF_STATUS_CONNECTED,
				&ifp->vif->sme_state);
			conn_params.status = WLAN_STATUS_SUCCESS;
		} else {
			clear_bit(BRCMF_VIF_STATUS_EAP_SUCCESS,
				  &ifp->vif->sme_state);
			clear_bit(BRCMF_VIF_STATUS_ASSOC_SUCCESS,
				  &ifp->vif->sme_state);
			conn_params.status = WLAN_STATUS_AUTH_TIMEOUT;
		}
		conn_params.links[0].bssid = profile->bssid;
		conn_params.req_ie = conn_info->req_ie;
		conn_params.req_ie_len = conn_info->req_ie_len;
		conn_params.resp_ie = conn_info->resp_ie;
		conn_params.resp_ie_len = conn_info->resp_ie_len;

		if ((profile->use_fwsup == BRCMF_PROFILE_FWSUP_1X &&
		     brcmf_has_pmkid(conn_params.req_ie, conn_params.req_ie_len, NULL)) ||
		     profile->use_fwsup == BRCMF_PROFILE_FWSUP_PSK ||
		     profile->use_fwsup == BRCMF_PROFILE_FWSUP_SAE)
			conn_params.authorized = completed;

		cfg80211_connect_done(ndev, &conn_params, GFP_KERNEL);
		brcmf_dbg(CONN, "Report connect result - connection %s\n",
			  completed ? "succeeded" : "failed");
	} else if (cfg->pfn_enable && completed) {
		cfg->pfn_connection = 1;
	}
	brcmf_dbg(TRACE, "Exit\n");
	return 0;
}

s32 brcmf_mchan_config(struct brcmf_cfg80211_info *cfg)
{
	struct brcmf_pub *drvr = cfg->pub;
	struct brcmf_if *ifp;
	int ifidx = 0;
	s32 err = 0;
	struct brcmf_assoclist_le assoclist = {0};
	u8 mac_addr[ETH_ALEN] = {0}, mac_null[ETH_ALEN] = {0};
	u32 mchan_arg = 0;
	bool staif_connected = false, apif_connected = false;

	if (!brcmf_feat_is_enabled(drvr->iflist[0], BRCMF_FEAT_MCHAN_CONFIG))
		return 0;

	for (ifidx = 0; ifidx < BRCMF_MAX_IFS; ifidx++) {
		ifp = drvr->iflist[ifidx];
		if (ifp && ifp->vif) {
			if (ifp->vif->wdev.iftype == NL80211_IFTYPE_STATION) {
				err = brcmf_fil_cmd_data_get(ifp, BRCMF_C_GET_BSSID, &mac_addr,
							     sizeof(mac_addr));
				if (err)
					bphy_err(drvr, "BRCMF_C_GET_BSSID fail (%d)\n", err);
				else if (memcmp(mac_null, mac_addr, ETH_ALEN))
					staif_connected = true;
			} else if (ifp->vif->wdev.iftype == NL80211_IFTYPE_AP) {
				memset(&assoclist, 0, sizeof(assoclist));
				assoclist.count = cpu_to_le32(BRCMF_MAX_ASSOCLIST);
				err = brcmf_fil_cmd_data_get(ifp, BRCMF_C_GET_ASSOCLIST,
							     &assoclist,
							     sizeof(assoclist));
				if (err)
					bphy_err(drvr, "BRCMF_C_GET_ASSOCLIST fail (%d)\n", err);
				else if (assoclist.count > 0)
					apif_connected = true;
			}
		}
	}

	if (staif_connected && apif_connected) {
		brcmf_dbg(TRACE, "apsta case, set mchan config %d\n", cfg->mchan_conf);
		switch (cfg->mchan_conf) {
		case BRCMF_MCHAN_CONF_DEFAULT:
			mchan_arg = BRCMF_MCHAN_SI_ALGO;
			err = brcmf_fil_iovar_data_set(drvr->iflist[0], "mchan_algo",
						       &mchan_arg, sizeof(mchan_arg));
			break;
		case BRCMF_MCHAN_CONF_VEDIO:
			mchan_arg = BRCMF_MCHAN_ASYMMETRIC_SI_ALGO;
			err = brcmf_fil_iovar_data_set(drvr->iflist[0], "mchan_algo",
						       &mchan_arg, sizeof(mchan_arg));
			break;
		case BRCMF_MCHAN_CONF_AUDIO:
			mchan_arg = BRCMF_MCHAN_BANDWIDTH_ALGO;
			err = brcmf_fil_iovar_data_set(drvr->iflist[0], "mchan_algo",
						       &mchan_arg, sizeof(mchan_arg));
			if (err)
				goto cmd_fail;
			mchan_arg = BRCMF_MCHAN_BANDWIDTH_VAL;
			err = brcmf_fil_iovar_data_set(drvr->iflist[0], "mchan_bw",
						       &mchan_arg, sizeof(mchan_arg));
			break;
		default:
			brcmf_dbg(TRACE, "unexpected mchan conf %d\n", cfg->mchan_conf);
			break;
		}
cmd_fail:
		if (err)
			bphy_err(drvr, "cmd fail while set mchan config (%d)\n", err);
	}

	return 0;
}

static s32
brcmf_notify_connect_status_ap(struct brcmf_cfg80211_info *cfg,
			       struct net_device *ndev,
			       const struct brcmf_event_msg *e, void *data)
{
	struct brcmf_pub *drvr = cfg->pub;
	static int generation;
	u32 event = e->event_code;
	u32 reason = e->reason;
	struct station_info *sinfo;

	brcmf_dbg(CONN, "event %s (%u), reason %d\n",
		  brcmf_fweh_event_name(event), event, reason);
	if (event == BRCMF_E_LINK && reason == BRCMF_E_REASON_LINK_BSSCFG_DIS &&
	    ndev != cfg_to_ndev(cfg)) {
		brcmf_dbg(CONN, "AP mode link down\n");
		complete(&cfg->vif_disabled);
		return 0;
	}

	if (((event == BRCMF_E_ASSOC_IND) || (event == BRCMF_E_REASSOC_IND)) &&
	    (reason == BRCMF_E_STATUS_SUCCESS)) {
		if (!data) {
			bphy_err(drvr, "No IEs present in ASSOC/REASSOC_IND\n");
			return -EINVAL;
		}

		sinfo = kzalloc(sizeof(*sinfo), GFP_KERNEL);
		if (!sinfo)
			return -ENOMEM;

		sinfo->assoc_req_ies = data;
		sinfo->assoc_req_ies_len = e->datalen;
		generation++;
		sinfo->generation = generation;
		cfg80211_new_sta(ndev, e->addr, sinfo, GFP_KERNEL);

		kfree(sinfo);
	} else if ((event == BRCMF_E_DISASSOC_IND) ||
		   (event == BRCMF_E_DEAUTH_IND) ||
		   (event == BRCMF_E_DEAUTH)) {
		cfg80211_del_sta(ndev, e->addr, GFP_KERNEL);
	}
	return 0;
}

static s32
brcmf_notify_connect_status(struct brcmf_if *ifp,
			    const struct brcmf_event_msg *e, void *data)
{
	struct brcmf_cfg80211_info *cfg = ifp->drvr->config;
	struct net_device *ndev = ifp->ndev;
	struct brcmf_cfg80211_profile *profile = &ifp->vif->profile;
	struct ieee80211_channel *chan;
	s32 err = 0;

	if ((e->event_code == BRCMF_E_DEAUTH) ||
	    (e->event_code == BRCMF_E_DEAUTH_IND) ||
	    (e->event_code == BRCMF_E_DISASSOC_IND) ||
	    ((e->event_code == BRCMF_E_LINK) && (!e->flags))) {
		brcmf_proto_delete_peer(ifp->drvr, ifp->ifidx, (u8 *)e->addr);
	}

	if (brcmf_is_apmode(ifp->vif)) {
		if (e->event_code == BRCMF_E_ASSOC_IND ||
		    e->event_code == BRCMF_E_REASSOC_IND) {
			brcmf_findadd_sta(ifp, e->addr);
		} else if ((e->event_code == BRCMF_E_DISASSOC_IND) ||
				(e->event_code == BRCMF_E_DEAUTH_IND) ||
				(e->event_code == BRCMF_E_DEAUTH)) {
			brcmf_del_sta(ifp, e->addr);
		}
		err = brcmf_notify_connect_status_ap(cfg, ndev, e, data);
		brcmf_mchan_config(cfg);
	} else if (brcmf_is_linkup(ifp->vif, e)) {
		brcmf_dbg(CONN, "Linkup\n");
		if (brcmf_is_ibssmode(ifp->vif)) {
			brcmf_inform_ibss(cfg, ndev, e->addr);
			chan = ieee80211_get_channel(cfg->wiphy, cfg->channel);
			memcpy(profile->bssid, e->addr, ETH_ALEN);
			cfg80211_ibss_joined(ndev, e->addr, chan, GFP_KERNEL);
			clear_bit(BRCMF_VIF_STATUS_CONNECTING,
				  &ifp->vif->sme_state);
			set_bit(BRCMF_VIF_STATUS_CONNECTED,
				&ifp->vif->sme_state);
		} else {
			if (e->event_code == BRCMF_E_LINK && !profile->is_ft &&
			    test_bit(BRCMF_VIF_STATUS_CONNECTED, &ifp->vif->sme_state)) {
				brcmf_bss_roaming_done(cfg, ndev, e);
			} else {
				brcmf_bss_connect_done(cfg, ndev, e, true);
			}
		}
		brcmf_net_setcarrier(ifp, true);
		brcmf_mchan_config(cfg);
	} else if (brcmf_is_linkdown(ifp->vif, e)) {
		brcmf_dbg(CONN, "Linkdown\n");
		if (!brcmf_is_ibssmode(ifp->vif) &&
		    (test_bit(BRCMF_VIF_STATUS_CONNECTED,
			      &ifp->vif->sme_state) ||
		     test_bit(BRCMF_VIF_STATUS_CONNECTING,
			      &ifp->vif->sme_state))) {
			if (test_bit(BRCMF_VIF_STATUS_CONNECTED,
				     &ifp->vif->sme_state) &&
			    memcmp(profile->bssid, e->addr, ETH_ALEN))
				return err;

			brcmf_bss_connect_done(cfg, ndev, e, false);
			brcmf_link_down(ifp->vif,
					brcmf_map_fw_linkdown_reason(e),
					e->event_code &
					(BRCMF_E_DEAUTH_IND |
					BRCMF_E_DISASSOC_IND)
					? false : true);
			brcmf_init_prof(ndev_to_prof(ndev));
			if (ndev != cfg_to_ndev(cfg))
				complete(&cfg->vif_disabled);
			brcmf_net_setcarrier(ifp, false);
		}
	} else if (brcmf_is_nonetwork(cfg, e)) {
		if (brcmf_is_ibssmode(ifp->vif))
			clear_bit(BRCMF_VIF_STATUS_CONNECTING,
				  &ifp->vif->sme_state);
		else
			brcmf_bss_connect_done(cfg, ndev, e, false);
	}

	return err;
}

static s32
brcmf_notify_roaming_status(struct brcmf_if *ifp,
			    const struct brcmf_event_msg *e, void *data)
{
	struct brcmf_cfg80211_info *cfg = ifp->drvr->config;
	u32 event = e->event_code;
	u32 status = e->status;

	if (event == BRCMF_E_ROAM && status == BRCMF_E_STATUS_SUCCESS) {
		if (test_bit(BRCMF_VIF_STATUS_CONNECTED,
			     &ifp->vif->sme_state)) {
			if (ifp->vif->profile.is_ft)
				brcmf_bss_roaming_done(cfg, ifp->ndev, e);
		} else {
			brcmf_bss_connect_done(cfg, ifp->ndev, e, true);
			brcmf_net_setcarrier(ifp, true);
		}
	}

	return 0;
}

static s32
brcmf_notify_mic_status(struct brcmf_if *ifp,
			const struct brcmf_event_msg *e, void *data)
{
	u16 flags = e->flags;
	enum nl80211_key_type key_type;

	if (flags & BRCMF_EVENT_MSG_GROUP)
		key_type = NL80211_KEYTYPE_GROUP;
	else
		key_type = NL80211_KEYTYPE_PAIRWISE;

	cfg80211_michael_mic_failure(ifp->ndev, (u8 *)&e->addr, key_type, -1,
				     NULL, GFP_KERNEL);

	return 0;
}

static s32 brcmf_notify_rssi(struct brcmf_if *ifp,
			     const struct brcmf_event_msg *e, void *data)
{
	struct brcmf_cfg80211_vif *vif = ifp->vif;
	struct brcmf_rssi_be *info = data;
	s32 rssi, snr = 0, noise = 0;
	s32 low, high, last;

	if (e->datalen >= sizeof(*info)) {
		rssi = be32_to_cpu(info->rssi);
		snr = be32_to_cpu(info->snr);
		noise = be32_to_cpu(info->noise);
	} else if (e->datalen >= sizeof(rssi)) {
		rssi = be32_to_cpu(*(__be32 *)data);
	} else {
		brcmf_err("insufficient RSSI event data\n");
		return 0;
	}

	low = vif->cqm_rssi_low;
	high = vif->cqm_rssi_high;
	last = vif->cqm_rssi_last;

	brcmf_dbg(TRACE, "rssi=%d snr=%d noise=%d low=%d high=%d last=%d\n",
		  rssi, snr, noise, low, high, last);

	vif->cqm_rssi_last = rssi;

	if (rssi <= low || rssi == 0) {
		brcmf_dbg(INFO, "LOW rssi=%d\n", rssi);
		cfg80211_cqm_rssi_notify(ifp->ndev,
					 NL80211_CQM_RSSI_THRESHOLD_EVENT_LOW,
					 rssi, GFP_KERNEL);
	} else if (rssi > high) {
		brcmf_dbg(INFO, "HIGH rssi=%d\n", rssi);
		cfg80211_cqm_rssi_notify(ifp->ndev,
					 NL80211_CQM_RSSI_THRESHOLD_EVENT_HIGH,
					 rssi, GFP_KERNEL);
	}

	return 0;
}

static s32 brcmf_notify_vif_event(struct brcmf_if *ifp,
				  const struct brcmf_event_msg *e, void *data)
{
	struct brcmf_cfg80211_info *cfg = ifp->drvr->config;
	struct brcmf_if_event *ifevent = (struct brcmf_if_event *)data;
	struct brcmf_cfg80211_vif_event *event = &cfg->vif_event;
	struct brcmf_cfg80211_vif *vif;
	enum nl80211_iftype iftype = NL80211_IFTYPE_UNSPECIFIED;
	bool vif_pend = false;
	int err;

	brcmf_dbg(TRACE, "Enter: action %u flags %u ifidx %u bsscfgidx %u\n",
		  ifevent->action, ifevent->flags, ifevent->ifidx,
		  ifevent->bsscfgidx);

	spin_lock(&event->vif_event_lock);
	event->action = ifevent->action;
	vif = event->vif;

	switch (ifevent->action) {
	case BRCMF_E_IF_ADD:
		/* waiting process may have timed out */
		if (!vif) {
			/* handle IF_ADD event from firmware */
			spin_unlock(&event->vif_event_lock);
			vif_pend = true;
			if (ifevent->role == WLC_E_IF_ROLE_STA)
				iftype = NL80211_IFTYPE_STATION;
			else if (ifevent->role == WLC_E_IF_ROLE_AP)
				iftype = NL80211_IFTYPE_AP;
			else
				vif_pend = false;

			if (vif_pend) {
				vif = brcmf_alloc_vif(cfg, iftype);
				if (IS_ERR(vif)) {
					brcmf_err("Role:%d failed to alloc vif\n",
						  ifevent->role);
					return PTR_ERR(vif);
				}
			} else {
				brcmf_err("Invalid Role:%d\n", ifevent->role);
				return -EBADF;
			}
		}

		ifp->vif = vif;
		vif->ifp = ifp;
		if (ifp->ndev) {
			vif->wdev.netdev = ifp->ndev;
			ifp->ndev->ieee80211_ptr = &vif->wdev;
			SET_NETDEV_DEV(ifp->ndev, wiphy_dev(cfg->wiphy));
		}

		if (vif_pend) {
			err = brcmf_net_attach(ifp, false);
			if (err) {
				brcmf_err("netdevice register failed with err:%d\n",
					  err);
				brcmf_free_vif(vif);
				free_netdev(ifp->ndev);
			}
			return err;
		}

		spin_unlock(&event->vif_event_lock);
		wake_up(&event->vif_wq);
		return 0;

	case BRCMF_E_IF_DEL:
		spin_unlock(&event->vif_event_lock);
		/* event may not be upon user request */
		if (brcmf_cfg80211_vif_event_armed(cfg))
			wake_up(&event->vif_wq);
		return 0;

	case BRCMF_E_IF_CHANGE:
		spin_unlock(&event->vif_event_lock);
		wake_up(&event->vif_wq);
		return 0;

	default:
		spin_unlock(&event->vif_event_lock);
		break;
	}
	return -EINVAL;
}

static s32
brcmf_notify_ext_auth_request(struct brcmf_if *ifp,
			      const struct brcmf_event_msg *e, void *data)
{
	struct brcmf_pub *drvr = ifp->drvr;
	struct cfg80211_external_auth_params params;
	struct brcmf_auth_req_status_le *auth_req =
		(struct brcmf_auth_req_status_le *)data;
	s32 err = 0;
	struct brcmf_auth_req_status_info_le_v2 *auth_req_v2 = NULL;
	struct brcmf_bss_info_le *bi = NULL;
	struct brcmf_cfg80211_info *cfg = drvr->config;

	brcmf_dbg(INFO, "Enter: event %s (%d) received\n",
		  brcmf_fweh_event_name(e->event_code), e->event_code);

	if (drvr->wlc_ver.wlc_ver_major > BRCMF_AUTH_STATUS_V2_FW_MAJOR ||
	    (drvr->wlc_ver.wlc_ver_major == BRCMF_AUTH_STATUS_V2_FW_MAJOR &&
	    drvr->wlc_ver.wlc_ver_minor >= BRCMF_AUTH_STATUS_V2_FW_MINOR)) {
		auth_req_v2 = (struct brcmf_auth_req_status_info_le_v2 *)data;
		if (e->datalen < sizeof(*auth_req_v2)) {
			brcmf_err("Ext auth req event data too small. Ignoring event\n");
			return -EINVAL;
		}
		/* Inform bss info to cfg80211 layer as during roaming
		 * Supplicant might not have scan results,if scan results
		 * are not found the SAE auth uses HNP by default and
		 * Target AP will reject the connection.
		 */
		if (e->datalen > sizeof(*auth_req_v2)) {
			bi = (struct brcmf_bss_info_le *)&auth_req_v2->bss_info_le;
			if (bi) {
				err = brcmf_inform_single_bss(cfg, bi);
				if (err) {
					brcmf_err("failed to update bss info, err=%d\n", err);
					return err;
				}
			} else {
				brcmf_err("External Auth request bss info is null\n");
				return -EINVAL;
			}
		}
		/* 10 ms delay to update results in cfg80211 */
		brcmf_delay(10);
		memset(&params, 0, sizeof(params));
		params.action = NL80211_EXTERNAL_AUTH_START;
		params.key_mgmt_suite = ntohl(WLAN_AKM_SUITE_SAE);
		params.status = WLAN_STATUS_SUCCESS;
		params.ssid.ssid_len = min_t(u32, IEEE80211_MAX_SSID_LEN, auth_req_v2->ssid_len);
		memcpy(params.ssid.ssid, auth_req_v2->ssid, params.ssid.ssid_len);
		memcpy(params.bssid, auth_req_v2->peer_mac, ETH_ALEN);
	} else {
		if (e->datalen < sizeof(*auth_req)) {
			bphy_err(drvr, "Event %s (%d) data too small. Ignore\n",
				 brcmf_fweh_event_name(e->event_code), e->event_code);
			return -EINVAL;
		}

		memset(&params, 0, sizeof(params));
		params.action = NL80211_EXTERNAL_AUTH_START;
		params.key_mgmt_suite = ntohl(WLAN_AKM_SUITE_SAE);
		params.status = WLAN_STATUS_SUCCESS;
		params.ssid.ssid_len = min_t(u32, 32, le32_to_cpu(auth_req->ssid_len));
		memcpy(params.ssid.ssid, auth_req->ssid, params.ssid.ssid_len);
		memcpy(params.bssid, auth_req->peer_mac, ETH_ALEN);
	}

	err = cfg80211_external_auth_request(ifp->ndev, &params, GFP_ATOMIC);
	if (err)
		bphy_err(drvr, "Ext Auth request to supplicant failed (%d)\n",
			 err);

	return err;
}

static s32
brcmf_notify_auth_frame_rx(struct brcmf_if *ifp,
			   const struct brcmf_event_msg *e, void *data)
{
	struct brcmf_pub *drvr = ifp->drvr;
	struct brcmf_cfg80211_info *cfg = drvr->config;
	struct wireless_dev *wdev;
	u32 mgmt_frame_len = e->datalen - sizeof(struct brcmf_rx_mgmt_data);
	struct brcmf_rx_mgmt_data *rxframe = (struct brcmf_rx_mgmt_data *)data;
	u8 *frame = (u8 *)(rxframe + 1);
	struct brcmu_chan ch;
	struct ieee80211_mgmt *mgmt_frame;
	s32 freq;

	brcmf_dbg(INFO, "Enter: event %s (%d) received\n",
		  brcmf_fweh_event_name(e->event_code), e->event_code);

	if (e->datalen < sizeof(*rxframe)) {
		bphy_err(drvr, "Event %s (%d) data too small. Ignore\n",
			 brcmf_fweh_event_name(e->event_code), e->event_code);
		return -EINVAL;
	}

	wdev = &ifp->vif->wdev;
	WARN_ON(!wdev);

	ch.chspec = be16_to_cpu(rxframe->chanspec);
	cfg->d11inf.decchspec(&ch);

	mgmt_frame = kzalloc(mgmt_frame_len, GFP_KERNEL);
	if (!mgmt_frame)
		return -ENOMEM;

	mgmt_frame->frame_control = cpu_to_le16(IEEE80211_STYPE_AUTH);
	memcpy(mgmt_frame->da, ifp->mac_addr, ETH_ALEN);
	memcpy(mgmt_frame->sa, e->addr, ETH_ALEN);
	brcmf_fil_cmd_data_get(ifp, BRCMF_C_GET_BSSID, mgmt_frame->bssid,
			       ETH_ALEN);
	frame += offsetof(struct ieee80211_mgmt, u);
	unsafe_memcpy(&mgmt_frame->u, frame,
		      mgmt_frame_len - offsetof(struct ieee80211_mgmt, u),
		      /* alloc enough buf*/);

	freq = ieee80211_channel_to_frequency(ch.control_ch_num,
			BRCMU_CHAN_BAND_TO_NL80211(ch.band));

	cfg80211_rx_mgmt(wdev, freq, 0, (u8 *)mgmt_frame, mgmt_frame_len,
			 NL80211_RXMGMT_FLAG_EXTERNAL_AUTH);
	kfree(mgmt_frame);
	return 0;
}

static s32
brcmf_notify_mgmt_tx_status(struct brcmf_if *ifp,
			    const struct brcmf_event_msg *e, void *data)
{
	struct brcmf_cfg80211_vif *vif = ifp->vif;
	u32 *packet_id = (u32 *)data;

	brcmf_dbg(INFO, "Enter: event %s (%d), status=%d\n",
		  brcmf_fweh_event_name(e->event_code), e->event_code,
		  e->status);

	if (!test_bit(BRCMF_MGMT_TX_SEND_FRAME, &vif->mgmt_tx_status) ||
	    (*packet_id != vif->mgmt_tx_id))
		return 0;

	if (e->event_code == BRCMF_E_MGMT_FRAME_TXSTATUS) {
		if (e->status == BRCMF_E_STATUS_SUCCESS)
			set_bit(BRCMF_MGMT_TX_ACK, &vif->mgmt_tx_status);
		else
			set_bit(BRCMF_MGMT_TX_NOACK, &vif->mgmt_tx_status);
	} else {
		set_bit(BRCMF_MGMT_TX_OFF_CHAN_COMPLETED, &vif->mgmt_tx_status);
	}

	complete(&vif->mgmt_tx);
	return 0;
}

static s32
brcmf_notify_rssi_change_ind(struct brcmf_if *ifp,
			     const struct brcmf_event_msg *e, void *data)
{
	struct brcmf_cfg80211_info *cfg = ifp->drvr->config;
	struct wl_event_data_rssi *value = (struct wl_event_data_rssi *)data;
	s32 rssi = 0;

	brcmf_dbg(INFO, "Enter: event %s (%d), status=%d\n",
		  brcmf_fweh_event_name(e->event_code), e->event_code,
		  e->status);

	if (!cfg->cqm_info.enable)
		return 0;

	rssi = ntohl(value->rssi);
	brcmf_dbg(TRACE, "rssi: %d, threshold: %d, send event(%s)\n",
		  rssi, cfg->cqm_info.rssi_threshold,
		  rssi > cfg->cqm_info.rssi_threshold ? "HIGH" : "LOW");
	cfg80211_cqm_rssi_notify(cfg_to_ndev(cfg),
				 (rssi > cfg->cqm_info.rssi_threshold ?
					NL80211_CQM_RSSI_THRESHOLD_EVENT_HIGH :
					NL80211_CQM_RSSI_THRESHOLD_EVENT_LOW),
				 rssi, GFP_KERNEL);

	return 0;
}

static s32
brcmf_notify_beacon_loss(struct brcmf_if *ifp,
			 const struct brcmf_event_msg *e, void *data)
{
	struct brcmf_cfg80211_info *cfg = ifp->drvr->config;
	struct brcmf_cfg80211_profile *profile = &ifp->vif->profile;
	struct cfg80211_bss *bss;
	struct net_device *ndev = ifp->ndev;

	brcmf_dbg(INFO, "Enter: event %s (%d), status=%d\n",
		  brcmf_fweh_event_name(e->event_code), e->event_code,
		  e->status);

	switch (ifp->drvr->settings->roamoff) {
	case BRCMF_ROAMOFF_EN_BCNLOST_MSG:
		/* On beacon loss event, Supplicant triggers new scan request
		 * with NL80211_SCAN_FLAG_FLUSH Flag set, but lost AP bss entry
		 * still remained as it is held by cfg as associated. Unlinking this
		 * current BSS from cfg cached bss list on beacon loss event here,
		 * would allow supplicant to receive new scanned entries
		 * without current bss and select new bss to trigger roam.
		 */
		bss = cfg80211_get_bss(cfg->wiphy, NULL, profile->bssid, 0, 0,
				       IEEE80211_BSS_TYPE_ANY, IEEE80211_PRIVACY_ANY);
		if (bss) {
			cfg80211_unlink_bss(cfg->wiphy, bss);
			cfg80211_put_bss(cfg->wiphy, bss);
		}

		cfg80211_cqm_beacon_loss_notify(cfg_to_ndev(cfg), GFP_KERNEL);
		break;
	case BRCMF_ROAMOFF_EN_DISCONNECT_EVT:
		brcmf_link_down(ifp->vif,
				WLAN_REASON_UNSPECIFIED,
				true);
		brcmf_init_prof(ndev_to_prof(ndev));
		if (ndev != cfg_to_ndev(cfg))
			complete(&cfg->vif_disabled);
		brcmf_net_setcarrier(ifp, false);
		break;

	case BRCMF_ROAMOFF_DISABLE:
	default:
		break;
	}

	return 0;
}

static s32
brcmf_notify_ext_assoc_frame_rx(struct brcmf_if *ifp,
				const struct brcmf_event_msg *e, void *data)
{
	struct brcmf_pub *drvr = ifp->drvr;
	struct net_device *ndev = ifp->ndev;
	u32 mgmt_frame_len = e->datalen - sizeof(struct brcmf_rx_mgmt_data);
	struct brcmf_rx_mgmt_data *rxframe = (struct brcmf_rx_mgmt_data *)data;
	u8 *frame = (u8 *)(rxframe + 1);
	struct cfg80211_update_owe_info owe_info;
	struct ieee80211_mgmt *mgmt_frame = (struct ieee80211_mgmt *)frame;

	brcmf_dbg(INFO, "Enter: event %s (%d) received\n",
		  brcmf_fweh_event_name(e->event_code), e->event_code);

	if (e->datalen < sizeof(*rxframe)) {
		bphy_err(drvr, "Event %s (%d) data too small. Ignore\n",
			 brcmf_fweh_event_name(e->event_code), e->event_code);
		return -EINVAL;
	}

	memset(&owe_info, 0, sizeof(struct cfg80211_update_owe_info));
	owe_info.ie_len = mgmt_frame_len - offsetof(struct ieee80211_mgmt, u);
	memcpy(owe_info.peer, e->addr, ETH_ALEN);
	owe_info.ie = kzalloc(owe_info.ie_len, GFP_KERNEL);

	if (!owe_info.ie)
		return -ENOMEM;

	if (ieee80211_is_assoc_req(mgmt_frame->frame_control)) {
		frame += offsetof(struct ieee80211_mgmt, u.assoc_req.variable);
	} else if (ieee80211_is_reassoc_req(mgmt_frame->frame_control)) {
		frame += offsetof(struct ieee80211_mgmt, u.reassoc_req.variable);
	} else {
		bphy_err(drvr, "unexpected FC:0x%x\n", mgmt_frame->frame_control);
		return -EINVAL;
	}

	memcpy((u8 *)owe_info.ie, frame, owe_info.ie_len);
	cfg80211_update_owe_info_event(ndev, &owe_info, GFP_KERNEL);

	kfree(owe_info.ie);
	return 0;
}

static void brcmf_init_conf(struct brcmf_cfg80211_conf *conf)
{
	conf->frag_threshold = (u32)-1;
	conf->rts_threshold = (u32)-1;
	conf->retry_short = (u32)-1;
	conf->retry_long = (u32)-1;
}

static s32
brcmf_notify_assoc_req_ie(struct brcmf_if *ifp, const struct brcmf_event_msg *e, void *data)
{
	struct brcmf_cfg80211_info *cfg = ifp->drvr->config;
	struct brcmf_cfg80211_connect_info *conn_info = cfg_to_conn(cfg);
	u32 event = e->event_code;
	u32 status = e->status;
	u32 req_len = e->datalen;

	brcmf_dbg(INFO, "Enter: event %s (%d), status=%d\n",
		  brcmf_fweh_event_name(e->event_code), e->event_code,
		  e->status);

	if (event == BRCMF_E_ASSOC_REQ_IE && status == BRCMF_E_STATUS_SUCCESS) {
		if (test_bit(BRCMF_VIF_STATUS_CONNECTED, &ifp->vif->sme_state) ||
		    test_bit(BRCMF_VIF_STATUS_CONNECTING, &ifp->vif->sme_state)) {
			brcmf_clear_assoc_req_ie(cfg);

			conn_info->req_ie_len = req_len;
			conn_info->req_ie = kmemdup(data, conn_info->req_ie_len, GFP_KERNEL);
			if (!conn_info->req_ie)
				conn_info->req_ie_len = 0;
			brcmf_dbg(CONN, "req ie (%p) req len (%d)\n", conn_info->req_ie,
				  conn_info->req_ie_len);
		} else {
			brcmf_err("No (Re)connection is in progress, Ignore event\n");
		}
	} else {
		brcmf_err("Failed to handle the event\n");
	}

	return 0;
}

static s32
brcmf_notify_assoc_resp_ie(struct brcmf_if *ifp,
			   const struct brcmf_event_msg *e, void *data)
{
	struct brcmf_cfg80211_info *cfg = ifp->drvr->config;
	struct brcmf_cfg80211_connect_info *conn_info = cfg_to_conn(cfg);
	struct brcmf_cfg80211_edcf_acparam edcf_acparam_info[EDCF_AC_COUNT];
	u32 event = e->event_code;
	u32 status = e->status;
	u32 resp_len = e->datalen;
	s32 err = 0;

	brcmf_dbg(INFO, "Enter: event %s (%d), status=%d\n",
		  brcmf_fweh_event_name(e->event_code), e->event_code,
		  e->status);

	if (event == BRCMF_E_ASSOC_RESP_IE && status == BRCMF_E_STATUS_SUCCESS) {
		if (test_bit(BRCMF_VIF_STATUS_CONNECTED, &ifp->vif->sme_state) ||
		    test_bit(BRCMF_VIF_STATUS_CONNECTING, &ifp->vif->sme_state)) {
			brcmf_clear_assoc_resp_ie(cfg);

			conn_info->resp_ie_len = resp_len;
			conn_info->resp_ie = kmemdup(data, conn_info->resp_ie_len, GFP_KERNEL);
			if (!conn_info->resp_ie)
				conn_info->resp_ie_len = 0;

			brcmf_dbg(CONN, "resp ie (%p) resp len (%d)\n", conn_info->resp_ie,
				  conn_info->resp_ie_len);
			err = brcmf_fil_iovar_data_get(ifp, "wme_ac_sta",
						       edcf_acparam_info,
						       sizeof(edcf_acparam_info));
			if (err) {
				brcmf_err("could not get wme_ac_sta (%d)\n", err);
				brcmf_clear_assoc_resp_ie(cfg);
			} else {
				brcmf_wifi_prioritize_acparams(edcf_acparam_info,
							       cfg->ac_priority);
			}
		} else {
			brcmf_err("No (Re)connection is in progress, Ignore event\n");
		}
	} else {
		brcmf_err("Failed to handle the event\n");
	}

	return 0;
}

static void brcmf_register_event_handlers(struct brcmf_cfg80211_info *cfg)
{
	struct brcmf_if *ifp = netdev_priv(cfg_to_ndev(cfg));
	struct wl_rssi_event rssi_event = {};
	int err = 0;

	/* get supported version from firmware side */
	err = brcmf_fil_iovar_data_get(ifp, "rssi_event", &rssi_event,
				       sizeof(rssi_event));
	if (err)
		brcmf_err("fail to get supported rssi_event version, err=%d\n", err);

	brcmf_fweh_register(cfg->pub, BRCMF_E_LINK,
			    brcmf_notify_connect_status);
	brcmf_fweh_register(cfg->pub, BRCMF_E_DEAUTH_IND,
			    brcmf_notify_connect_status);
	brcmf_fweh_register(cfg->pub, BRCMF_E_DEAUTH,
			    brcmf_notify_connect_status);
	brcmf_fweh_register(cfg->pub, BRCMF_E_DISASSOC_IND,
			    brcmf_notify_connect_status);
	brcmf_fweh_register(cfg->pub, BRCMF_E_ASSOC_IND,
			    brcmf_notify_connect_status);
	brcmf_fweh_register(cfg->pub, BRCMF_E_REASSOC_IND,
			    brcmf_notify_connect_status);
	brcmf_fweh_register(cfg->pub, BRCMF_E_ROAM,
			    brcmf_notify_roaming_status);
	brcmf_fweh_register(cfg->pub, BRCMF_E_MIC_ERROR,
			    brcmf_notify_mic_status);
	brcmf_fweh_register(cfg->pub, BRCMF_E_SET_SSID,
			    brcmf_notify_connect_status);
	brcmf_fweh_register(cfg->pub, BRCMF_E_PFN_NET_FOUND,
			    brcmf_notify_sched_scan_results);
	brcmf_fweh_register(cfg->pub, BRCMF_E_SA_COMPLETE_IND,
			    brcmf_notify_csa_completion_ind);
	brcmf_fweh_register(cfg->pub, BRCMF_E_IF,
			    brcmf_notify_vif_event);
	brcmf_fweh_register(cfg->pub, BRCMF_E_P2P_PROBEREQ_MSG,
			    brcmf_p2p_notify_rx_mgmt_p2p_probereq);
	brcmf_fweh_register(cfg->pub, BRCMF_E_P2P_DISC_LISTEN_COMPLETE,
			    brcmf_p2p_notify_listen_complete);
	brcmf_fweh_register(cfg->pub, BRCMF_E_ACTION_FRAME_RX,
			    brcmf_p2p_notify_action_frame_rx);
	brcmf_fweh_register(cfg->pub, BRCMF_E_ACTION_FRAME_COMPLETE,
			    brcmf_p2p_notify_action_tx_complete);
	brcmf_fweh_register(cfg->pub, BRCMF_E_ACTION_FRAME_OFF_CHAN_COMPLETE,
			    brcmf_p2p_notify_action_tx_complete);
	brcmf_fweh_register(cfg->pub, BRCMF_E_PSK_SUP,
			    brcmf_notify_connect_status);
	if (rssi_event.version == WL_RSSI_EVENT_IFX_VERSION)
		brcmf_fweh_register(cfg->pub, BRCMF_E_RSSI,
				    brcmf_notify_rssi_change_ind);
	else
		brcmf_fweh_register(cfg->pub, BRCMF_E_RSSI,
				    brcmf_notify_rssi);
	brcmf_fweh_register(cfg->pub, BRCMF_E_EXT_AUTH_REQ,
			    brcmf_notify_ext_auth_request);
	brcmf_fweh_register(cfg->pub, BRCMF_E_EXT_AUTH_FRAME_RX,
			    brcmf_notify_auth_frame_rx);
	brcmf_fweh_register(cfg->pub, BRCMF_E_MGMT_FRAME_TXSTATUS,
			    brcmf_notify_mgmt_tx_status);
	brcmf_fweh_register(cfg->pub, BRCMF_E_MGMT_FRAME_OFF_CHAN_COMPLETE,
			    brcmf_notify_mgmt_tx_status);
	brcmf_fweh_register(cfg->pub, BRCMF_E_BCNLOST_MSG,
			    brcmf_notify_beacon_loss);

	if (brcmf_feat_is_enabled(ifp, BRCMF_FEAT_TWT)) {
		brcmf_fweh_register(cfg->pub, BRCMF_E_TWT_SETUP,
				    brcmf_notify_twt_event);
		brcmf_fweh_register(cfg->pub, BRCMF_E_TWT_TEARDOWN,
				    brcmf_notify_twt_event);
	}
	brcmf_fweh_register(cfg->pub, BRCMF_E_EXT_ASSOC_FRAME_RX,
			    brcmf_notify_ext_assoc_frame_rx);
	brcmf_fweh_register(cfg->pub, BRCMF_E_ASSOC_REQ_IE,
			    brcmf_notify_assoc_req_ie);
	brcmf_fweh_register(cfg->pub, BRCMF_E_ASSOC_RESP_IE,
			    brcmf_notify_assoc_resp_ie);
	brcmf_fweh_register(cfg->pub, BRCMF_E_ICMP_ECHO_REQ,
			    brcmf_wiphy_icmp_echo_req_event_handler);
}

static void brcmf_deinit_priv_mem(struct brcmf_cfg80211_info *cfg)
{
	kfree(cfg->conf);
	cfg->conf = NULL;
	kfree(cfg->extra_buf);
	cfg->extra_buf = NULL;
	kfree(cfg->wowl.nd);
	cfg->wowl.nd = NULL;
	kfree(cfg->wowl.nd_info);
	cfg->wowl.nd_info = NULL;
	kfree(cfg->escan_info.escan_buf);
	cfg->escan_info.escan_buf = NULL;
}

static s32 brcmf_init_priv_mem(struct brcmf_cfg80211_info *cfg)
{
	cfg->conf = kzalloc(sizeof(*cfg->conf), GFP_KERNEL);
	if (!cfg->conf)
		goto init_priv_mem_out;
	cfg->extra_buf = kzalloc(WL_EXTRA_BUF_MAX, GFP_KERNEL);
	if (!cfg->extra_buf)
		goto init_priv_mem_out;
	cfg->wowl.nd = kzalloc(sizeof(*cfg->wowl.nd) + sizeof(u32), GFP_KERNEL);
	if (!cfg->wowl.nd)
		goto init_priv_mem_out;
	cfg->wowl.nd_info = kzalloc(sizeof(*cfg->wowl.nd_info) +
				    sizeof(struct cfg80211_wowlan_nd_match *),
				    GFP_KERNEL);
	if (!cfg->wowl.nd_info)
		goto init_priv_mem_out;
	cfg->escan_info.escan_buf = kzalloc(BRCMF_ESCAN_BUF_SIZE, GFP_KERNEL);
	if (!cfg->escan_info.escan_buf)
		goto init_priv_mem_out;

	return 0;

init_priv_mem_out:
	brcmf_deinit_priv_mem(cfg);

	return -ENOMEM;
}

static s32 wl_init_priv(struct brcmf_cfg80211_info *cfg)
{
	s32 err = 0;

	cfg->scan_request = NULL;
	cfg->pwr_save = true;
	cfg->dongle_up = false;		/* dongle is not up yet */
	err = brcmf_init_priv_mem(cfg);
	if (err)
		return err;
	brcmf_register_event_handlers(cfg);
	mutex_init(&cfg->usr_sync);
	brcmf_init_escan(cfg);
	brcmf_init_conf(cfg->conf);
	brcmf_init_wmm_prio(cfg->ac_priority);
	init_completion(&cfg->vif_disabled);
	return err;
}

static void wl_deinit_priv(struct brcmf_cfg80211_info *cfg)
{
	cfg->dongle_up = false;	/* dongle down */
	brcmf_abort_scanning(cfg);
	brcmf_deinit_priv_mem(cfg);
	brcmf_clear_assoc_ies(cfg);
}

static void init_vif_event(struct brcmf_cfg80211_vif_event *event)
{
	init_waitqueue_head(&event->vif_wq);
	spin_lock_init(&event->vif_event_lock);
}

static s32 brcmf_dongle_roam(struct brcmf_if *ifp)
{
	struct brcmf_pub *drvr = ifp->drvr;
	s32 err;
	u32 bcn_timeout;
	__le32 roamtrigger[2];
	__le32 roam_delta[2];
	__le32 bandlist[4];
	u32 n_bands;
	int i;

	/* Configure beacon timeout value based upon roaming setting */
	if (ifp->drvr->settings->roamoff < BRCMF_ROAMOFF_DISABLE ||
	    ifp->drvr->settings->roamoff >= BRCMF_ROAMOFF_MAX) {
		bphy_err(drvr,
			 "roamoff setting is incorrect (%d), reset it\n",
			 ifp->drvr->settings->roamoff);
		ifp->drvr->settings->roamoff = BRCMF_ROAMOFF_DISABLE;
	}

	if (ifp->drvr->settings->roamoff)
		bcn_timeout = BRCMF_DEFAULT_BCN_TIMEOUT_ROAM_OFF;
	else
		bcn_timeout = BRCMF_DEFAULT_BCN_TIMEOUT_ROAM_ON;
	err = brcmf_fil_iovar_int_set(ifp, "bcn_timeout", bcn_timeout);
	if (err) {
		bphy_err(drvr, "bcn_timeout error (%d)\n", err);
		goto roam_setup_done;
	}

	/* Enable/Disable built-in roaming to allow supplicant to take care of
	 * roaming.
	 */
	brcmf_dbg(INFO, "Internal Roaming = %s, Mode:%d\n",
		  ifp->drvr->settings->roamoff ? "Off" : "On", ifp->drvr->settings->roamoff);
	err = brcmf_fil_iovar_int_set(ifp, "roam_off",
				      ifp->drvr->settings->roamoff ? 1 : 0);
	if (err) {
		bphy_err(drvr, "roam_off error (%d)\n", err);
		goto roam_setup_done;
	}

	err = brcmf_fil_cmd_data_get(ifp, BRCMF_C_GET_BANDLIST, &bandlist,
				     sizeof(bandlist));
	if (err) {
		bphy_err(drvr, "could not obtain band info: err=%d\n", err);
		goto roam_setup_done;
	}
	/* To enhance compatibility set each band's roam properties instead of
	 * using all band. BAND_5G is 1, BAND_2G is 2 and BAND_6G is 3.
	 */
	n_bands = le32_to_cpu(bandlist[0]);
	for (i = 1; i <= n_bands; i++) {
		roamtrigger[0] = cpu_to_le32(WL_ROAM_TRIGGER_LEVEL);
		roamtrigger[1] = cpu_to_le32(bandlist[i]);
		err = brcmf_fil_cmd_data_set(ifp, BRCMF_C_SET_ROAM_TRIGGER,
					     (void *)roamtrigger, sizeof(roamtrigger));
		if (err)
			bphy_err(drvr, "WLC_SET_ROAM_TRIGGER error (%d), band %d\n",
				 err, bandlist[i]);

		roam_delta[0] = cpu_to_le32(WL_ROAM_DELTA);
		roam_delta[1] = cpu_to_le32(bandlist[i]);
		err = brcmf_fil_cmd_data_set(ifp, BRCMF_C_SET_ROAM_DELTA,
					     (void *)roam_delta, sizeof(roam_delta));
		if (err)
			bphy_err(drvr, "WLC_SET_ROAM_DELTA error (%d), band %d\n",
				 err, bandlist[i]);
	}

	return 0;

roam_setup_done:
	return err;
}

static s32
brcmf_dongle_scantime(struct brcmf_if *ifp)
{
	struct brcmf_pub *drvr = ifp->drvr;
	s32 err = 0;

	err = brcmf_fil_cmd_int_set(ifp, BRCMF_C_SET_SCAN_CHANNEL_TIME,
				    BRCMF_SCAN_CHANNEL_TIME);
	if (err) {
		bphy_err(drvr, "Scan assoc time error (%d)\n", err);
		goto dongle_scantime_out;
	}
	err = brcmf_fil_cmd_int_set(ifp, BRCMF_C_SET_SCAN_UNASSOC_TIME,
				    BRCMF_SCAN_UNASSOC_TIME);
	if (err) {
		bphy_err(drvr, "Scan unassoc time error (%d)\n", err);
		goto dongle_scantime_out;
	}

	err = brcmf_fil_cmd_int_set(ifp, BRCMF_C_SET_SCAN_PASSIVE_TIME,
				    BRCMF_SCAN_PASSIVE_TIME);
	if (err) {
		bphy_err(drvr, "Scan passive time error (%d)\n", err);
		goto dongle_scantime_out;
	}

dongle_scantime_out:
	return err;
}

static void brcmf_update_bw40_channel_flag(struct ieee80211_channel *channel,
					   struct brcmu_chan *ch)
{
	u32 ht40_flag;

	ht40_flag = channel->flags & IEEE80211_CHAN_NO_HT40;
	if (ch->sb == BRCMU_CHAN_SB_U) {
		if (ht40_flag == IEEE80211_CHAN_NO_HT40)
			channel->flags &= ~IEEE80211_CHAN_NO_HT40;
		channel->flags |= IEEE80211_CHAN_NO_HT40PLUS;
	} else {
		/* It should be one of
		 * IEEE80211_CHAN_NO_HT40 or
		 * IEEE80211_CHAN_NO_HT40PLUS
		 */
		channel->flags &= ~IEEE80211_CHAN_NO_HT40;
		if (ht40_flag == IEEE80211_CHAN_NO_HT40)
			channel->flags |= IEEE80211_CHAN_NO_HT40MINUS;
	}
}

static void brcmf_wiphy_reset_band_and_channel(struct wiphy *wiphy)
{
	enum nl80211_band band;
	struct ieee80211_supported_band *wiphy_band = NULL;

	for (band = 0; band < NUM_NL80211_BANDS; band++) {
		wiphy_band = wiphy->bands[band];
		if (!wiphy_band)
			continue;

		kfree(wiphy_band->channels);
		wiphy_band->channels = NULL;
		kfree(wiphy_band);
		wiphy->bands[band] = NULL;
	}
}

static int brcmf_fill_band_with_default_chanlist(struct wiphy *wiphy, struct brcmf_if *ifp)
{
	struct brcmf_pub *drvr = ifp->drvr;
	struct ieee80211_supported_band *band;
	int err, i;
	__le32 bandlist[4];
	u32 n_bands;

	err = brcmf_fil_cmd_data_get(ifp, BRCMF_C_GET_BANDLIST, &bandlist,
				     sizeof(bandlist));
	if (err) {
		bphy_err(drvr, "could not obtain band info: err=%d\n", err);
		return err;
	}

	brcmf_wiphy_reset_band_and_channel(wiphy);

	n_bands = le32_to_cpu(bandlist[0]);
	for (i = 1; i <= n_bands && i < ARRAY_SIZE(bandlist); i++) {
		if (bandlist[i] == cpu_to_le32(WLC_BAND_2G)) {
			band = kmemdup(&__wl_band_2ghz, sizeof(__wl_band_2ghz),
				       GFP_KERNEL);
			if (!band)
				goto mem_err;
			band->channels = kmemdup(&__wl_2ghz_channels,
						 sizeof(__wl_2ghz_channels),
						 GFP_KERNEL);
			if (!band->channels)
				goto mem_err;

			/* restore 2G channels info */
			band->n_channels = ARRAY_SIZE(__wl_2ghz_channels);
			wiphy->bands[NL80211_BAND_2GHZ] = band;
		} else if (bandlist[i] == cpu_to_le32(WLC_BAND_5G)) {
			band = kmemdup(&__wl_band_5ghz, sizeof(__wl_band_5ghz),
				       GFP_KERNEL);
			if (!band)
				goto mem_err;
			band->channels = kmemdup(&__wl_5ghz_channels,
						 sizeof(__wl_5ghz_channels),
						 GFP_KERNEL);
			if (!band->channels)
				goto mem_err;

			/* restore 5G channels info */
			band->n_channels = ARRAY_SIZE(__wl_5ghz_channels);
			wiphy->bands[NL80211_BAND_5GHZ] = band;
		} else if (bandlist[i] == cpu_to_le32(WLC_BAND_6G) &&
		    brcmf_feat_is_6ghz_enabled(ifp)) {
			band = kmemdup(&__wl_band_6ghz, sizeof(__wl_band_6ghz),
				       GFP_KERNEL);
			if (!band)
				goto mem_err;
			band->channels = kmemdup(&__wl_6ghz_channels,
						 sizeof(__wl_6ghz_channels),
						 GFP_KERNEL);
			if (!band->channels)
				goto mem_err;

			/* restore 6G channels info */
			band->n_channels = ARRAY_SIZE(__wl_6ghz_channels);
			wiphy->bands[NL80211_BAND_6GHZ] = band;
		}
	}

	if (wiphy->bands[NL80211_BAND_5GHZ] &&
	    brcmf_feat_is_enabled(ifp, BRCMF_FEAT_DOT11H))
		wiphy_ext_feature_set(wiphy,
				      NL80211_EXT_FEATURE_DFS_OFFLOAD);

	return 0;

mem_err:
	brcmf_wiphy_reset_band_and_channel(wiphy);
	return -ENOMEM;
}

static void brcmf_wiphy_rm_disabled_band_and_channel(struct wiphy *wiphy)
{
	enum nl80211_band band;
	struct ieee80211_supported_band *wiphy_band = NULL;
	struct ieee80211_channel *cur = NULL;
	struct ieee80211_channel *next = NULL;
	u32 n_ch = 0;
	u32 i, j;

	for (band = 0; band < NUM_NL80211_BANDS; band++) {
		wiphy_band = wiphy->bands[band];
		if (!wiphy_band)
			continue;

		n_ch = wiphy_band->n_channels;
		for (i = 0; i < n_ch;) {
			cur = &wiphy_band->channels[i];
			if (cur->flags == IEEE80211_CHAN_DISABLED) {
				for (j = i; j < n_ch - 1; j++) {
					cur = &wiphy_band->channels[j];
					next = &wiphy_band->channels[j + 1];
					memcpy(cur, next, sizeof(*cur));
				}
				n_ch--;
			} else {
				i++;
			}
		}

		wiphy_band->n_channels = n_ch;
		if (!n_ch) {
			kfree(wiphy_band->channels);
			wiphy_band->channels = NULL;
			kfree(wiphy_band);
			wiphy->bands[band] = NULL;
		}
	}
}

static int brcmf_construct_chaninfo(struct brcmf_cfg80211_info *cfg,
				    u32 bw_cap[])
{
	struct wiphy *wiphy = cfg_to_wiphy(cfg);
	struct brcmf_pub *drvr = cfg->pub;
	struct brcmf_if *ifp = brcmf_get_ifp(drvr, 0);
	struct ieee80211_supported_band *band;
	struct ieee80211_channel *channel;
	struct brcmf_chanspec_list *list;
	struct brcmu_chan ch;
	int err;
	u8 *pbuf;
	u32 i, j;
	u32 total;
	u32 chaninfo;
	pbuf = kzalloc(BRCMF_DCMD_MEDLEN, GFP_KERNEL);

	if (pbuf == NULL)
		return -ENOMEM;

	list = (struct brcmf_chanspec_list *)pbuf;

	err = brcmf_fil_iovar_data_get(ifp, "chanspecs", pbuf,
				       BRCMF_DCMD_MEDLEN);
	if (err) {
		bphy_err(drvr, "get chanspecs error (%d)\n", err);
		goto fail_pbuf;
	}

	err = brcmf_fill_band_with_default_chanlist(wiphy, ifp);
	if (err) {
		bphy_err(drvr, "could not retrore band and channels: err=%d\n", err);
		goto fail_pbuf;
	}

	band = wiphy->bands[NL80211_BAND_2GHZ];
	if (band) {
		for (i = 0; i < band->n_channels; i++)
			band->channels[i].flags = IEEE80211_CHAN_DISABLED;
	}
	band = wiphy->bands[NL80211_BAND_5GHZ];
	if (band) {
		for (i = 0; i < band->n_channels; i++)
			band->channels[i].flags = IEEE80211_CHAN_DISABLED;
	}
	band = wiphy->bands[NL80211_BAND_6GHZ];
	if (band) {
		for (i = 0; i < band->n_channels; i++)
			band->channels[i].flags = IEEE80211_CHAN_DISABLED;
	}

	total = le32_to_cpu(list->count);
	if (total > BRCMF_MAX_CHANSPEC_LIST) {
		bphy_err(drvr, "Invalid count of channel Spec. (%u)\n",
			 total);
		err = -EINVAL;
		goto fail_pbuf;
	}

	for (i = 0; i < total; i++) {
		ch.chspec = (u16)le32_to_cpu(list->element[i]);
		cfg->d11inf.decchspec(&ch);

		if (ch.band == BRCMU_CHAN_BAND_2G) {
			band = wiphy->bands[NL80211_BAND_2GHZ];
		} else if (ch.band == BRCMU_CHAN_BAND_5G) {
			band = wiphy->bands[NL80211_BAND_5GHZ];
		} else if ((ch.band == BRCMU_CHAN_BAND_6G)) {
			if (brcmf_feat_is_6ghz_enabled(ifp)) {
				band = wiphy->bands[NL80211_BAND_6GHZ];
			} else {
				brcmf_dbg(INFO, "Disabled channel Spec. 0x%x.\n",
					  ch.chspec);
				continue;
			}
		} else {
			bphy_err(drvr, "Invalid channel Spec. 0x%x.\n",
				 ch.chspec);
			continue;
		}
		if (!band)
			continue;
		if (!(bw_cap[band->band] & WLC_BW_40MHZ_BIT) &&
		    ch.bw == BRCMU_CHAN_BW_40)
			continue;
		if (!(bw_cap[band->band] & WLC_BW_80MHZ_BIT) &&
		    ch.bw == BRCMU_CHAN_BW_80)
			continue;

		channel = NULL;
		for (j = 0; j < band->n_channels; j++) {
			if (band->channels[j].hw_value == ch.control_ch_num) {
				channel = &band->channels[j];
				break;
			}
		}
		if (!channel) {
			/* It seems firmware supports some channel we never
			 * considered. Something new in IEEE standard?
			 */
			bphy_err(drvr, "Ignoring unexpected firmware channel %d\n",
				 ch.control_ch_num);
			continue;
		}

		if (channel->orig_flags & IEEE80211_CHAN_DISABLED)
			continue;

		/* assuming the chanspecs order is HT20,
		 * HT40 upper, HT40 lower, and VHT80.
		 */
		switch (ch.bw) {
		case BRCMU_CHAN_BW_160:
			channel->flags &= ~IEEE80211_CHAN_NO_160MHZ;
			break;
		case BRCMU_CHAN_BW_80:
			channel->flags &= ~IEEE80211_CHAN_NO_80MHZ;
			break;
		case BRCMU_CHAN_BW_40:
			brcmf_update_bw40_channel_flag(channel, &ch);
			break;
		default:
			wiphy_warn(wiphy, "Firmware reported unsupported bandwidth %d\n",
				   ch.bw);
			fallthrough;
		case BRCMU_CHAN_BW_20:
			/* enable the channel and disable other bandwidths
			 * for now as mentioned order assure they are enabled
			 * for subsequent chanspecs.
			 */
			channel->flags = IEEE80211_CHAN_NO_HT40 |
					 IEEE80211_CHAN_NO_80MHZ |
					 IEEE80211_CHAN_NO_160MHZ;
			ch.bw = BRCMU_CHAN_BW_20;
			cfg->d11inf.encchspec(&ch);
			chaninfo = ch.chspec;
			err = brcmf_fil_bsscfg_int_get(ifp, "per_chan_info",
						       &chaninfo);
			if (!err) {
				if (chaninfo & WL_CHAN_RADAR)
					channel->flags |=
						(IEEE80211_CHAN_RADAR |
						 IEEE80211_CHAN_NO_IR);
				if (chaninfo & WL_CHAN_PASSIVE)
					channel->flags |=
						IEEE80211_CHAN_NO_IR;
			}
		}
	}

	/* Remove disabled channels and band to avoid unexpected restore. */
	brcmf_wiphy_rm_disabled_band_and_channel(wiphy);

fail_pbuf:
	kfree(pbuf);
	return err;
}

static int brcmf_enable_bw40_2g(struct brcmf_cfg80211_info *cfg)
{
	struct brcmf_pub *drvr = cfg->pub;
	struct brcmf_if *ifp = brcmf_get_ifp(drvr, 0);
	struct ieee80211_supported_band *band;
	struct brcmf_fil_bwcap_le band_bwcap;
	struct brcmf_chanspec_list *list;
	u8 *pbuf;
	u32 val;
	int err;
	struct brcmu_chan ch;
	u32 num_chan;
	int i, j;

	/* verify support for bw_cap command */
	val = WLC_BAND_5G;
	err = brcmf_fil_iovar_int_get(ifp, "bw_cap", &val);

	if (!err) {
		/* only set 2G bandwidth using bw_cap command */
		band_bwcap.band = cpu_to_le32(WLC_BAND_2G);
		band_bwcap.bw_cap = cpu_to_le32(WLC_BW_CAP_40MHZ);
		err = brcmf_fil_iovar_data_set(ifp, "bw_cap", &band_bwcap,
					       sizeof(band_bwcap));
	} else {
		brcmf_dbg(INFO, "fallback to mimo_bw_cap\n");
		val = WLC_N_BW_40ALL;
		err = brcmf_fil_iovar_int_set(ifp, "mimo_bw_cap", val);
	}

	if (!err) {
		/* update channel info in 2G band */
		pbuf = kzalloc(BRCMF_DCMD_MEDLEN, GFP_KERNEL);

		if (pbuf == NULL)
			return -ENOMEM;

		ch.band = BRCMU_CHAN_BAND_2G;
		ch.bw = BRCMU_CHAN_BW_40;
		ch.sb = BRCMU_CHAN_SB_NONE;
		ch.chnum = 0;
		cfg->d11inf.encchspec(&ch);

		/* pass encoded chanspec in query */
		*(__le16 *)pbuf = cpu_to_le16(ch.chspec);

		err = brcmf_fil_iovar_data_get(ifp, "chanspecs", pbuf,
					       BRCMF_DCMD_MEDLEN);
		if (err) {
			bphy_err(drvr, "get chanspecs error (%d)\n", err);
			kfree(pbuf);
			return err;
		}

		band = cfg_to_wiphy(cfg)->bands[NL80211_BAND_2GHZ];
		list = (struct brcmf_chanspec_list *)pbuf;
		num_chan = le32_to_cpu(list->count);
		if (num_chan > BRCMF_MAX_CHANSPEC_LIST) {
			bphy_err(drvr, "Invalid count of channel Spec. (%u)\n",
				 num_chan);
			kfree(pbuf);
			return -EINVAL;
		}

		for (i = 0; i < num_chan; i++) {
			ch.chspec = (u16)le32_to_cpu(list->element[i]);
			cfg->d11inf.decchspec(&ch);
			if (WARN_ON(ch.band != BRCMU_CHAN_BAND_2G))
				continue;
			if (WARN_ON(ch.bw != BRCMU_CHAN_BW_40))
				continue;
			for (j = 0; j < band->n_channels; j++) {
				if (band->channels[j].hw_value == ch.control_ch_num)
					break;
			}
			if (WARN_ON(j == band->n_channels))
				continue;

			brcmf_update_bw40_channel_flag(&band->channels[j], &ch);
		}
		kfree(pbuf);
	}
	return err;
}

static void brcmf_get_bwcap(struct brcmf_if *ifp, u32 bw_cap[])
{
	struct brcmf_pub *drvr = ifp->drvr;
	u32 band, mimo_bwcap;
	int err;

	band = WLC_BAND_2G;
	err = brcmf_fil_iovar_int_get(ifp, "bw_cap", &band);
	if (!err) {
		bw_cap[NL80211_BAND_2GHZ] = band;
		band = WLC_BAND_5G;
		err = brcmf_fil_iovar_int_get(ifp, "bw_cap", &band);
		if (!err) {
			bw_cap[NL80211_BAND_5GHZ] = band;

			if (!brcmf_feat_is_6ghz_enabled(ifp))
				return;

			band = WLC_BAND_6G;
			err = brcmf_fil_iovar_int_get(ifp, "bw_cap", &band);
			if (!err) {
				bw_cap[NL80211_BAND_6GHZ] = band;
				return;
			}
			return;
		}
		WARN_ON(1);
		return;
	}
	brcmf_dbg(INFO, "fallback to mimo_bw_cap info\n");
	mimo_bwcap = 0;
	err = brcmf_fil_iovar_int_get(ifp, "mimo_bw_cap", &mimo_bwcap);
	if (err)
		/* assume 20MHz if firmware does not give a clue */
		mimo_bwcap = WLC_N_BW_20ALL;

	switch (mimo_bwcap) {
	case WLC_N_BW_40ALL:
		bw_cap[NL80211_BAND_2GHZ] |= WLC_BW_40MHZ_BIT;
		fallthrough;
	case WLC_N_BW_20IN2G_40IN5G:
		bw_cap[NL80211_BAND_5GHZ] |= WLC_BW_40MHZ_BIT;
		fallthrough;
	case WLC_N_BW_20ALL:
		bw_cap[NL80211_BAND_2GHZ] |= WLC_BW_20MHZ_BIT;
		bw_cap[NL80211_BAND_5GHZ] |= WLC_BW_20MHZ_BIT;
		break;
	default:
		bphy_err(drvr, "invalid mimo_bw_cap value\n");
	}
}

static void brcmf_update_ht_cap(struct ieee80211_supported_band *band,
				u32 bw_cap[2], u32 nchain)
{
	/* not allowed in 6G band */
	if (band->band == NL80211_BAND_6GHZ)
		return;

	band->ht_cap.ht_supported = true;
	if (bw_cap[band->band] & WLC_BW_40MHZ_BIT) {
		band->ht_cap.cap |= IEEE80211_HT_CAP_SGI_40;
		band->ht_cap.cap |= IEEE80211_HT_CAP_SUP_WIDTH_20_40;
	}
	band->ht_cap.cap |= IEEE80211_HT_CAP_SGI_20;
	band->ht_cap.cap |= IEEE80211_HT_CAP_DSSSCCK40;
	band->ht_cap.ampdu_factor = IEEE80211_HT_MAX_AMPDU_64K;
	band->ht_cap.ampdu_density = IEEE80211_HT_MPDU_DENSITY_16;
	memset(band->ht_cap.mcs.rx_mask, 0xff, nchain);
	band->ht_cap.mcs.tx_params = IEEE80211_HT_MCS_TX_DEFINED;
}

static __le16 brcmf_get_mcs_map(u32 nchain, enum ieee80211_vht_mcs_support supp)
{
	u16 mcs_map;
	int i;

	for (i = 0, mcs_map = 0xFFFF; i < nchain; i++)
		mcs_map = (mcs_map << 2) | supp;

	return cpu_to_le16(mcs_map);
}

static void brcmf_update_vht_cap(struct ieee80211_supported_band *band,
				 u32 bw_cap[2], u32 nchain, u32 txstreams,
				 u32 txbf_bfe_cap, u32 txbf_bfr_cap)
{
	__le16 mcs_map;

	/* not allowed in 2.4G & 6G band */
	if (band->band == NL80211_BAND_2GHZ || band->band == NL80211_BAND_6GHZ)
		return;

	band->vht_cap.vht_supported = true;
	/* 80MHz is mandatory */
	band->vht_cap.cap |= IEEE80211_VHT_CAP_SHORT_GI_80;
	if (bw_cap[band->band] & WLC_BW_160MHZ_BIT) {
		band->vht_cap.cap |= IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_160MHZ;
		band->vht_cap.cap |= IEEE80211_VHT_CAP_SHORT_GI_160;
	}
	/* all support 256-QAM */
	mcs_map = brcmf_get_mcs_map(nchain, IEEE80211_VHT_MCS_SUPPORT_0_9);
	band->vht_cap.vht_mcs.rx_mcs_map = mcs_map;
	band->vht_cap.vht_mcs.tx_mcs_map = mcs_map;

	/* Beamforming support information */
	if (txbf_bfe_cap & BRCMF_TXBF_SU_BFE_CAP)
		band->vht_cap.cap |= IEEE80211_VHT_CAP_SU_BEAMFORMEE_CAPABLE;
	if (txbf_bfe_cap & BRCMF_TXBF_MU_BFE_CAP)
		band->vht_cap.cap |= IEEE80211_VHT_CAP_MU_BEAMFORMEE_CAPABLE;
	if (txbf_bfr_cap & BRCMF_TXBF_SU_BFR_CAP)
		band->vht_cap.cap |= IEEE80211_VHT_CAP_SU_BEAMFORMER_CAPABLE;
	if (txbf_bfr_cap & BRCMF_TXBF_MU_BFR_CAP)
		band->vht_cap.cap |= IEEE80211_VHT_CAP_MU_BEAMFORMER_CAPABLE;

	if ((txbf_bfe_cap || txbf_bfr_cap) && (txstreams > 1)) {
		band->vht_cap.cap |=
			(2 << IEEE80211_VHT_CAP_BEAMFORMEE_STS_SHIFT);
		band->vht_cap.cap |= ((txstreams - 1) <<
				IEEE80211_VHT_CAP_SOUNDING_DIMENSIONS_SHIFT);
		band->vht_cap.cap |=
			IEEE80211_VHT_CAP_VHT_LINK_ADAPTATION_VHT_MRQ_MFB;
	}
}

static void brcmf_update_he_cap(struct ieee80211_supported_band *band,
				struct ieee80211_sband_iftype_data *data)
{
	int idx = 1;
	struct ieee80211_sta_he_cap *he_cap = &data->he_cap;
	struct ieee80211_he_cap_elem *he_cap_elem = &he_cap->he_cap_elem;
	struct ieee80211_he_mcs_nss_supp *he_mcs = &he_cap->he_mcs_nss_supp;
	struct ieee80211_he_6ghz_capa *he_6ghz_capa = &data->he_6ghz_capa;

	if (data == NULL) {
		brcmf_dbg(INFO, "failed to allco mem\n");
		return;
	}

	data->types_mask = BIT(NL80211_IFTYPE_STATION) | BIT(NL80211_IFTYPE_AP);
	he_cap->has_he = true;

	/* HE MAC Capabilities Information */
	he_cap_elem->mac_cap_info[0] = IEEE80211_HE_MAC_CAP0_HTC_HE |
				       IEEE80211_HE_MAC_CAP0_TWT_REQ |
				       IEEE80211_HE_MAC_CAP0_TWT_RES;

	he_cap_elem->mac_cap_info[1] = IEEE80211_HE_MAC_CAP1_TF_MAC_PAD_DUR_8US |
				       IEEE80211_HE_MAC_CAP1_TF_MAC_PAD_DUR_16US;

	he_cap_elem->mac_cap_info[2] = IEEE80211_HE_MAC_CAP2_BSR |
				       IEEE80211_HE_MAC_CAP2_BCAST_TWT;

	he_cap_elem->mac_cap_info[3] = IEEE80211_HE_MAC_CAP3_OMI_CONTROL |
				       IEEE80211_HE_MAC_CAP3_MAX_AMPDU_LEN_EXP_EXT_1 |
				       IEEE80211_HE_MAC_CAP3_FLEX_TWT_SCHED;

	he_cap_elem->mac_cap_info[4] = IEEE80211_HE_MAC_CAP4_AMSDU_IN_AMPDU;


	/* HE PHY Capabilities Information */
	he_cap_elem->phy_cap_info[0] = IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_40MHZ_IN_2G |
				       IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_40MHZ_80MHZ_IN_5G;

	he_cap_elem->phy_cap_info[1] = IEEE80211_HE_PHY_CAP1_LDPC_CODING_IN_PAYLOAD;

	he_cap_elem->phy_cap_info[2] = IEEE80211_HE_PHY_CAP2_NDP_4x_LTF_AND_3_2US |
				       IEEE80211_HE_PHY_CAP2_UL_MU_FULL_MU_MIMO |
				       IEEE80211_HE_PHY_CAP2_UL_MU_PARTIAL_MU_MIMO;

	he_cap_elem->phy_cap_info[3] = IEEE80211_HE_PHY_CAP3_DCM_MAX_CONST_TX_QPSK |
				       IEEE80211_HE_PHY_CAP3_DCM_MAX_TX_NSS_2 |
				       IEEE80211_HE_PHY_CAP3_DCM_MAX_CONST_RX_16_QAM;

	he_cap_elem->phy_cap_info[4] = IEEE80211_HE_PHY_CAP4_SU_BEAMFORMEE |
				       IEEE80211_HE_PHY_CAP4_BEAMFORMEE_MAX_STS_UNDER_80MHZ_8;

	he_cap_elem->phy_cap_info[5] = IEEE80211_HE_PHY_CAP5_NG16_SU_FEEDBACK |
				       IEEE80211_HE_PHY_CAP5_NG16_MU_FEEDBACK;

	he_cap_elem->phy_cap_info[6] = IEEE80211_HE_PHY_CAP6_CODEBOOK_SIZE_42_SU |
				       IEEE80211_HE_PHY_CAP6_CODEBOOK_SIZE_75_MU |
				       IEEE80211_HE_PHY_CAP6_TRIG_SU_BEAMFORMING_FB |
				       IEEE80211_HE_PHY_CAP6_TRIG_MU_BEAMFORMING_PARTIAL_BW_FB |
				       IEEE80211_HE_PHY_CAP6_TRIG_CQI_FB |
				       IEEE80211_HE_PHY_CAP6_PARTIAL_BW_EXT_RANGE |
				       IEEE80211_HE_PHY_CAP6_PPE_THRESHOLD_PRESENT;

	he_cap_elem->phy_cap_info[7] = IEEE80211_HE_PHY_CAP7_HE_SU_MU_PPDU_4XLTF_AND_08_US_GI |
				       IEEE80211_HE_PHY_CAP7_MAX_NC_1;

	he_cap_elem->phy_cap_info[8] = IEEE80211_HE_PHY_CAP8_HE_ER_SU_PPDU_4XLTF_AND_08_US_GI |
				       IEEE80211_HE_PHY_CAP8_20MHZ_IN_40MHZ_HE_PPDU_IN_2G;

	he_cap_elem->phy_cap_info[9] = IEEE80211_HE_PHY_CAP9_RX_1024_QAM_LESS_THAN_242_TONE_RU |
				       IEEE80211_HE_PHY_CAP9_RX_FULL_BW_SU_USING_MU_WITH_COMP_SIGB |
				       IEEE80211_HE_PHY_CAP9_RX_FULL_BW_SU_USING_MU_WITH_NON_COMP_SIGB;

	/* HE Supported MCS and NSS Set */
	he_mcs->rx_mcs_80 = cpu_to_le16(0xfffa);
	he_mcs->tx_mcs_80 = cpu_to_le16(0xfffa);
	/* HE 6 GHz band capabilities */
	if (band->band == NL80211_BAND_6GHZ) {
		u16 capa = 0;

		capa = FIELD_PREP(IEEE80211_HE_6GHZ_CAP_MIN_MPDU_START,
				   IEEE80211_HT_MPDU_DENSITY_8) |
			FIELD_PREP(IEEE80211_HE_6GHZ_CAP_MAX_AMPDU_LEN_EXP,
				   IEEE80211_VHT_MAX_AMPDU_1024K) |
			FIELD_PREP(IEEE80211_HE_6GHZ_CAP_MAX_MPDU_LEN,
				   IEEE80211_VHT_CAP_MAX_MPDU_LENGTH_11454);
		he_6ghz_capa->capa = cpu_to_le16(capa);
	}
	band->n_iftype_data = idx;
	band->iftype_data = data;
}

static int brcmf_setup_wiphybands(struct brcmf_cfg80211_info *cfg)
{
	struct brcmf_pub *drvr = cfg->pub;
	struct brcmf_if *ifp = brcmf_get_ifp(drvr, 0);
	struct wiphy *wiphy = cfg_to_wiphy(cfg);
	u32 nmode = 0;
	u32 vhtmode = 0;
	u32 bw_cap[4] = { WLC_BW_20MHZ_BIT,  /* 2GHz  */
			  WLC_BW_20MHZ_BIT,  /* 5GHz  */
			  0,                 /* 60GHz */
			  0 };		     /* 6GHz  */
	u32 rxchain;
	u32 nchain;
	int err;
	s32 i;
	struct ieee80211_supported_band *band;
	u32 txstreams = 0;
	u32 txbf_bfe_cap = 0;
	u32 txbf_bfr_cap = 0;
	u32 he[2] = {0, 0};

	(void)brcmf_fil_iovar_int_get(ifp, "vhtmode", &vhtmode);
	err = brcmf_fil_iovar_int_get(ifp, "nmode", &nmode);
	if (err) {
		bphy_err(drvr, "nmode error (%d)\n", err);
	} else {
		brcmf_get_bwcap(ifp, bw_cap);
	}
	(void)brcmf_fil_iovar_data_get(ifp, "he", he, sizeof(he));

	brcmf_dbg(INFO, "nmode=%d, vhtmode=%d, he=%d, bw_cap=(%d, %d, %d)\n",
		  nmode, vhtmode, he[0], bw_cap[NL80211_BAND_2GHZ],
		  bw_cap[NL80211_BAND_5GHZ], bw_cap[NL80211_BAND_6GHZ]);

	err = brcmf_fil_iovar_int_get(ifp, "rxchain", &rxchain);
	if (err) {
		/* rxchain unsupported by firmware of older chips */
		if (err == -EBADE)
			bphy_info_once(drvr, "rxchain unsupported\n");
		else
			bphy_err(drvr, "rxchain error (%d)\n", err);

		nchain = 1;
	} else {
		for (nchain = 0; rxchain; nchain++)
			rxchain = rxchain & (rxchain - 1);
	}
	brcmf_dbg(INFO, "nchain=%d\n", nchain);

	err = brcmf_construct_chaninfo(cfg, bw_cap);
	if (err) {
		bphy_err(drvr, "brcmf_construct_chaninfo failed (%d)\n", err);
		return err;
	}

	if (vhtmode) {
		(void)brcmf_fil_iovar_int_get(ifp, "txstreams", &txstreams);
		(void)brcmf_fil_iovar_int_get(ifp, "txbf_bfe_cap",
					      &txbf_bfe_cap);
		(void)brcmf_fil_iovar_int_get(ifp, "txbf_bfr_cap",
					      &txbf_bfr_cap);
	}

	for (i = 0; i < ARRAY_SIZE(wiphy->bands); i++) {
		band = wiphy->bands[i];
		if (band == NULL)
			continue;

		if ((band->band == NL80211_BAND_6GHZ) &&
		    !brcmf_feat_is_6ghz_enabled(ifp))
			continue;

		if (nmode)
			brcmf_update_ht_cap(band, bw_cap, nchain);
		if (vhtmode)
			brcmf_update_vht_cap(band, bw_cap, nchain, txstreams,
					     txbf_bfe_cap, txbf_bfr_cap);
		if (he[0])
			brcmf_update_he_cap(band, &sdata[band->band]);
	}

	return 0;
}

static const struct ieee80211_txrx_stypes
brcmf_txrx_stypes[NUM_NL80211_IFTYPES] = {
	[NL80211_IFTYPE_STATION] = {
		.tx = 0xffff,
		.rx = BIT(IEEE80211_STYPE_ACTION >> 4) |
		      BIT(IEEE80211_STYPE_AUTH >> 4) |
		      BIT(IEEE80211_STYPE_PROBE_REQ >> 4)
	},
	[NL80211_IFTYPE_P2P_CLIENT] = {
		.tx = 0xffff,
		.rx = BIT(IEEE80211_STYPE_ACTION >> 4) |
		      BIT(IEEE80211_STYPE_PROBE_REQ >> 4)
	},
	[NL80211_IFTYPE_P2P_GO] = {
		.tx = 0xffff,
		.rx = BIT(IEEE80211_STYPE_ASSOC_REQ >> 4) |
		      BIT(IEEE80211_STYPE_REASSOC_REQ >> 4) |
		      BIT(IEEE80211_STYPE_PROBE_REQ >> 4) |
		      BIT(IEEE80211_STYPE_DISASSOC >> 4) |
		      BIT(IEEE80211_STYPE_AUTH >> 4) |
		      BIT(IEEE80211_STYPE_DEAUTH >> 4) |
		      BIT(IEEE80211_STYPE_ACTION >> 4)
	},
	[NL80211_IFTYPE_P2P_DEVICE] = {
		.tx = 0xffff,
		.rx = BIT(IEEE80211_STYPE_ACTION >> 4) |
		      BIT(IEEE80211_STYPE_PROBE_REQ >> 4)
	},
	[NL80211_IFTYPE_AP] = {
		.tx = 0xffff,
		.rx = BIT(IEEE80211_STYPE_ASSOC_REQ >> 4) |
		      BIT(IEEE80211_STYPE_REASSOC_REQ >> 4) |
		      BIT(IEEE80211_STYPE_PROBE_REQ >> 4) |
		      BIT(IEEE80211_STYPE_DISASSOC >> 4) |
		      BIT(IEEE80211_STYPE_AUTH >> 4) |
		      BIT(IEEE80211_STYPE_DEAUTH >> 4) |
		      BIT(IEEE80211_STYPE_ACTION >> 4)
	}
};

/**
 * brcmf_setup_ifmodes() - determine interface modes and combinations.
 *
 * @wiphy: wiphy object.
 * @ifp: interface object needed for feat module api.
 *
 * The interface modes and combinations are determined dynamically here
 * based on firmware functionality.
 *
 * no p2p and no mbss:
 *
 *	#STA <= 1, #AP <= 1, channels = 1, 2 total
 *
 * no p2p and mbss:
 *
 *	#STA <= 1, #AP <= 1, channels = 1, 2 total
 *	#AP <= 4, matching BI, channels = 1, 4 total
 *
 * no p2p and rsdb:
 *	#STA <= 1, #AP <= 2, channels = 2, 4 total
 *
 * p2p, no mchan, and mbss:
 *
 *	#STA <= 1, #P2P-DEV <= 1, #{P2P-CL, P2P-GO} <= 1, channels = 1, 3 total
 *	#STA <= 1, #P2P-DEV <= 1, #AP <= 1, #P2P-CL <= 1, channels = 1, 4 total
 *	#AP <= 4, matching BI, channels = 1, 4 total
 *
 * p2p, mchan, and mbss:
 *
 *	#STA <= 2, #P2P-DEV <= 1, #{P2P-CL, P2P-GO} <= 1, channels = 2, 3 total
 *	#STA <= 1, #P2P-DEV <= 1, #AP <= 1, #P2P-CL <= 1, channels = 1, 4 total
 *	#AP <= 4, matching BI, channels = 1, 4 total
 *
 * p2p, rsdb, and no mbss:
 *	#STA <= 1, #P2P-DEV <= 1, #{P2P-CL, P2P-GO} <= 2, AP <= 2,
 *	 channels = 2, 4 total
 */
static int brcmf_setup_ifmodes(struct wiphy *wiphy, struct brcmf_if *ifp)
{
	struct ieee80211_iface_combination *combo = NULL;
	struct ieee80211_iface_limit *c0_limits = NULL;
	struct ieee80211_iface_limit *p2p_limits = NULL;
	struct ieee80211_iface_limit *mbss_limits = NULL;
	bool mon_flag, mbss, p2p, rsdb, mchan;
	int i, c, n_combos, n_limits;

	mon_flag = brcmf_feat_is_enabled(ifp, BRCMF_FEAT_MONITOR_FLAG);
	mbss = brcmf_feat_is_enabled(ifp, BRCMF_FEAT_MBSS);
	p2p = brcmf_feat_is_enabled(ifp, BRCMF_FEAT_P2P);
	rsdb = brcmf_feat_is_enabled(ifp, BRCMF_FEAT_RSDB);
	mchan = brcmf_feat_is_enabled(ifp, BRCMF_FEAT_MCHAN);

	n_combos = 1 + !!(p2p && !rsdb) + !!mbss;
	combo = kcalloc(n_combos, sizeof(*combo), GFP_KERNEL);
	if (!combo)
		goto err;

	wiphy->interface_modes = BIT(NL80211_IFTYPE_STATION) |
				 BIT(NL80211_IFTYPE_ADHOC) |
				 BIT(NL80211_IFTYPE_AP);
	if (mon_flag)
		wiphy->interface_modes |= BIT(NL80211_IFTYPE_MONITOR);
	if (p2p)
		wiphy->interface_modes |= BIT(NL80211_IFTYPE_P2P_CLIENT) |
					  BIT(NL80211_IFTYPE_P2P_GO) |
					  BIT(NL80211_IFTYPE_P2P_DEVICE);

	c = 0;
	i = 0;
	n_limits = 1 + mon_flag + (p2p ? 2 : 0) + (rsdb || !p2p);
	c0_limits = kcalloc(n_limits, sizeof(*c0_limits), GFP_KERNEL);
	if (!c0_limits)
		goto err;

	combo[c].num_different_channels = 1 + (rsdb || (p2p && mchan));
	c0_limits[i].max = 1 + (p2p && mchan);
	c0_limits[i++].types = BIT(NL80211_IFTYPE_STATION);
	if (mon_flag) {
		c0_limits[i].max = 1;
		c0_limits[i++].types = BIT(NL80211_IFTYPE_MONITOR);
	}
	if (p2p) {
		c0_limits[i].max = 1;
		c0_limits[i++].types = BIT(NL80211_IFTYPE_P2P_DEVICE);
		c0_limits[i].max = 1 + rsdb;
		c0_limits[i++].types = BIT(NL80211_IFTYPE_P2P_CLIENT) |
				       BIT(NL80211_IFTYPE_P2P_GO);
	}
	if (p2p && rsdb) {
		c0_limits[i].max = 2;
		c0_limits[i++].types = BIT(NL80211_IFTYPE_AP);
		combo[c].max_interfaces = 4;
	} else if (p2p) {
		combo[c].max_interfaces = i;
	} else if (rsdb) {
		c0_limits[i].max = 2;
		c0_limits[i++].types = BIT(NL80211_IFTYPE_AP);
		combo[c].max_interfaces = 3;
	} else {
		c0_limits[i].max = 1;
		c0_limits[i++].types = BIT(NL80211_IFTYPE_AP);
		combo[c].max_interfaces = i;
	}
	combo[c].n_limits = i;
	combo[c].limits = c0_limits;

	if (p2p && !rsdb) {
		c++;
		i = 0;
		p2p_limits = kcalloc(4, sizeof(*p2p_limits), GFP_KERNEL);
		if (!p2p_limits)
			goto err;
		p2p_limits[i].max = 1;
		p2p_limits[i++].types = BIT(NL80211_IFTYPE_STATION);
		p2p_limits[i].max = 1;
		p2p_limits[i++].types = BIT(NL80211_IFTYPE_AP);
		p2p_limits[i].max = 1;
		p2p_limits[i++].types = BIT(NL80211_IFTYPE_P2P_CLIENT);
		p2p_limits[i].max = 1;
		p2p_limits[i++].types = BIT(NL80211_IFTYPE_P2P_DEVICE);
		combo[c].num_different_channels = 1;
		combo[c].max_interfaces = i;
		combo[c].n_limits = i;
		combo[c].limits = p2p_limits;
	}

	if (mbss) {
		c++;
		i = 0;
		n_limits = 1 + mon_flag;
		mbss_limits = kcalloc(n_limits, sizeof(*mbss_limits),
				      GFP_KERNEL);
		if (!mbss_limits)
			goto err;
		mbss_limits[i].max = 4;
		mbss_limits[i++].types = BIT(NL80211_IFTYPE_AP);
		if (mon_flag) {
			mbss_limits[i].max = 1;
			mbss_limits[i++].types = BIT(NL80211_IFTYPE_MONITOR);
		}
		combo[c].beacon_int_infra_match = true;
		combo[c].num_different_channels = 1;
		combo[c].max_interfaces = 4 + mon_flag;
		combo[c].n_limits = i;
		combo[c].limits = mbss_limits;
	}

	wiphy->n_iface_combinations = n_combos;
	wiphy->iface_combinations = combo;
	return 0;

err:
	kfree(c0_limits);
	kfree(p2p_limits);
	kfree(mbss_limits);
	kfree(combo);
	return -ENOMEM;
}

#ifdef CONFIG_PM
static const struct wiphy_wowlan_support brcmf_wowlan_support = {
	.flags = WIPHY_WOWLAN_MAGIC_PKT | WIPHY_WOWLAN_DISCONNECT,
	.n_patterns = BRCMF_WOWL_MAXPATTERNS,
	.pattern_max_len = BRCMF_WOWL_MAXPATTERNSIZE,
	.pattern_min_len = 1,
	.max_pkt_offset = 1500,
};
#endif

static void brcmf_wiphy_wowl_params(struct wiphy *wiphy, struct brcmf_if *ifp)
{
#ifdef CONFIG_PM
	struct brcmf_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct brcmf_pub *drvr = cfg->pub;
	struct wiphy_wowlan_support *wowl;
	struct cfg80211_wowlan *brcmf_wowlan_config = NULL;

	wowl = kmemdup(&brcmf_wowlan_support, sizeof(brcmf_wowlan_support),
		       GFP_KERNEL);
	if (!wowl) {
		bphy_err(drvr, "only support basic wowlan features\n");
		wiphy->wowlan = &brcmf_wowlan_support;
		return;
	}

	if (brcmf_feat_is_enabled(ifp, BRCMF_FEAT_PNO)) {
		if (brcmf_feat_is_enabled(ifp, BRCMF_FEAT_WOWL_ND)) {
			wowl->flags |= WIPHY_WOWLAN_NET_DETECT;
			wowl->max_nd_match_sets = BRCMF_PNO_MAX_PFN_COUNT;
			init_waitqueue_head(&cfg->wowl.nd_data_wait);
		}
	}

	/* for backward compatibility, retain BRCMF_FEAT_WOWL_GTK */
	if (brcmf_feat_is_enabled(ifp, BRCMF_FEAT_WOWL_GTK) ||
	    brcmf_feat_is_enabled(ifp, BRCMF_FEAT_GTKO))
		wowl->flags |= WIPHY_WOWLAN_SUPPORTS_GTK_REKEY;

	if (brcmf_feat_is_enabled(ifp, BRCMF_FEAT_WOWL_GTK))
		wowl->flags |= WIPHY_WOWLAN_GTK_REKEY_FAILURE;

	wiphy->wowlan = wowl;

	/* wowlan_config structure report for kernels */
	brcmf_wowlan_config = kzalloc(sizeof(*brcmf_wowlan_config),
				      GFP_KERNEL);
	if (brcmf_wowlan_config) {
		brcmf_wowlan_config->any = false;
		brcmf_wowlan_config->disconnect = true;
		brcmf_wowlan_config->eap_identity_req = true;
		brcmf_wowlan_config->four_way_handshake = true;
		brcmf_wowlan_config->rfkill_release = false;
		brcmf_wowlan_config->patterns = NULL;
		brcmf_wowlan_config->n_patterns = 0;
		brcmf_wowlan_config->tcp = NULL;
		if (brcmf_feat_is_enabled(ifp, BRCMF_FEAT_WOWL_GTK))
			brcmf_wowlan_config->gtk_rekey_failure = true;
		else
			brcmf_wowlan_config->gtk_rekey_failure = false;
	} else {
		brcmf_err("Can not allocate memory for brcm_wowlan_config\n");
	}
	wiphy->wowlan_config = brcmf_wowlan_config;
#endif
}

static int brcmf_setup_wiphy(struct wiphy *wiphy, struct brcmf_if *ifp)
{
	struct brcmf_pub *drvr = ifp->drvr;
	struct brcmf_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	const struct ieee80211_iface_combination *combo;
	u16 max_interfaces = 0;
	bool gscan;
	int err, i;
	enum nl80211_band band;

	wiphy->max_scan_ssids = WL_NUM_SCAN_MAX;
	wiphy->max_scan_ie_len = BRCMF_SCAN_IE_LEN_MAX;
	wiphy->max_num_pmkids = BRCMF_MAXPMKID;

	err = brcmf_setup_ifmodes(wiphy, ifp);
	if (err)
		return err;

	for (i = 0, combo = wiphy->iface_combinations;
	     i < wiphy->n_iface_combinations; i++, combo++) {
		max_interfaces = max(max_interfaces, combo->max_interfaces);
	}

	for (i = 0; i < max_interfaces && i < ARRAY_SIZE(drvr->addresses);
	     i++) {
		u8 *addr = drvr->addresses[i].addr;

		memcpy(addr, drvr->mac, ETH_ALEN);
		if (i) {
			addr[0] |= BIT(1);
			addr[ETH_ALEN - 1] ^= i;
		}
	}
	wiphy->addresses = drvr->addresses;
	wiphy->n_addresses = i;

	wiphy->signal_type = CFG80211_SIGNAL_TYPE_MBM;
	wiphy->cipher_suites = brcmf_cipher_suites;
	wiphy->n_cipher_suites = ARRAY_SIZE(brcmf_cipher_suites);
	if (!brcmf_feat_is_enabled(ifp, BRCMF_FEAT_MFP))
		wiphy->n_cipher_suites -= 4;
	wiphy->bss_select_support = BIT(NL80211_BSS_SELECT_ATTR_RSSI) |
				    BIT(NL80211_BSS_SELECT_ATTR_BAND_PREF) |
				    BIT(NL80211_BSS_SELECT_ATTR_RSSI_ADJUST);

	wiphy->flags |= WIPHY_FLAG_NETNS_OK |
			WIPHY_FLAG_PS_ON_BY_DEFAULT |
			WIPHY_FLAG_HAVE_AP_SME |
			WIPHY_FLAG_OFFCHAN_TX |
			WIPHY_FLAG_HAS_REMAIN_ON_CHANNEL |
			WIPHY_FLAG_SPLIT_SCAN_6GHZ;

	if (brcmf_feat_is_enabled(ifp, BRCMF_FEAT_TDLS))
		wiphy->flags |= WIPHY_FLAG_SUPPORTS_TDLS;
	if (ifp->drvr->settings->roamoff == BRCMF_ROAMOFF_DISABLE)
		wiphy->flags |= WIPHY_FLAG_SUPPORTS_FW_ROAM;
	if (brcmf_feat_is_enabled(ifp, BRCMF_FEAT_FWSUP)) {
		wiphy_ext_feature_set(wiphy,
				      NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_PSK);
		wiphy_ext_feature_set(wiphy,
				      NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_1X);
		if (brcmf_feat_is_enabled(ifp, BRCMF_FEAT_OWE))
			wiphy_ext_feature_set(wiphy,
					      NL80211_EXT_FEATURE_OWE_OFFLOAD);
		if (brcmf_feat_is_enabled(ifp, BRCMF_FEAT_SAE))
			wiphy_ext_feature_set(wiphy,
					      NL80211_EXT_FEATURE_SAE_OFFLOAD);
	}
	if (brcmf_feat_is_enabled(ifp, BRCMF_FEAT_FWAUTH)) {
		wiphy_ext_feature_set(wiphy,
				      NL80211_EXT_FEATURE_4WAY_HANDSHAKE_AP_PSK);
		if (brcmf_feat_is_enabled(ifp, BRCMF_FEAT_SAE))
			wiphy_ext_feature_set(wiphy,
					      NL80211_EXT_FEATURE_SAE_OFFLOAD_AP);
	}
	if (brcmf_feat_is_enabled(ifp, BRCMF_FEAT_SAE_EXT)) {
		wiphy->features |= NL80211_FEATURE_SAE;
		wiphy_ext_feature_set(wiphy,
				      NL80211_EXT_FEATURE_AP_PMKSA_CACHING);
	}
	if (brcmf_feat_is_enabled(ifp, BRCMF_FEAT_FBT) ||
	    brcmf_feat_is_enabled(ifp, BRCMF_FEAT_OKC))
		wiphy_ext_feature_set(wiphy,
					NL80211_EXT_FEATURE_ROAM_OFFLOAD);
	wiphy_ext_feature_set(wiphy, NL80211_EXT_FEATURE_CQM_RSSI_LIST);

	wiphy->mgmt_stypes = brcmf_txrx_stypes;
	wiphy->max_remain_on_channel_duration = 5000;
	if (brcmf_feat_is_enabled(ifp, BRCMF_FEAT_PNO)) {
		gscan = brcmf_feat_is_enabled(ifp, BRCMF_FEAT_GSCAN);
		brcmf_pno_wiphy_params(wiphy, gscan);
	}
	/* vendor commands/events support */
	wiphy->vendor_commands = brcmf_vendor_cmds;
	wiphy->n_vendor_commands = get_brcmf_num_vndr_cmds();
	wiphy->vendor_events = brcmf_vendor_events;
	wiphy->n_vendor_events = get_brcmf_num_vndr_evts();
	brcmf_fweh_register(cfg->pub, BRCMF_E_PHY_TEMP,
			    brcmf_wiphy_phy_temp_evt_handler);

	brcmf_wiphy_wowl_params(wiphy, ifp);

	/* first entry in bandlist is number of bands */
	for (band = 0; band < NUM_NL80211_BANDS; band++)
		wiphy->bands[band] = NULL;
	err = brcmf_fill_band_with_default_chanlist(wiphy, ifp);
	if (err) {
		bphy_err(drvr, "could not retrore band and channels: err=%d\n", err);
		return err;
	}

	wiphy_ext_feature_set(wiphy, NL80211_EXT_FEATURE_CQM_RSSI_LIST);

	wiphy_read_of_freq_limits(wiphy);
	return 0;
}

static s32 brcmf_config_dongle(struct brcmf_cfg80211_info *cfg)
{
	struct brcmf_pub *drvr = cfg->pub;
	struct net_device *ndev;
	struct wireless_dev *wdev;
	struct brcmf_if *ifp;
	s32 power_mode;
	s32 eap_restrict;
	s32 err = 0;
	u32 wowl_config = 0;

	if (cfg->dongle_up)
		return err;

	ndev = cfg_to_ndev(cfg);
	wdev = ndev->ieee80211_ptr;
	ifp = netdev_priv(ndev);

	/* make sure RF is ready for work */
	brcmf_fil_cmd_int_set(ifp, BRCMF_C_UP, 0);

	brcmf_dongle_scantime(ifp);

	power_mode = cfg->pwr_save ? ifp->drvr->settings->default_pm : PM_OFF;
	err = brcmf_fil_cmd_int_set(ifp, BRCMF_C_SET_PM, power_mode);
	if (err)
		goto default_conf_out;
	brcmf_dbg(INFO, "power save set to %s\n",
		  (power_mode ? "enabled" : "disabled"));

	err = brcmf_dongle_roam(ifp);
	if (err)
		goto default_conf_out;

	eap_restrict = ifp->drvr->settings->eap_restrict;
	if (eap_restrict) {
		err = brcmf_fil_iovar_int_set(ifp, "eap_restrict",
					      eap_restrict);
		if (err)
			brcmf_info("eap_restrict error (%d)\n", err);
	}
	err = brcmf_cfg80211_change_iface(wdev->wiphy, ndev, wdev->iftype,
					  NULL);
	if (err)
		goto default_conf_out;

	/* Configure user based power profile for offloads.
	 * Default profile is LOW_PWR.
	 */
	if (brcmf_feat_is_enabled(ifp, BRCMF_FEAT_OFFLOADS)) {
		brcmf_generic_offload_config(ifp, brcmf_offload_feat,
					     brcmf_offload_prof, false);

		if (brcmf_feat_is_enabled(ifp, BRCMF_FEAT_ULP)) {
			wowl_config = BRCMF_WOWL_DIS | BRCMF_WOWL_BCN;
			err = brcmf_fil_iovar_int_set(ifp, "wowl", wowl_config);
			if (err < 0)
				brcmf_err("wowl_flags DIS,BCN not set");
		}
	} else {
		brcmf_configure_arp_nd_offload(ifp, true);
	}

	err = brcmf_fil_cmd_int_set(ifp, BRCMF_C_SET_FAKEFRAG, 1);
	if (err) {
		bphy_err(drvr, "failed to set frameburst mode\n");
		goto default_conf_out;
	}

	cfg->dongle_up = true;
default_conf_out:

	return err;

}

static s32 __brcmf_cfg80211_up(struct brcmf_if *ifp)
{
	set_bit(BRCMF_VIF_STATUS_READY, &ifp->vif->sme_state);

	return brcmf_config_dongle(ifp->drvr->config);
}

static s32 __brcmf_cfg80211_down(struct brcmf_if *ifp)
{
	struct brcmf_cfg80211_info *cfg = ifp->drvr->config;

	/* Disable all offloads started on brcmf_config_dongle before
	 * link is brought down.
	 */
	if (brcmf_feat_is_enabled(ifp, BRCMF_FEAT_OFFLOADS))
		brcmf_generic_offload_config(ifp, brcmf_offload_feat,
					     brcmf_offload_prof, true);

	/*
	 * While going down, if associated with AP disassociate
	 * from AP to save power
	 */
	if (check_vif_up(ifp->vif)) {
		brcmf_link_down(ifp->vif, WLAN_REASON_UNSPECIFIED, true);

		/* Make sure WPA_Supplicant receives all the event
		   generated due to DISASSOC call to the fw to keep
		   the state fw and WPA_Supplicant state consistent
		 */
		brcmf_delay(500);
		cfg->dongle_up = false;
	}

	brcmf_abort_scanning(cfg);
	clear_bit(BRCMF_VIF_STATUS_READY, &ifp->vif->sme_state);

	return 0;
}

s32 brcmf_cfg80211_up(struct net_device *ndev)
{
	struct brcmf_if *ifp = netdev_priv(ndev);
	struct brcmf_cfg80211_info *cfg = ifp->drvr->config;
	s32 err = 0;

	mutex_lock(&cfg->usr_sync);
	err = __brcmf_cfg80211_up(ifp);
	mutex_unlock(&cfg->usr_sync);

	return err;
}

s32 brcmf_cfg80211_down(struct net_device *ndev)
{
	struct brcmf_if *ifp = netdev_priv(ndev);
	struct brcmf_cfg80211_info *cfg = ifp->drvr->config;
	s32 err = 0;

	mutex_lock(&cfg->usr_sync);
	err = __brcmf_cfg80211_down(ifp);
	mutex_unlock(&cfg->usr_sync);

	return err;
}

enum nl80211_iftype brcmf_cfg80211_get_iftype(struct brcmf_if *ifp)
{
	struct wireless_dev *wdev = &ifp->vif->wdev;

	return wdev->iftype;
}

bool brcmf_get_vif_state_any(struct brcmf_cfg80211_info *cfg,
			     unsigned long state)
{
	struct brcmf_cfg80211_vif *vif;

	list_for_each_entry(vif, &cfg->vif_list, list) {
		if (test_bit(state, &vif->sme_state))
			return true;
	}
	return false;
}

static inline bool vif_event_equals(struct brcmf_cfg80211_vif_event *event,
				    u8 action)
{
	u8 evt_action;

	spin_lock(&event->vif_event_lock);
	evt_action = event->action;
	spin_unlock(&event->vif_event_lock);
	return evt_action == action;
}

void brcmf_cfg80211_arm_vif_event(struct brcmf_cfg80211_info *cfg,
				  struct brcmf_cfg80211_vif *vif)
{
	struct brcmf_cfg80211_vif_event *event = &cfg->vif_event;

	spin_lock(&event->vif_event_lock);
	event->vif = vif;
	event->action = 0;
	spin_unlock(&event->vif_event_lock);
}

bool brcmf_cfg80211_vif_event_armed(struct brcmf_cfg80211_info *cfg)
{
	struct brcmf_cfg80211_vif_event *event = &cfg->vif_event;
	bool armed;

	spin_lock(&event->vif_event_lock);
	armed = event->vif != NULL;
	spin_unlock(&event->vif_event_lock);

	return armed;
}

int brcmf_cfg80211_wait_vif_event(struct brcmf_cfg80211_info *cfg,
				  u8 action, ulong timeout)
{
	struct brcmf_cfg80211_vif_event *event = &cfg->vif_event;

	return wait_event_timeout(event->vif_wq,
				  vif_event_equals(event, action), timeout);
}

static s32 brcmf_translate_country_code(struct brcmf_pub *drvr, char alpha2[2],
					struct brcmf_fil_country_le *ccreq)
{
	struct brcmfmac_pd_cc *country_codes;
	struct brcmfmac_pd_cc_entry *cc;
	s32 found_index;
	int i;

	if ((alpha2[0] == ccreq->country_abbrev[0]) &&
	    (alpha2[1] == ccreq->country_abbrev[1])) {
		brcmf_dbg(INFO, "Country code already set\n");
		return -EAGAIN;
	}

	country_codes = drvr->settings->country_codes;
	if (!country_codes) {
		brcmf_dbg(INFO, "No country codes configured for device, using ISO3166 code and 0 rev\n");
		memset(ccreq, 0, sizeof(*ccreq));
		ccreq->country_abbrev[0] = alpha2[0];
		ccreq->country_abbrev[1] = alpha2[1];
		ccreq->ccode[0] = alpha2[0];
		ccreq->ccode[1] = alpha2[1];
		return 0;
	}

	found_index = -1;
	for (i = 0; i < country_codes->table_size; i++) {
		cc = &country_codes->table[i];
		if ((cc->iso3166[0] == '\0') && (found_index == -1))
			found_index = i;
		if ((cc->iso3166[0] == alpha2[0]) &&
		    (cc->iso3166[1] == alpha2[1])) {
			found_index = i;
			break;
		}
	}
	if (found_index == -1) {
		brcmf_dbg(INFO, "No country code match found\n");
		return -EINVAL;
	}
	memset(ccreq, 0, sizeof(*ccreq));
	ccreq->rev = cpu_to_le32(country_codes->table[found_index].rev);
	memcpy(ccreq->ccode, country_codes->table[found_index].cc,
	       BRCMF_COUNTRY_BUF_SZ);
	ccreq->country_abbrev[0] = alpha2[0];
	ccreq->country_abbrev[1] = alpha2[1];
	ccreq->country_abbrev[2] = 0;

	return 0;
}

static int
brcmf_parse_dump_obss(char *buf, struct brcmf_dump_survey *survey)
{
	int i;
	char *token;
	char delim[] = "\n ";
	unsigned long val;
	int err = 0;

	token = strsep(&buf, delim);
	while (token) {
		if (!strcmp(token, "OBSS")) {
			for (i = 0; i < OBSS_TOKEN_IDX; i++)
				token = strsep(&buf, delim);
			err = kstrtoul(token, 10, &val);
			survey->obss = val;
		}

		if (!strcmp(token, "IBSS")) {
			for (i = 0; i < IBSS_TOKEN_IDX; i++)
				token = strsep(&buf, delim);
			err = kstrtoul(token, 10, &val);
			survey->ibss = val;
		}

		if (!strcmp(token, "TXDur")) {
			for (i = 0; i < TX_TOKEN_IDX; i++)
				token = strsep(&buf, delim);
			err = kstrtoul(token, 10, &val);
			survey->tx = val;
		}

		if (!strcmp(token, "Category")) {
			for (i = 0; i < CTG_TOKEN_IDX; i++)
				token = strsep(&buf, delim);
			err = kstrtoul(token, 10, &val);
			survey->no_ctg = val;
		}

		if (!strcmp(token, "Packet")) {
			for (i = 0; i < PKT_TOKEN_IDX; i++)
				token = strsep(&buf, delim);
			err = kstrtoul(token, 10, &val);
			survey->no_pckt = val;
		}

		if (!strcmp(token, "Opp(time):")) {
			for (i = 0; i < IDLE_TOKEN_IDX; i++)
				token = strsep(&buf, delim);
			err = kstrtoul(token, 10, &val);
			survey->idle = val;
		}

		token = strsep(&buf, delim);

		if (err)
			return err;
	}

	return 0;
}

static int
brcmf_dump_obss(struct brcmf_if *ifp, struct cca_msrmnt_query req,
		struct brcmf_dump_survey *survey)
{
	struct cca_stats_n_flags *results;
	char *buf;
	int err;

	buf = kzalloc(sizeof(char) * BRCMF_DCMD_MEDLEN, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	memcpy(buf, &req, sizeof(struct cca_msrmnt_query));
	err = brcmf_fil_iovar_data_get(ifp, "dump_obss",
				       buf, BRCMF_DCMD_MEDLEN);
	if (err) {
		brcmf_err("dump_obss error (%d)\n", err);
		err = -EINVAL;
		goto exit;
	}
	results = (struct cca_stats_n_flags *)(buf);

	if (req.msrmnt_query)
		brcmf_parse_dump_obss(results->buf, survey);

exit:
	kfree(buf);
	return err;
}

static s32
cfg80211_set_channel(struct wiphy *wiphy, struct net_device *dev,
		     struct ieee80211_channel *chan,
		     enum nl80211_channel_type channel_type)
{
	u16 chspec = 0;
	int err = 0;
	struct brcmf_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct brcmf_if *ifp = netdev_priv(cfg_to_ndev(cfg));

	/* set_channel */
	chspec = channel_to_chanspec(&cfg->d11inf, chan);
	if (chspec != INVCHANSPEC) {
		err = brcmf_fil_iovar_int_set(ifp, "chanspec", chspec);
		if (err)
			err = -EINVAL;
	} else {
		brcmf_err("failed to convert host chanspec to fw chanspec\n");
		err = -EINVAL;
	}

	return err;
}

static struct ieee80211_channel *
brcmf_cfg80211_get_chan_by_idx(struct wiphy *wiphy, int idx)
{
	enum nl80211_band band;
	struct ieee80211_supported_band *wiphy_band = NULL;

	for (band = 0; band < NUM_NL80211_BANDS; band++) {
		/* FIXME SWLINUX-4979, the firmware cannot report the survey info of 6GHz,
		 * once the firmware can report it in someday.
		 * This condition can be removed.
		 */
		if (band == NL80211_BAND_6GHZ)
			continue;

		wiphy_band = wiphy->bands[band];
		if (!wiphy_band)
			continue;

		if (idx < wiphy_band->n_channels)
			return &wiphy_band->channels[idx];

		idx -= wiphy_band->n_channels;
	}

	return NULL;
}

static int
brcmf_cfg80211_dump_survey(struct wiphy *wiphy, struct net_device *ndev,
			   int idx, struct survey_info *info)
{
	struct brcmf_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct brcmf_if *ifp = netdev_priv(cfg_to_ndev(cfg));
	struct brcmf_dump_survey *survey;
	struct ieee80211_channel *chan;
	struct cca_msrmnt_query req;
	u32 noise;
	int err;

	brcmf_dbg(TRACE, "Enter: channel idx=%d\n", idx);

	if (!brcmf_is_apmode(ifp->vif))
		return -ENOENT;

	/* Do not run survey when VIF in CONNECTING / CONNECTED states */
	if ((test_bit(BRCMF_VIF_STATUS_CONNECTING, &ifp->vif->sme_state)) ||
	    (test_bit(BRCMF_VIF_STATUS_CONNECTED, &ifp->vif->sme_state))) {
		return -EBUSY;
	}

	/* Getting target channel */
	chan = brcmf_cfg80211_get_chan_by_idx(wiphy, idx);
	if (!chan) {
		brcmf_dbg(TRACE, "no more channel\n");
		return -ENOENT;
	}

	/* Setting current channel to the requested channel */
	err = cfg80211_set_channel(wiphy, ndev, chan, NL80211_CHAN_HT20);
	if (err) {
		info->channel = chan;
		info->filled = 0;
		return 0;
	}

	survey = kzalloc(sizeof(*survey), GFP_KERNEL);
	if (!survey)
		return -ENOMEM;

	/* Disable mpc */
	brcmf_set_mpc(ifp, 0);

	/* Set interface up, explicitly. */
	err = brcmf_fil_cmd_int_set(ifp, BRCMF_C_UP, 1);
	if (err) {
		brcmf_err("set interface up failed, err = %d\n", err);
		goto exit;
	}

	/* Get noise value */
	err = brcmf_fil_cmd_int_get(ifp, BRCMF_C_GET_PHY_NOISE, &noise);
	if (err) {
		brcmf_err("Get Phy Noise failed, use dummy value\n");
		noise = CHAN_NOISE_DUMMY;
	}


	/* Start Measurement for obss stats on current channel */
	req.msrmnt_query = 0;
	req.time_req = ACS_MSRMNT_DELAY;
	err = brcmf_dump_obss(ifp, req, survey);
	if (err)
		goto exit;

	/* Add 10 ms for IOVAR completion */
	msleep(ACS_MSRMNT_DELAY + 10);

	/* Issue IOVAR to collect measurement results */
	req.msrmnt_query = 1;
	err = brcmf_dump_obss(ifp, req, survey);
	if (err)
		goto exit;

	info->channel = chan;
	info->noise = noise;
	info->time = ACS_MSRMNT_DELAY;
	info->time_busy = ACS_MSRMNT_DELAY - survey->idle;
	info->time_rx = survey->obss + survey->ibss + survey->no_ctg +
		survey->no_pckt;
	info->time_tx = survey->tx;
	info->filled = SURVEY_INFO_NOISE_DBM | SURVEY_INFO_TIME |
		SURVEY_INFO_TIME_BUSY | SURVEY_INFO_TIME_RX |
		SURVEY_INFO_TIME_TX;

	brcmf_dbg(INFO, "OBSS dump: channel %d: survey duration %d\n",
		  ieee80211_frequency_to_channel(chan->center_freq),
		  ACS_MSRMNT_DELAY);
	brcmf_dbg(INFO, "noise(%d) busy(%llu) rx(%llu) tx(%llu)\n",
		  info->noise, info->time_busy, info->time_rx, info->time_tx);

exit:
	if (!brcmf_is_apmode(ifp->vif))
		brcmf_set_mpc(ifp, 1);
	kfree(survey);
	return err;
}

static int
brcmf_cfg80211_dump_survey_2(struct wiphy *wiphy, struct net_device *ndev,
			   int idx, struct survey_info *info)
{
	struct brcmf_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct brcmf_if *ifp = netdev_priv(cfg_to_ndev(cfg));
	struct ieee80211_channel *chan;
	struct cca_survey_req *survey = NULL;
	struct cca_survey  *secs;
	struct cfg80211_chan_def chandef;
	struct wireless_dev *wdev;
	int err = 0;
	u32 noise;

	brcmf_dbg(TRACE, "Enter: channel idx=%d\n", idx);

	/* Do not run survey when VIF in CONNECTING / CONNECTED states */
	if ((test_bit(BRCMF_VIF_STATUS_CONNECTING, &ifp->vif->sme_state))) {
		return -EBUSY;
	}

	/* Getting target channel */
	chan = brcmf_cfg80211_get_chan_by_idx(wiphy, idx);
	if (!chan) {
		brcmf_dbg(TRACE, "no more channel\n");
		return -ENOENT;
	}

	/* Set interface up, explicitly. */
	err = brcmf_fil_cmd_int_set(ifp, BRCMF_C_UP, 1);
	if (err) {
		brcmf_err("set interface up failed, err = %d\n", err);
		return err;
	}

	/* Get noise value */
	err = brcmf_fil_cmd_int_get(ifp, BRCMF_C_GET_PHY_NOISE, &noise);
	if (err) {
		brcmf_err("Get Phy Noise failed, use dummy value\n");
		noise = CHAN_NOISE_DUMMY;
	}

	survey = kzalloc(sizeof(struct cca_survey_req), GFP_KERNEL);
	if (!survey)
		return -ENOMEM;

	survey->chanspec = channel_to_chanspec(&cfg->d11inf, chan);
	err = brcmf_fil_iovar_data_get(ifp, "cca_survey_dump",
				       survey, sizeof(struct cca_survey_req));
	if (err) {
		brcmf_err("cca_survey_dump error (%d)\n", err);
		err = -EINVAL;
		goto exit;
	}

	secs = &survey->secs[0];

	info->channel = chan;
	info->noise = noise;
	info->time = secs->usecs;
	info->time_busy = secs->ibss + secs->txdur + secs->obss
	       + secs->noctg+secs->nopkt;
	info->time_rx = secs->obss + secs->ibss + secs->noctg
	       + secs->nopkt;
	info->time_tx = secs->txdur;
	info->time_bss_rx = secs->ibss;

	info->filled = SURVEY_INFO_NOISE_DBM | SURVEY_INFO_TIME |
		SURVEY_INFO_TIME_BUSY | SURVEY_INFO_TIME_RX |
		SURVEY_INFO_TIME_TX | SURVEY_INFO_TIME_BSS_RX;

	wdev = ndev->ieee80211_ptr;
	memset(&chandef, 0, sizeof(chandef));
	err = brcmf_cfg80211_get_channel(wiphy, wdev, 0, &chandef);
	if (unlikely(err)) {
		brcmf_err("Get chandef error: %d \n", err);
		err = -EINVAL;
		goto exit;
	}
	if (chandef.chan->center_freq == chan->center_freq) {
		info->filled = info->filled | SURVEY_INFO_IN_USE;
	}

	brcmf_dbg(INFO, "survey dump: channel %d: survey duration %llu\n",
		  ieee80211_frequency_to_channel(chan->center_freq),
		  info->time);
	brcmf_dbg(INFO, "noise(%d) busy(%llu) rx(%llu) tx(%llu)\n",
		  info->noise, info->time_busy, info->time_rx, info->time_tx);

exit:
	kfree(survey);
	return err;
}

static void brcmf_cfg80211_reg_notifier(struct wiphy *wiphy,
					struct regulatory_request *req)
{
	struct brcmf_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct brcmf_if *ifp = brcmf_get_ifp(cfg->pub, 0);
	struct brcmf_pub *drvr = cfg->pub;
	struct brcmf_fil_country_le ccreq;
	s32 err;
	int i;

	/* The country code gets set to "00" by default at boot, ignore */
	if (req->alpha2[0] == '0' && req->alpha2[1] == '0')
		return;

	/* ignore non-ISO3166 country codes */
	for (i = 0; i < 2; i++)
		if (req->alpha2[i] < 'A' || req->alpha2[i] > 'Z') {
			bphy_err(drvr, "not an ISO3166 code (0x%02x 0x%02x)\n",
				 req->alpha2[0], req->alpha2[1]);
			return;
		}

	brcmf_dbg(INFO, "Enter: initiator=%d, alpha=%c%c\n", req->initiator,
		  req->alpha2[0], req->alpha2[1]);

	err = brcmf_fil_iovar_data_get(ifp, "country", &ccreq, sizeof(ccreq));
	if (err) {
		bphy_err(drvr, "Country code iovar returned err = %d\n", err);
		return;
	}

	err = brcmf_translate_country_code(ifp->drvr, req->alpha2, &ccreq);
	if (err)
		return;

	/* Abort on-going scan before changing ccode */
	brcmf_abort_scanning(cfg);

	err = brcmf_fil_iovar_data_set(ifp, "country", &ccreq, sizeof(ccreq));
	if (err) {
		bphy_err(drvr, "Firmware rejected country setting\n");
		return;
	}
	brcmf_setup_wiphybands(cfg);
}

static void brcmf_free_wiphy(struct wiphy *wiphy)
{
	int i;

	if (!wiphy)
		return;

	if (wiphy->iface_combinations) {
		for (i = 0; i < wiphy->n_iface_combinations; i++)
			kfree(wiphy->iface_combinations[i].limits);
	}
	kfree(wiphy->iface_combinations);
	if (wiphy->bands[NL80211_BAND_2GHZ]) {
		kfree(wiphy->bands[NL80211_BAND_2GHZ]->channels);
		kfree(wiphy->bands[NL80211_BAND_2GHZ]);
	}
	if (wiphy->bands[NL80211_BAND_5GHZ]) {
		kfree(wiphy->bands[NL80211_BAND_5GHZ]->channels);
		kfree(wiphy->bands[NL80211_BAND_5GHZ]);
	}
	if (wiphy->bands[NL80211_BAND_6GHZ]) {
		kfree(wiphy->bands[NL80211_BAND_6GHZ]->channels);
		kfree(wiphy->bands[NL80211_BAND_6GHZ]);
	}

#if IS_ENABLED(CONFIG_PM)
	if (wiphy->wowlan != &brcmf_wowlan_support)
		kfree(wiphy->wowlan);
#endif
}

struct brcmf_cfg80211_info *brcmf_cfg80211_attach(struct brcmf_pub *drvr,
						  struct cfg80211_ops *ops,
						  bool p2pdev_forced)
{
	struct wiphy *wiphy = drvr->wiphy;
	struct net_device *ndev = brcmf_get_ifp(drvr, 0)->ndev;
	struct brcmf_cfg80211_info *cfg;
	struct brcmf_cfg80211_vif *vif;
	struct brcmf_if *ifp;
	s32 err = 0;
	s32 io_type;
	u16 *cap = NULL;

	if (!ndev) {
		bphy_err(drvr, "ndev is invalid\n");
		return NULL;
	}

	cfg = kzalloc(sizeof(*cfg), GFP_KERNEL);
	if (!cfg) {
		bphy_err(drvr, "Could not allocate wiphy device\n");
		return NULL;
	}

	cfg->wiphy = wiphy;
	cfg->pub = drvr;
	cfg->pm_state = BRCMF_CFG80211_PM_STATE_RESUMED;
	cfg->num_softap = 0;
	cfg->mchan_conf = BRCMF_MCHAN_CONF_DEFAULT;
	init_vif_event(&cfg->vif_event);
	INIT_LIST_HEAD(&cfg->vif_list);

	vif = brcmf_alloc_vif(cfg, NL80211_IFTYPE_STATION);
	if (IS_ERR(vif))
		goto wiphy_out;

	ifp = netdev_priv(ndev);
	vif->ifp = ifp;
	vif->wdev.netdev = ndev;
	ndev->ieee80211_ptr = &vif->wdev;
	SET_NETDEV_DEV(ndev, wiphy_dev(cfg->wiphy));

	err = wl_init_priv(cfg);
	if (err) {
		bphy_err(drvr, "Failed to init iwm_priv (%d)\n", err);
		brcmf_free_vif(vif);
		goto wiphy_out;
	}
	ifp->vif = vif;

	/* determine d11 io type before wiphy setup */
	err = brcmf_fil_cmd_int_get(ifp, BRCMF_C_GET_VERSION, &io_type);
	if (err) {
		bphy_err(drvr, "Failed to get D11 version (%d)\n", err);
		goto priv_out;
	}
	cfg->d11inf.io_type = (u8)io_type;
	brcmu_d11_attach(&cfg->d11inf);

	/* regulatory notifer below needs access to cfg so
	 * assign it now.
	 */
	drvr->config = cfg;

	err = brcmf_setup_wiphy(wiphy, ifp);
	if (err < 0)
		goto priv_out;

	brcmf_dbg(INFO, "Registering custom regulatory\n");
	wiphy->reg_notifier = brcmf_cfg80211_reg_notifier;
	wiphy->regulatory_flags |= REGULATORY_CUSTOM_REG;
	wiphy->regulatory_flags |= REGULATORY_COUNTRY_IE_IGNORE;
	wiphy_apply_custom_regulatory(wiphy, &brcmf_regdom);

	/* firmware defaults to 40MHz disabled in 2G band. We signal
	 * cfg80211 here that we do and have it decide we can enable
	 * it. But first check if device does support 2G operation.
	 */
	if (wiphy->bands[NL80211_BAND_2GHZ]) {
		cap = &wiphy->bands[NL80211_BAND_2GHZ]->ht_cap.cap;
		*cap |= IEEE80211_HT_CAP_SUP_WIDTH_20_40;
	}
#ifdef CONFIG_PM
	if (brcmf_feat_is_enabled(ifp, BRCMF_FEAT_WOWL_GTK))
		ops->set_rekey_data = brcmf_cfg80211_set_rekey_data;
#endif
	/* if the firmware has GTKO cap,
	 * user space can use NL80211_CMD_SET_REKEY_OFFLOAD command to pass gtk data.
	 */
	if (brcmf_feat_is_enabled(ifp, BRCMF_FEAT_GTKO))
		ops->set_rekey_data = brcmf_cfg80211_set_rekey_data;

	if (brcmf_feat_is_enabled(ifp, BRCMF_FEAT_DUMP_OBSS))
		ops->dump_survey = brcmf_cfg80211_dump_survey;
	else if (brcmf_feat_is_enabled(ifp, BRCMF_FEAT_SURVEY_DUMP))
		ops->dump_survey = brcmf_cfg80211_dump_survey_2;
	else
		ops->dump_survey = NULL;

	err = brcmf_setup_wiphybands(cfg);
	if (err) {
		bphy_err(drvr, "Setting wiphy bands failed (%d)\n", err);
		goto wiphy_unreg_out;
	}

	err = wiphy_register(wiphy);
	if (err < 0) {
		bphy_err(drvr, "Could not register wiphy device (%d)\n", err);
		goto priv_out;
	}

	/* If cfg80211 didn't disable 40MHz HT CAP in wiphy_register(),
	 * setup 40MHz in 2GHz band and enable OBSS scanning.
	 */
	if (cap && (*cap & IEEE80211_HT_CAP_SUP_WIDTH_20_40)) {
		err = brcmf_enable_bw40_2g(cfg);
		if (!err)
			err = brcmf_fil_iovar_int_set(ifp, "obss_coex",
						      BRCMF_OBSS_COEX_AUTO);
		else
			*cap &= ~IEEE80211_HT_CAP_SUP_WIDTH_20_40;
	}

	err = brcmf_fweh_activate_events(ifp);
	if (err) {
		bphy_err(drvr, "FWEH activation failed (%d)\n", err);
		goto wiphy_unreg_out;
	}

	err = brcmf_p2p_attach(cfg, p2pdev_forced);
	if (err) {
		bphy_err(drvr, "P2P initialisation failed (%d)\n", err);
		goto wiphy_unreg_out;
	}
	err = brcmf_btcoex_attach(cfg);
	if (err) {
		bphy_err(drvr, "BT-coex initialisation failed (%d)\n", err);
		brcmf_p2p_detach(&cfg->p2p);
		goto wiphy_unreg_out;
	}
	err = brcmf_pno_attach(cfg);
	if (err) {
		bphy_err(drvr, "PNO initialisation failed (%d)\n", err);
		brcmf_btcoex_detach(cfg);
		brcmf_p2p_detach(&cfg->p2p);
		goto wiphy_unreg_out;
	}

	if (brcmf_feat_is_enabled(ifp, BRCMF_FEAT_TDLS)) {
		err = brcmf_fil_iovar_int_set(ifp, "tdls_enable", 1);
		if (err) {
			brcmf_dbg(INFO, "TDLS not enabled (%d)\n", err);
			wiphy->flags &= ~WIPHY_FLAG_SUPPORTS_TDLS;
		} else {
			brcmf_fweh_register(cfg->pub, BRCMF_E_TDLS_PEER_EVENT,
					    brcmf_notify_tdls_peer_event);
		}
	}

	err = ifx_vndr_cmdstr_hashtbl_init();
	if (err) {
		bphy_err(drvr, "vendor_cmd_hashtable initialisation failed (%d)\n", err);
		goto detach;
	}
	/* (re-) activate FWEH event handling */
	err = brcmf_fweh_activate_events(ifp);
	if (err) {
		bphy_err(drvr, "FWEH activation failed (%d)\n", err);
		goto detach;
	}

	/* Fill in some of the advertised nl80211 supported features */
	if (brcmf_feat_is_enabled(ifp, BRCMF_FEAT_SCAN_RANDOM_MAC)) {
		wiphy->features |= NL80211_FEATURE_SCHED_SCAN_RANDOM_MAC_ADDR;
#ifdef CONFIG_PM
		if (wiphy->wowlan &&
		    wiphy->wowlan->flags & WIPHY_WOWLAN_NET_DETECT)
			wiphy->features |= NL80211_FEATURE_ND_RANDOM_MAC_ADDR;
#endif
	}

	return cfg;

detach:
	brcmf_pno_detach(cfg);
	brcmf_btcoex_detach(cfg);
	brcmf_p2p_detach(&cfg->p2p);
wiphy_unreg_out:
	wiphy_unregister(cfg->wiphy);
priv_out:
	wl_deinit_priv(cfg);
	brcmf_free_vif(vif);
	ifp->vif = NULL;
wiphy_out:
	brcmf_free_wiphy(wiphy);
	kfree(cfg);
	return NULL;
}

void brcmf_cfg80211_detach(struct brcmf_cfg80211_info *cfg)
{
	if (!cfg)
		return;

	ifx_vndr_cmdstr_hashtbl_deinit();
	brcmf_pno_detach(cfg);
	brcmf_btcoex_detach(cfg);
	wiphy_unregister(cfg->wiphy);
	wl_deinit_priv(cfg);
	cancel_work_sync(&cfg->escan_timeout_work);
	brcmf_free_wiphy(cfg->wiphy);
	kfree(cfg);
}
