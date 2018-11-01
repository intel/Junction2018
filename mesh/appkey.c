/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2017-2018  Intel Corporation. All rights reserved.
 *
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ell/ell.h>

#include "mesh/mesh-defs.h"

#include "mesh/mesh.h"
#include "mesh/node.h"
#include "mesh/net.h"
#include "mesh/crypto.h"
#include "mesh/display.h"
#include "mesh/model.h"
#include "mesh/storage.h"
#include "mesh/appkey.h"

struct mesh_app_key {
	struct l_queue *replay_cache;
	uint16_t net_idx;
	uint16_t app_idx;
	uint8_t key[16];
	uint8_t key_id;
	uint8_t new_key[16];
	uint8_t new_key_id;
};

struct mesh_msg {
	uint32_t iv_index;
	uint32_t seq;
	uint16_t src;
};

struct mod_decrypt {
	const uint8_t *data;
	uint8_t *out;
	struct mesh_app_key *key;
	uint8_t *virt;
	uint32_t seq;
	uint32_t iv_idx;
	uint16_t src;
	uint16_t dst;
	uint16_t idx;
	uint16_t size;
	uint16_t virt_size;
	uint8_t key_id;
	bool szmict;
	bool decrypted;
};

static bool match_key_index(const void *a, const void *b)
{
	const struct mesh_app_key *key = a;
	uint16_t idx = L_PTR_TO_UINT(b);

	return key->app_idx == idx;
}

static bool match_replay_cache(const void *a, const void *b)
{
	const struct mesh_msg *msg = a;
	uint16_t src = L_PTR_TO_UINT(b);

	return src == msg->src;
}

static bool clean_old_iv_index(void *a, void *b)
{
	struct mesh_msg *msg = a;
	uint32_t iv_index = L_PTR_TO_UINT(b);

	if (iv_index < 2)
		return false;

	if (msg->iv_index < iv_index - 1) {
		l_free(msg);
		return true;
	}

	return false;
}

static void packet_decrypt(void *a, void *b)
{
	struct mesh_app_key *key = a;
	struct mod_decrypt *dec = b;

	l_debug("model.c - app_packet_decrypt");
	if (dec->decrypted)
		return;

	if (key->key_id != dec->key_id &&
			key->new_key_id != dec->key_id)
		return;

	dec->key = key;

	if (key->key_id == dec->key_id) {
		dec->decrypted = mesh_crypto_payload_decrypt(dec->virt,
				dec->virt_size, dec->data, dec->size,
				dec->szmict, dec->src, dec->dst, dec->key_id,
				dec->seq, dec->iv_idx, dec->out, key->key);
		if (dec->decrypted)
			print_packet("Used App Key", dec->key->key, 16);
		else
			print_packet("Failed with App Key", dec->key->key, 16);
	}

	if (!dec->decrypted && key->new_key_id == dec->key_id) {
		dec->decrypted = mesh_crypto_payload_decrypt(dec->virt,
				dec->virt_size, dec->data, dec->size,
				dec->szmict, dec->src, dec->dst, dec->key_id,
				dec->seq, dec->iv_idx, dec->out, key->new_key);
		if (dec->decrypted)
			print_packet("Used App Key", dec->key->new_key, 16);
		else
			print_packet("Failed with App Key",
							dec->key->new_key, 16);
	}

	if (dec->decrypted)
		dec->idx = key->app_idx;
}

int appkey_packet_decrypt(struct mesh_net *net, bool szmict, uint32_t seq,
				uint32_t iv_index, uint16_t src,
				uint16_t dst, uint8_t *virt, uint16_t virt_size,
				uint8_t key_id, const uint8_t *data,
				uint16_t data_size, uint8_t *out)
{
	struct l_queue *app_keys;

	struct mod_decrypt decrypt = {
		.src = src,
		.dst = dst,
		.seq = seq,
		.data = data,
		.out = out,
		.size = data_size,
		.key_id = key_id,
		.iv_idx = iv_index,
		.virt = virt,
		.virt_size = virt_size,
		.szmict = szmict,
		.decrypted = false,
	};

	app_keys = mesh_net_get_app_keys(net);
	if (!app_keys)
		return -1;

	l_queue_foreach(app_keys, packet_decrypt, &decrypt);

	return decrypt.decrypted ? decrypt.idx : -1;
}

bool appkey_msg_in_replay_cache(struct mesh_net *net, uint16_t idx,
				uint16_t src, uint16_t crpl, uint32_t seq,
				uint32_t iv_index)
{
	struct mesh_app_key *key;
	struct mesh_msg *msg;
	struct l_queue *app_keys;

	app_keys = mesh_net_get_app_keys(net);
	if (!app_keys)
		return false;

	l_debug("Test Replay src: %4.4x seq: %6.6x iv: %8.8x",
						src, seq, iv_index);

	key = l_queue_find(app_keys, match_key_index, L_UINT_TO_PTR(idx));

	if (!key)
		return false;

	msg = l_queue_find(key->replay_cache, match_replay_cache,
						L_UINT_TO_PTR(src));

	if (msg) {
		if (iv_index > msg->iv_index) {
			msg->seq = seq;
			msg->iv_index = iv_index;
			return false;
		}

		if (seq < msg->seq) {
			l_info("Ignoring packet with lower sequence number");
			return true;
		}

		if (seq == msg->seq) {
			l_info("Message already processed (duplicate)");
			return true;
		}

		msg->seq = seq;

		return false;
	}

	l_debug("New Entry for %4.4x", src);
	if (key->replay_cache == NULL)
		key->replay_cache = l_queue_new();

	/* Replay Cache is fixed sized */
	if (l_queue_length(key->replay_cache) >= crpl) {
		int ret = l_queue_foreach_remove(key->replay_cache,
				clean_old_iv_index, L_UINT_TO_PTR(iv_index));

		if (!ret)
			return true;
	}

	msg = l_new(struct mesh_msg, 1);
	msg->src = src;
	msg->seq = seq;
	msg->iv_index = iv_index;
	l_queue_push_head(key->replay_cache, msg);

	return false;
}

static struct mesh_app_key *app_key_new(void)
{
	struct mesh_app_key *key = l_new(struct mesh_app_key, 1);

	key->new_key_id = 0xFF;
	key->replay_cache = l_queue_new();
	return key;
}

static bool set_key(struct mesh_app_key *key, uint16_t app_idx,
			const uint8_t *key_value, bool is_new)
{
	uint8_t key_id;

	if (!mesh_crypto_k4(key_value, &key_id))
		return false;

	key_id = KEY_ID_AKF | (key_id << KEY_AID_SHIFT);
	if (!is_new)
		key->key_id = key_id;
	else
		key->new_key_id = key_id;

	memcpy(is_new ? key->new_key : key->key, key_value, 16);

	return true;
}

void appkey_key_free(void *data)
{
	struct mesh_app_key *key = data;

	if (!key)
		return;

	l_queue_destroy(key->replay_cache, l_free);
	l_free(key);
}

bool appkey_key_init(struct mesh_net *net, uint16_t net_idx, uint16_t app_idx,
				uint8_t *key_value, uint8_t *new_key_value)
{
	struct mesh_app_key *key;
	struct l_queue *app_keys;

	if (net_idx > MAX_KEY_IDX || app_idx > MAX_KEY_IDX)
		return false;

	app_keys = mesh_net_get_app_keys(net);
	if (!app_keys)
		return NULL;

	key = app_key_new();
	if (!key)
		return false;

	if (!mesh_net_have_key(net, net_idx))
		return false;

	key->net_idx = net_idx;
	key->app_idx = app_idx;

	if (key_value && !set_key(key, app_idx, key_value, false))
		return false;

	if (new_key_value && !set_key(key, app_idx, new_key_value, true))
		return false;

	l_queue_push_tail(app_keys, key);

	return true;
}

const uint8_t *appkey_get_key(struct mesh_net *net, uint16_t app_idx,
							uint8_t *key_id)
{
	struct mesh_app_key *app_key;
	uint8_t phase;
	struct l_queue *app_keys;

	app_keys = mesh_net_get_app_keys(net);
	if (!app_keys)
		return NULL;

	app_key = l_queue_find(app_keys, match_key_index,
							L_UINT_TO_PTR(app_idx));
	if (!app_key)
		return NULL;

	if (mesh_net_key_refresh_phase_get(net, app_key->net_idx, &phase) !=
							MESH_STATUS_SUCCESS)
		return NULL;

	if (phase != KEY_REFRESH_PHASE_TWO) {
		*key_id = app_key->key_id;
		return app_key->key;
	}

	if (app_key->new_key_id == NET_NID_INVALID)
		return NULL;

	*key_id = app_key->new_key_id;
	return app_key->new_key;
}

bool appkey_have_key(struct mesh_net *net, uint16_t app_idx)
{
	struct mesh_app_key *key;
	struct l_queue *app_keys;

	app_keys = mesh_net_get_app_keys(net);
	if (!app_keys)
		return false;

	key = l_queue_find(app_keys, match_key_index, L_UINT_TO_PTR(app_idx));

	if (!key)
		return false;
	else
		return true;
}

int appkey_key_add(struct mesh_net *net, uint16_t net_idx, uint16_t app_idx,
					const uint8_t *new_key, bool update)
{
	struct mesh_app_key *key;
	struct l_queue *app_keys;
	uint8_t phase = KEY_REFRESH_PHASE_NONE;

	app_keys = mesh_net_get_app_keys(net);
	if (!app_keys)
		return MESH_STATUS_INSUFF_RESOURCES;

	key = l_queue_find(app_keys, match_key_index, L_UINT_TO_PTR(app_idx));

	if (!mesh_net_have_key(net, net_idx) ||
					(update && key->net_idx != net_idx))
		return MESH_STATUS_INVALID_NETKEY;

	if (update && !key)
		return MESH_STATUS_INVALID_APPKEY;

	mesh_net_key_refresh_phase_get(net, net_idx, &phase);
	if (update && phase != KEY_REFRESH_PHASE_ONE)
		return MESH_STATUS_CANNOT_UPDATE;

	if (key) {
		if (memcmp(new_key, key->key, 16) == 0)
			return MESH_STATUS_SUCCESS;

		if (!update) {
			l_info("Failed to add key: index already stored %x",
				(net_idx << 16) | app_idx);
			return MESH_STATUS_IDX_ALREADY_STORED;
		}
	}

	if (!key) {
		if (l_queue_length(app_keys) <= MAX_APP_KEYS)
			return MESH_STATUS_INSUFF_RESOURCES;

		key = app_key_new();
		if (!key)
			return MESH_STATUS_INSUFF_RESOURCES;

		if (!set_key(key, app_idx, new_key, false)) {
			appkey_key_free(key);
			return MESH_STATUS_INSUFF_RESOURCES;
		}

		if (!storage_local_app_key_add(net, net_idx, app_idx, new_key,
								false)) {
			appkey_key_free(key);
			return MESH_STATUS_STORAGE_FAIL;
		}

		key->net_idx = net_idx;
		key->app_idx = app_idx;
		l_queue_push_tail(app_keys, key);
	} else {
		if (!set_key(key, app_idx, new_key, true))
			return MESH_STATUS_INSUFF_RESOURCES;

		if (!storage_local_app_key_add(net, net_idx, app_idx, new_key,
								true))
			return MESH_STATUS_STORAGE_FAIL;
	}

	l_queue_clear(key->replay_cache, l_free);

	return MESH_STATUS_SUCCESS;
}

int appkey_key_delete(struct mesh_net *net, uint16_t net_idx,
							uint16_t app_idx)
{
	struct mesh_app_key *key;
	struct l_queue *app_keys;

	app_keys = mesh_net_get_app_keys(net);
	if (!app_keys)
		return MESH_STATUS_INVALID_APPKEY;

	key = l_queue_find(app_keys, match_key_index, L_UINT_TO_PTR(app_idx));

	if (!key)
		return MESH_STATUS_INVALID_APPKEY;

	if (key->net_idx != net_idx)
		return MESH_STATUS_INVALID_NETKEY;

	node_app_key_delete(net, mesh_net_get_address(net), net_idx, app_idx);

	l_queue_remove(app_keys, key);
	appkey_key_free(key);

	if (!storage_local_app_key_del(net, net_idx, app_idx))
		return MESH_STATUS_STORAGE_FAIL;

	return MESH_STATUS_SUCCESS;
}

void appkey_delete_bound_keys(struct mesh_net *net, uint16_t net_idx)
{
	const struct l_queue_entry *entry;
	struct l_queue *app_keys;

	app_keys = mesh_net_get_app_keys(net);
	if (!app_keys)
		return;

	entry = l_queue_get_entries(app_keys);

	for (; entry; entry = entry->next) {
		struct mesh_app_key *key = entry->data;

		appkey_key_delete(net, net_idx, key->app_idx);
	}
}

uint8_t appkey_list(struct mesh_net *net, uint16_t net_idx, uint8_t *buf,
					uint16_t buf_size, uint16_t *size)
{
	const struct l_queue_entry *entry;
	uint32_t idx_pair;
	int i;
	uint16_t datalen;
	struct l_queue *app_keys;

	*size = 0;

	app_keys = mesh_net_get_app_keys(net);
	if (!app_keys || l_queue_isempty(app_keys))
		return MESH_STATUS_SUCCESS;

	idx_pair = 0;
	i = 0;
	datalen = 0;
	entry = l_queue_get_entries(app_keys);

	for (; entry; entry = entry->next) {
		struct mesh_app_key *key = entry->data;

		if (net_idx != key->net_idx)
			continue;

		if (!(i & 0x1)) {
			idx_pair = key->app_idx;
		} else {
			idx_pair <<= 12;
			idx_pair += key->app_idx;
			/* Unlikely, but check for overflow*/
			if ((datalen + 3) > buf_size) {
				l_warn("Appkey list too large");
				goto done;
			}
			l_put_le32(idx_pair, buf);
			buf += 3;
			datalen += 3;
		}
		i++;
	}

	/* Process the last app key if present */
	if (i & 0x1 && ((datalen + 2) <= buf_size)) {
		l_put_le16(idx_pair, buf);
		datalen += 2;
	}

done:
	*size = datalen;

	return MESH_STATUS_SUCCESS;
}
