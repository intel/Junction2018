/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2018  Intel Corporation. All rights reserved.
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

#include <unistd.h>
#include <stdio.h>
#include <sys/time.h>
#include <ell/ell.h>

#include "mesh/mesh-defs.h"

#include "mesh/mesh.h"
#include "mesh/node.h"
#include "mesh/net.h"
#include "mesh/appkey.h"
#include "mesh/model.h"
#include "mesh/storage.h"

#include "mesh/cfgmod.h"

#define CFG_MAX_MSG_LEN 380

static void send_pub_status(struct mesh_net *net, uint16_t src, uint16_t dst,
			uint8_t status, uint16_t ele_addr, uint16_t pub_addr,
			uint32_t mod_id, uint16_t idx, bool cred_flag,
			uint8_t ttl, uint8_t period, uint8_t retransmit)
{
	uint8_t msg[16];
	size_t n;

	n = mesh_model_opcode_set(OP_CONFIG_MODEL_PUB_STATUS, msg);
	msg[n++] = status;
	l_put_le16(ele_addr, msg + n);
	n += 2;
	l_put_le16(pub_addr, msg + n);
	n += 2;
	idx |= cred_flag ? CREDFLAG_MASK : 0;
	l_put_le16(idx, msg + n);
	n += 2;
	msg[n++] = ttl;
	msg[n++] = period;
	msg[n++] = retransmit;
	if (mod_id < 0x10000 || mod_id > VENDOR_ID_MASK) {
		l_put_le16(mod_id, msg + n);
		n += 2;
	} else {
		l_put_le16(mod_id >> 16, msg + n);
		n += 2;
		l_put_le16(mod_id, msg + n);
		n += 2;
	}

	mesh_model_send(net, dst, src,
			APP_IDX_DEV, DEFAULT_TTL, msg, n);
}

static bool config_pub_get(struct mesh_net *net, uint16_t src, uint16_t dst,
					const uint8_t *pkt, uint16_t size)
{
	uint32_t mod_id;
	uint16_t ele_addr;
	int ele_idx;
	struct mesh_model_pub *pub = NULL;
	int status;

	if (size == 4) {
		mod_id = l_get_le16(pkt + 2);
		mod_id |= VENDOR_ID_MASK;
	} else if (size == 6) {
		mod_id = l_get_le16(pkt + 2) << 16;
		mod_id |= l_get_le16(pkt + 4);
	} else
		return false;

	ele_addr = l_get_le16(pkt);
	ele_idx = node_get_element_idx(mesh_net_local_node_get(net), ele_addr);

	if (ele_idx >= 0)
		pub = mesh_model_pub_get(net, ele_idx, mod_id, &status);
	else
		status = MESH_STATUS_INVALID_ADDRESS;

	if (pub && status == MESH_STATUS_SUCCESS)
		send_pub_status(net, src, dst, status, ele_addr, pub->addr,
				mod_id, pub->idx, pub->credential, pub->ttl,
						pub->period, pub->retransmit);
	else
		send_pub_status(net, src, dst, status, ele_addr, 0, mod_id,
								0, 0, 0, 0, 0);
	return true;
}

static bool config_pub_set(struct mesh_net *net, uint16_t src, uint16_t dst,
					const uint8_t *pkt, uint16_t size,
					bool unreliable)
{
	uint32_t mod_id;
	uint16_t ele_addr, idx, ota = 0;
	const uint8_t *pub_addr;
	uint16_t test_addr;
	uint8_t ttl, period;
	uint8_t retransmit;
	int status;
	bool cred_flag, b_virt = false;

	switch (size) {
	default:
		return false;

	case 11:
		idx = l_get_le16(pkt + 4);
		ttl = pkt[6];
		period = pkt[7];
		retransmit = pkt[8];
		mod_id = l_get_le16(pkt + 9);
		mod_id |= VENDOR_ID_MASK;
		break;

	case 13:
		idx = l_get_le16(pkt + 4);
		ttl = pkt[6];
		period = pkt[7];
		retransmit = pkt[8];
		mod_id = l_get_le16(pkt + 9) << 16;
		mod_id |= l_get_le16(pkt + 11);
		break;

	case 25:
		b_virt = true;
		idx = l_get_le16(pkt + 18);
		ttl = pkt[20];
		period = pkt[21];
		retransmit = pkt[22];
		mod_id = l_get_le16(pkt + 23);
		mod_id |= VENDOR_ID_MASK;
		break;

	case 27:
		b_virt = true;
		idx = l_get_le16(pkt + 18);
		ttl = pkt[20];
		period = pkt[21];
		retransmit = pkt[22];
		mod_id = l_get_le16(pkt + 23) << 16;
		mod_id |= l_get_le16(pkt + 25);
		break;
	}
	ele_addr = l_get_le16(pkt);
	pub_addr = pkt + 2;

	/* Doesn't accept out-of-range TTLs */
	if (ttl > TTL_MASK && ttl != DEFAULT_TTL)
		return false;

	/* Get cred_flag */
	cred_flag = !!(CREDFLAG_MASK & idx);

	/* Ignore non-IDX bits */
	idx &= APP_IDX_MASK;

	/* Doesn't accept virtual seeming addresses */
	test_addr = l_get_le16(pub_addr);
	if (!b_virt && test_addr > 0x7fff && test_addr < 0xc000)
		return false;

	status = mesh_model_pub_set(net, ele_addr, mod_id, pub_addr, idx,
					cred_flag, ttl, period, retransmit,
					b_virt, &ota);

	l_info("pub_set: status %d, ea %4.4x, ota: %4.4x, mod: %x, idx: %3.3x",
					status, ele_addr, ota, mod_id, idx);

	if (IS_UNASSIGNED(ota) && !b_virt)
		ttl = period = idx = 0;

	if (status >= 0 && !unreliable)
		send_pub_status(net, src, dst, status, ele_addr, ota,
				mod_id, idx, cred_flag, ttl, period,
				retransmit);
	return true;
}

static void send_sub_status(struct mesh_net *net, uint16_t src, uint16_t dst,
					uint8_t status, uint16_t ele_addr,
					uint16_t addr, uint32_t mod)
{
	uint8_t msg[12];
	int n = mesh_model_opcode_set(OP_CONFIG_MODEL_SUB_STATUS, msg);

	msg[n++] = status;
	l_put_le16(ele_addr, msg + n);
	n += 2;
	l_put_le16(addr, msg + n);
	n += 2;
	if (mod >= 0x10000 && mod < VENDOR_ID_MASK) {
		l_put_le16(mod >> 16, msg + n);
		l_put_le16(mod, msg + n + 2);
		n += 4;
	} else {
		l_put_le16(mod, msg + n);
		n += 2;
	}

	mesh_model_send(net, dst, src, APP_IDX_DEV, DEFAULT_TTL, msg, n);
}

static bool config_sub_get(struct mesh_net *net, uint16_t src, uint16_t dst,
					const uint8_t *pkt, uint16_t size)
{
	uint16_t ele_addr;
	uint32_t mod_id;
	uint16_t n = 0;
	int ret = 0;
	uint8_t *status;
	uint16_t buf_size;
	uint8_t msg[5 + sizeof(uint16_t) * MAX_GRP_PER_MOD];

	/* Incoming message has already been size-checked */
	ele_addr = l_get_le16(pkt);

	switch (size) {
	default:
		l_debug("Bad Len Cfg_Pub_Set: %d", size);
		return false;

	case 4:
		mod_id = l_get_le16(pkt + 2);
		n = mesh_model_opcode_set(OP_CONFIG_MODEL_SUB_LIST, msg);
		status = msg + n;
		msg[n++] = 0;
		l_put_le16(ele_addr, msg + n);
		n += 2;
		l_put_le16(mod_id, msg + n);
		n += 2;
		mod_id |= VENDOR_ID_MASK;
		break;

	case 6:
		mod_id = l_get_le16(pkt + 2) << 16;
		mod_id |= l_get_le16(pkt + 4);
		n = mesh_model_opcode_set(OP_CONFIG_VEND_MODEL_SUB_LIST, msg);
		status = msg + n;
		msg[n++] = 0;
		l_put_le16(ele_addr, msg + n);
		n += 2;
		l_put_le16(mod_id >> 16, msg + n);
		n += 2;
		l_put_le16(mod_id, msg + n);
		n += 2;
		break;
	}

	buf_size = sizeof(uint16_t) * MAX_GRP_PER_MOD;
	ret = mesh_model_sub_get(net, ele_addr, mod_id, msg + n, buf_size,
									&size);

	if (!ret)
		n += size;
	else if (ret > 0)
		*status = ret;

	mesh_model_send(net, dst, src, APP_IDX_DEV, DEFAULT_TTL, msg, n);
	return true;
}

static void config_sub_set(struct mesh_net *net, uint16_t src, uint16_t dst,
					const uint8_t *pkt, uint16_t size,
					bool virt, uint32_t opcode)
{
	uint16_t grp, ele_addr;
	bool unreliable = !!(opcode & OP_UNRELIABLE);
	uint32_t mod_id, func;
	const uint8_t *addr = NULL;
	int status = 0;

	switch (size) {
	default:
		l_error("Bad Len Cfg_Sub_Set: %d", size);
		return;
	case 4:
		if (opcode != OP_CONFIG_MODEL_SUB_DELETE_ALL)
			return;
		mod_id = l_get_le16(pkt + 2);
		mod_id |= VENDOR_ID_MASK;
		break;
	case 6:
		if (virt)
			return;
		if (opcode != OP_CONFIG_MODEL_SUB_DELETE_ALL) {
			mod_id = l_get_le16(pkt + 4);
			mod_id |= VENDOR_ID_MASK;
		} else {
			mod_id = l_get_le16(pkt + 2) << 16;
			mod_id |= l_get_le16(pkt + 4);
		}
		break;
	case 8:
		if (virt)
			return;
		mod_id = l_get_le16(pkt + 4) << 16;
		mod_id |= l_get_le16(pkt + 6);
		break;
	case 20:
		if (!virt)
			return;
		mod_id = l_get_le16(pkt + 18);
		mod_id |= VENDOR_ID_MASK;
		break;
	case 22:
		if (!virt)
			return;
		mod_id = l_get_le16(pkt + 18) << 16;
		mod_id |= l_get_le16(pkt + 20);
		break;
	}
	ele_addr = l_get_le16(pkt);

	if (opcode != OP_CONFIG_MODEL_SUB_DELETE_ALL) {
		addr = pkt + 2;
		grp = l_get_le16(addr);
	} else
		grp = UNASSIGNED_ADDRESS;

	func = opcode & ~OP_UNRELIABLE;
	switch (func) {
	default:
		l_info("Bad opcode: %x", func);
		return;

	case OP_CONFIG_MODEL_SUB_DELETE_ALL:
		status = mesh_model_sub_del_all(net, ele_addr, mod_id);
		break;

	case OP_CONFIG_MODEL_SUB_VIRT_OVERWRITE:
		grp = UNASSIGNED_ADDRESS;
		/* Fall Through */
	case OP_CONFIG_MODEL_SUB_OVERWRITE:
		status = mesh_model_sub_ovr(net, ele_addr, mod_id,
							addr, virt, &grp);
		break;
	case OP_CONFIG_MODEL_SUB_VIRT_ADD:
		grp = UNASSIGNED_ADDRESS;
		/* Fall Through */
	case OP_CONFIG_MODEL_SUB_ADD:
		status = mesh_model_sub_add(net, ele_addr, mod_id,
							addr, virt, &grp);
		break;
	case OP_CONFIG_MODEL_SUB_VIRT_DELETE:
		grp = UNASSIGNED_ADDRESS;
		/* Fall Through */
	case OP_CONFIG_MODEL_SUB_DELETE:
		status = mesh_model_sub_del(net, ele_addr, mod_id,
							addr, virt, &grp);
		break;
	}

	if (!unreliable && status >= 0)
		send_sub_status(net, src, dst, status, ele_addr, grp, mod_id);

}

static void send_model_app_status(struct mesh_net *net, uint16_t src,
					uint16_t dst, uint8_t status,
					uint16_t addr, uint32_t id,
					uint16_t idx)
{
	uint8_t msg[12];
	size_t n = mesh_model_opcode_set(OP_MODEL_APP_STATUS, msg);

	msg[n++] = status;
	l_put_le16(addr, msg + n);
	n += 2;
	l_put_le16(idx, msg + n);
	n += 2;
	if (id >= 0x10000 && id < VENDOR_ID_MASK) {
		l_put_le16(id >> 16, msg + n);
		n += 2;
	}
	l_put_le16(id, msg + n);
	n += 2;

	mesh_model_send(net, dst, src, APP_IDX_DEV, DEFAULT_TTL, msg, n);
}

static void model_app_list(struct mesh_net *net, uint16_t src, uint16_t dst,
					const uint8_t *pkt, uint16_t size)
{
	uint16_t ele_addr;
	uint32_t mod_id = 0xffff;
	uint8_t *msg = NULL;
	uint8_t *status;
	uint16_t n, buf_size;
	int result;

	buf_size = MAX_BINDINGS * sizeof(uint16_t);
	msg = l_malloc(7 + buf_size);
	if (!msg)
		return;

	ele_addr = l_get_le16(pkt);

	switch (size) {
	default:
		l_free(msg);
		return;
	case 4:
		n = mesh_model_opcode_set(OP_MODEL_APP_LIST, msg);
		status = msg + n;
		mod_id = l_get_le16(pkt + 2);
		l_put_le16(ele_addr, msg + 1 + n);
		l_put_le16(mod_id, msg + 3 + n);
		mod_id |= VENDOR_ID_MASK;
		n += 5;
		break;
	case 6:
		n = mesh_model_opcode_set(OP_VEND_MODEL_APP_LIST, msg);
		status = msg + n;
		mod_id = l_get_le16(pkt + 2) << 16;
		mod_id |= l_get_le16(pkt + 4);

		l_put_le16(ele_addr, msg + 1 + n);
		l_put_le16(mod_id >> 16, msg + 3 + n);
		l_put_le16(mod_id, msg + 5 + n);
		n += 7;
		break;
	}


	result = mesh_model_get_bindings(net, ele_addr, mod_id, msg + n,
							buf_size, &size);
	n += size;

	if (result >= 0) {
		*status = result;
		mesh_model_send(net, dst, src, APP_IDX_DEV, DEFAULT_TTL,
								msg, n);
	}

	l_free(msg);
}

static bool model_app_bind(struct mesh_net *net, uint16_t src, uint16_t dst,
					const uint8_t *pkt, uint16_t size,
					bool unbind)
{
	uint16_t ele_addr;
	uint32_t mod_id;
	uint16_t idx;
	int result;

	switch (size) {
	default:
		return false;

	case 6:
		mod_id = l_get_le16(pkt + 4);
		mod_id |= VENDOR_ID_MASK;
		break;
	case 8:
		mod_id = l_get_le16(pkt + 4) << 16;
		mod_id |= l_get_le16(pkt + 6);
		break;
	}

	ele_addr = l_get_le16(pkt);
	idx = l_get_le16(pkt + 2);

	if (idx > 0xfff)
		return false;

	if (unbind)
		result = mesh_model_binding_del(net, ele_addr, mod_id, idx);
	else
		result = mesh_model_binding_add(net, ele_addr, mod_id, idx);

	send_model_app_status(net, src, dst, result, ele_addr, mod_id, idx);

	return true;
}

static void hb_pub_timeout_func(struct l_timeout *timeout, void *user_data)
{
	struct mesh_net *net = user_data;
	struct mesh_net_heartbeat *hb = mesh_net_heartbeat_get(net);

	mesh_net_heartbeat_send(net);

	if (hb->pub_count != 0xffff)
		hb->pub_count--;
	if (hb->pub_count > 0)
		l_timeout_modify(hb->pub_timer, hb->pub_period);
	else {
		l_timeout_remove(hb->pub_timer);
		hb->pub_timer = NULL;
	}
	l_debug("%d left", hb->pub_count);
}

static void update_hb_pub_timer(struct mesh_net *net,
						struct mesh_net_heartbeat *hb)
{
	if (IS_UNASSIGNED(hb->pub_dst) || hb->pub_count == 0) {
		l_timeout_remove(hb->pub_timer);
		hb->pub_timer = NULL;
		return;
	}

	if (!hb->pub_timer)
		hb->pub_timer = l_timeout_create(hb->pub_period,
					hb_pub_timeout_func, net, NULL);
	else
		l_timeout_modify(hb->pub_timer, hb->pub_period);
}

static void hb_sub_timeout_func(struct l_timeout *timeout, void *user_data)
{
	struct mesh_net *net = user_data;
	struct mesh_net_heartbeat *hb = mesh_net_heartbeat_get(net);

	l_info("HB Subscription Ended");
	l_timeout_remove(hb->sub_timer);
	hb->sub_timer = NULL;
	hb->sub_enabled = false;
}

static uint8_t uint32_to_log(uint32_t value)
{
	uint32_t val = 1;
	uint8_t ret = 1;

	if (!value)
		return 0;
	else if (value > 0x10000)
		return 0xff;

	while (val < value) {
		val <<= 1;
		ret++;
	}

	return ret;
}

static uint32_t log_to_uint32(uint8_t log, uint8_t offset)
{
	if (!log)
		return 0x0000;
	else if (log > 0x11)
		return 0xffff;
	else
		return (1 << (log - offset));
}


static int hb_subscription_set(struct mesh_net *net, uint16_t src,
					uint16_t dst, uint8_t period_log)
{
	struct mesh_net_heartbeat *hb = mesh_net_heartbeat_get(net);
	struct timeval time_now;

	/* SRC must be Unicast, DST can be any legal address except Virtual */
	if ((!IS_UNASSIGNED(src) && !IS_UNICAST(src)) || IS_VIRTUAL(dst))
		return -1;

	/* Check if the subscription should be disabled */
	if (IS_UNASSIGNED(src) || IS_UNASSIGNED(dst)) {
		if (IS_GROUP(hb->sub_dst))
			mesh_net_dst_unreg(net, hb->sub_dst);

		l_timeout_remove(hb->sub_timer);
		hb->sub_timer = NULL;
		hb->sub_enabled = false;
		hb->sub_dst = UNASSIGNED_ADDRESS;
		hb->sub_src = UNASSIGNED_ADDRESS;
		hb->sub_count = 0;
		hb->sub_period = 0;
		hb->sub_min_hops = 0;
		hb->sub_max_hops = 0;
		return MESH_STATUS_SUCCESS;
	} else if (!period_log && src == hb->sub_src && dst == hb->sub_dst) {
		/* Preserve collected data, but disable */
		l_timeout_remove(hb->sub_timer);
		hb->sub_timer = NULL;
		hb->sub_enabled = false;
		hb->sub_period = 0;
		return MESH_STATUS_SUCCESS;
	}

	if (hb->sub_dst != dst) {
		if (IS_GROUP(hb->sub_dst))
			mesh_net_dst_unreg(net, hb->sub_dst);
		if (IS_GROUP(dst))
			mesh_net_dst_reg(net, dst);
	}

	hb->sub_enabled = !!period_log;
	hb->sub_src = src;
	hb->sub_dst = dst;
	hb->sub_count = 0;
	hb->sub_period = log_to_uint32(period_log, 1);
	hb->sub_min_hops = 0x00;
	hb->sub_max_hops = 0x00;

	gettimeofday(&time_now, NULL);
	hb->sub_start = time_now.tv_sec;

	if (!hb->sub_enabled) {
		l_timeout_remove(hb->sub_timer);
		hb->sub_timer = NULL;
		return MESH_STATUS_SUCCESS;
	}

	hb->sub_min_hops = 0xff;

	if (!hb->sub_timer)
		hb->sub_timer = l_timeout_create(hb->sub_period,
						hb_sub_timeout_func, net, NULL);
	else
		l_timeout_modify(hb->sub_timer, hb->sub_period);

	return MESH_STATUS_SUCCESS;
}

static void node_reset(struct l_timeout *timeout, void *user_data)
{
	l_info("Node Reset");
	l_timeout_remove(timeout);
	l_main_quit();
}

static bool cfg_srv_pkt(uint16_t src, uint32_t dst,
				uint16_t unicast, uint16_t idx,
				const uint8_t *data, uint16_t size,
				uint8_t ttl, const void *user_data)
{
	struct mesh_net *net = (struct mesh_net *) user_data;
	const uint8_t *pkt = data;
	struct timeval time_now;
	uint32_t opcode, tmp32;
	int b_res = MESH_STATUS_SUCCESS;
	uint8_t msg[11];
	uint8_t *long_msg = NULL;
	struct mesh_net_heartbeat *hb;
	uint16_t net_idx, app_idx;
	uint8_t state, status;
	uint8_t phase;
	bool virt = false;
	uint8_t count;
	uint16_t interval;
	struct mesh_node *node;
	uint16_t n;

	if (idx != APP_IDX_DEV)
		return false;

	if (mesh_model_opcode_get(pkt, size, &opcode, &n)) {
		size -= n;
		pkt += n;
	} else
		return false;

	hb = mesh_net_heartbeat_get(net);
	l_debug("CONFIG-SRV-opcode 0x%x size %u idx %3.3x", opcode, size, idx);

	node = mesh_net_local_node_get(net);
	n = 0;

	switch (opcode) {
	default:
		return false;

	case OP_DEV_COMP_GET:
		if (size != 1)
			return false;

		/* Only page 0 is currently supported */
		if (pkt[0] != 0) {
			l_info("Unsupported page number %d", pkt[0]);
			l_info("Returning page number 0");
		}
		long_msg = l_malloc(CFG_MAX_MSG_LEN);
		n = mesh_model_opcode_set(OP_DEV_COMP_STATUS, long_msg);
		long_msg[n++] = 0;
		n += node_generate_comp(node, long_msg + n,
							CFG_MAX_MSG_LEN - n);

		break;

	case OP_CONFIG_DEFAULT_TTL_SET:
		if (size != 1 || pkt[0] > TTL_MASK || pkt[0] == 1)
			return true;

		if (pkt[0] <= TTL_MASK)
			node_default_ttl_set(node, pkt[0]);
		/* Fall Through */

	case OP_CONFIG_DEFAULT_TTL_GET:
		l_info("Get/Set Default TTL");

		n = mesh_model_opcode_set(OP_CONFIG_DEFAULT_TTL_STATUS, msg);
		msg[n++] = node_default_ttl_get(node);
		break;

	case OP_CONFIG_MODEL_PUB_VIRT_SET:
		if (size != 25 && size != 27)
			return true;

		config_pub_set(net, src, unicast, pkt, size,
				!!(opcode & OP_UNRELIABLE));
		break;

	case OP_CONFIG_MODEL_PUB_SET:
		if (size != 11 && size != 13)
			return true;

		config_pub_set(net, src, unicast, pkt, size,
				!!(opcode & OP_UNRELIABLE));
		break;

	case OP_CONFIG_MODEL_PUB_GET:
		config_pub_get(net, src, unicast, pkt, size);
		break;

	case OP_CONFIG_VEND_MODEL_SUB_GET:
		if (size != 6)
			return true;
		config_sub_get(net, src, unicast, pkt, size);
		break;

	case OP_CONFIG_MODEL_SUB_GET:
		if (size != 4)
			return true;
		config_sub_get(net, src, unicast, pkt, size);
		break;

	case OP_CONFIG_MODEL_SUB_VIRT_OVERWRITE:
	case OP_CONFIG_MODEL_SUB_VIRT_DELETE:
	case OP_CONFIG_MODEL_SUB_VIRT_ADD:
		virt = true;
		/* Fall Through */
	case OP_CONFIG_MODEL_SUB_OVERWRITE:
	case OP_CONFIG_MODEL_SUB_DELETE:
	case OP_CONFIG_MODEL_SUB_ADD:
	case OP_CONFIG_MODEL_SUB_DELETE_ALL:
		config_sub_set(net, src, unicast, pkt, size, virt, opcode);
		break;

	case OP_CONFIG_RELAY_SET:
		if (size != 2 || pkt[0] > 0x01)
			return true;

		count = (pkt[1] >> 5) + 1;
		interval = ((pkt[1] & 0x1f) + 1) * 10;
		node_relay_mode_set(node, !!pkt[0], pkt[1]>>5,
					pkt[1] & 0x1f);
		/* Fall Through */

	case OP_CONFIG_RELAY_GET:
		n = mesh_model_opcode_set(OP_CONFIG_RELAY_STATUS, msg);

		msg[n++] = node_relay_mode_get(node, &count, &interval);
		msg[n++] = ((count - 1) << 5) + ((interval/10 - 1) & 0x1f);

		l_info("Get/Set Relay Config (%d)", msg[n-1]);
		break;

	case OP_CONFIG_NETWORK_TRANSMIT_SET:
		if (size != 1)
			return true;

		count = (pkt[0] >> 5) + 1;
		interval = ((pkt[0] & 0x1f) + 1) * 10;
		if (storage_local_set_transmit_params(net, count, interval))
			mesh_net_transmit_params_set(net, count, interval);
		/* Fall Through */

	case OP_CONFIG_NETWORK_TRANSMIT_GET:
		n = mesh_model_opcode_set(OP_CONFIG_NETWORK_TRANSMIT_STATUS,
									msg);
		mesh_net_transmit_params_get(net, &count, &interval);
		msg[n++] = ((count - 1) << 5) + ((interval/10 - 1) & 0x1f);

		l_info("Get/Set Network Transmit Config");
		break;

	case OP_CONFIG_PROXY_SET:
		if (size != 1 || pkt[0] > 0x01)
			return true;

		node_proxy_mode_set(node, !!pkt[0]);
		/* Fall Through */

	case OP_CONFIG_PROXY_GET:
		n = mesh_model_opcode_set(OP_CONFIG_PROXY_STATUS, msg);

		msg[n++] = node_proxy_mode_get(node);
		l_info("Get/Set Config Proxy (%d)", msg[n-1]);
		break;

	case OP_NODE_IDENTITY_SET:
		if (size != 3 || pkt[2] > 0x01)
			return true;

		net_idx = l_get_le16(pkt);
		if (net_idx > 0xfff)
			return true;

		/*
		 * Currently no support for proxy: node identity not supported
		 */

		/* Fall Through */

	case OP_NODE_IDENTITY_GET:
		if (size < 2)
			return true;

		net_idx = l_get_le16(pkt);
		if (net_idx > 0xfff)
			return true;

		n = mesh_model_opcode_set(OP_NODE_IDENTITY_STATUS, msg);

		status = mesh_net_get_identity_mode(net, net_idx, &state);

		msg[n++] = status;

		l_put_le16(net_idx, msg + n);
		n += 2;

		msg[n++] = state;
		l_info("Get/Set Config Identity (%d)", state);
		break;

	case OP_CONFIG_BEACON_SET:
		if (size != 1 || pkt[0] > 0x01)
			return true;

		node_beacon_mode_set(node, !!pkt[0]);
		/* Fall Through */

	case OP_CONFIG_BEACON_GET:
		n = mesh_model_opcode_set(OP_CONFIG_BEACON_STATUS, msg);

		msg[n++] = node_beacon_mode_get(node);
		l_info("Get/Set Config Beacon (%d)", msg[n-1]);
		break;

	case OP_CONFIG_FRIEND_SET:
		if (size != 1 || pkt[0] > 0x01)
			return true;

		node_friend_mode_set(node, !!pkt[0]);
		/* Fall Through */

	case OP_CONFIG_FRIEND_GET:

		n = mesh_model_opcode_set(OP_CONFIG_FRIEND_STATUS, msg);

		msg[n++] = node_friend_mode_get(node);
		l_info("Get/Set Friend (%d)", msg[n-1]);
		break;

	case OP_CONFIG_KEY_REFRESH_PHASE_SET:
		if (size != 3 || pkt[2] > 0x03)
			return true;

		b_res = mesh_net_key_refresh_phase_set(net, l_get_le16(pkt),
							pkt[2]);
		size = 2;
		/* Fall Through */

	case OP_CONFIG_KEY_REFRESH_PHASE_GET:
		if (size != 2)
			return true;

		net_idx = l_get_le16(pkt);

		n = mesh_model_opcode_set(OP_CONFIG_KEY_REFRESH_PHASE_STATUS,
						msg);

		/* State: 0x00-0x03 phase of key refresh */
		status = mesh_net_key_refresh_phase_get(net, net_idx,
							&phase);
		if (status != MESH_STATUS_SUCCESS) {
			b_res = status;
			phase = KEY_REFRESH_PHASE_NONE;
		}

		msg[n++] = b_res;
		l_put_le16(net_idx, msg + n);
		n += 2;
		msg[n++] = phase;

		l_info("Get/Set Key Refresh State (%d)", msg[n-1]);
		break;

	case OP_APPKEY_ADD:
	case OP_APPKEY_UPDATE:
		if (size != 19)
			return true;

		net_idx = l_get_le16(pkt) & 0xfff;
		app_idx = l_get_le16(pkt + 1) >> 4;
		b_res = appkey_key_add(net, net_idx, app_idx, pkt + 3,
						opcode == OP_APPKEY_UPDATE);

		l_info("Add/Update AppKey %s: Net_Idx %3.3x, App_Idx %3.3x",
			(b_res == MESH_STATUS_SUCCESS) ? "success" : "fail",
							net_idx, app_idx);


		n = mesh_model_opcode_set(OP_APPKEY_STATUS, msg);

		msg[n++] = b_res;
		msg[n++] = pkt[0];
		msg[n++] = pkt[1];
		msg[n++] = pkt[2];
		break;

	case OP_APPKEY_DELETE:
		if (size != 3)
			return
				true;

		net_idx = l_get_le16(pkt) & 0xfff;
		app_idx = l_get_le16(pkt + 1) >> 4;
		b_res = appkey_key_delete(net, net_idx, app_idx);
		if (b_res == MESH_STATUS_SUCCESS)
			node_app_key_delete(net, dst, net_idx, app_idx);
		l_info("Delete AppKey %s Net_Idx %3.3x to App_Idx %3.3x",
			(b_res == MESH_STATUS_SUCCESS) ? "success" : "fail",
							net_idx, app_idx);

		n = mesh_model_opcode_set(OP_APPKEY_STATUS, msg);
		msg[n++] = b_res;
		msg[n++] = pkt[0];
		msg[n++] = pkt[1];
		msg[n++] = pkt[2];
		break;

	case OP_APPKEY_GET:
		if (size != 2)
			return true;
		net_idx = l_get_le16(pkt);

		long_msg = l_malloc(CFG_MAX_MSG_LEN);
		n = mesh_model_opcode_set(OP_APPKEY_LIST, long_msg);

		status = appkey_list(net, net_idx, long_msg + n + 3,
						CFG_MAX_MSG_LEN - n - 3, &size);

		long_msg[n] = status;
		l_put_le16(net_idx, long_msg + n + 1);
		n += (size + 3);
		break;

	case OP_NETKEY_ADD:
	case OP_NETKEY_UPDATE:
		if (size != 18)
			return true;

		b_res = mesh_net_add_key(net, opcode == OP_NETKEY_UPDATE,
						l_get_le16(pkt), pkt + 2);

		l_info("NetKey Add/Update %s",
			(b_res == MESH_STATUS_SUCCESS) ? "success" : "fail");

		n = mesh_model_opcode_set(OP_NETKEY_STATUS, msg);
		msg[n++] = b_res;
		l_put_le16(l_get_le16(pkt), msg + n);
		n += 2;
		break;

	case OP_NETKEY_DELETE:
		if (size != 2)
			return true;

		b_res = mesh_net_del_key(net, l_get_le16(pkt));

		l_info("NetKey delete %s",
			(b_res == MESH_STATUS_SUCCESS) ? "success" : "fail");

		n = mesh_model_opcode_set(OP_NETKEY_STATUS, msg);
		msg[n++] = b_res;
		l_put_le16(l_get_le16(pkt), msg + n);
		n += 2;
		break;

	case OP_NETKEY_GET:
		long_msg = l_malloc(CFG_MAX_MSG_LEN);
		n = mesh_model_opcode_set(OP_NETKEY_LIST, long_msg);
		size = CFG_MAX_MSG_LEN - n;

		if (mesh_net_key_list_get(net, long_msg + n, &size))
			n += size;
		else
			n = 0;
		break;

	case OP_MODEL_APP_BIND:
	case OP_MODEL_APP_UNBIND:
		model_app_bind(net, src, unicast, pkt, size,
				opcode != OP_MODEL_APP_BIND);
		break;

	case OP_VEND_MODEL_APP_GET:
		if (size != 6)
			return true;
		model_app_list(net, src, unicast, pkt, size);
		break;

	case OP_MODEL_APP_GET:
		if (size != 4)
			return true;
		model_app_list(net, src, unicast, pkt, size);
		break;

	case OP_CONFIG_HEARTBEAT_PUB_SET:
		l_info("OP_CONFIG_HEARTBEAT_PUB_SET");
		if (size != 9) {
			l_info("bad size %d", size);
			return true;
		}
		if (pkt[2] > 0x11 || pkt[3] > 0x10 || pkt[4] > 0x7f)
			return true;
		else if (IS_VIRTUAL(l_get_le16(pkt)))
			b_res = MESH_STATUS_INVALID_ADDRESS;
		else if (l_get_le16(pkt + 7) != mesh_net_get_primary_idx(net))
			/* Future work: check for valid subnets */
			b_res = MESH_STATUS_INVALID_NETKEY;

		n = mesh_model_opcode_set(OP_CONFIG_HEARTBEAT_PUB_STATUS,
						msg);
		msg[n++] = b_res;

		memcpy(&msg[n], pkt, 9);

		/* Ignore RFU bits in features */
		l_put_le16(l_get_le16(pkt + 5) & 0xf, &msg[n + 5]);

		/* Add octet count to status */
		n += 9;

		if (b_res != MESH_STATUS_SUCCESS)
			break;

		hb->pub_dst = l_get_le16(pkt);
		if (hb->pub_dst == UNASSIGNED_ADDRESS ||
				pkt[2] == 0 || pkt[3] == 0) {
			/*
			 * We might still have a pub_dst here in case
			 * we need it for State Change heartbeat
			 */
			hb->pub_count = 0;
			hb->pub_period = 0;
		} else {
			hb->pub_count = (pkt[2] != 0xff) ?
				log_to_uint32(pkt[2], 1) : 0xffff;
			hb->pub_period = log_to_uint32(pkt[3], 1);
		}

		hb->pub_ttl = pkt[4];
		hb->pub_features = l_get_le16(pkt + 5) & 0xf;
		hb->pub_net_idx = l_get_le16(pkt + 7);
		update_hb_pub_timer(net, hb);

		break;

	case OP_CONFIG_HEARTBEAT_PUB_GET:
		n = mesh_model_opcode_set(OP_CONFIG_HEARTBEAT_PUB_STATUS, msg);
		msg[n++] = b_res;
		l_put_le16(hb->pub_dst, msg + n);
		n += 2;
		msg[n++] = uint32_to_log(hb->pub_count);
		msg[n++] = uint32_to_log(hb->pub_period);
		msg[n++] = hb->pub_ttl;
		l_put_le16(hb->pub_features, msg + n);
		n += 2;
		l_put_le16(hb->pub_net_idx, msg + n);
		n += 2;
		break;

	case OP_CONFIG_HEARTBEAT_SUB_SET:
		if (size != 5)
			return true;

		l_info("Set Sub Period (Log %2.2x) %d sec",
				pkt[4], log_to_uint32(pkt[4], 1));

		b_res = hb_subscription_set(net, l_get_le16(pkt),
						l_get_le16(pkt + 2),
						pkt[4]);
		if (b_res < 0)
			return true;

		/* Fall through */

	case OP_CONFIG_HEARTBEAT_SUB_GET:
		gettimeofday(&time_now, NULL);
		time_now.tv_sec -= hb->sub_start;

		if (time_now.tv_sec >= hb->sub_period)
			time_now.tv_sec = 0;
		else
			time_now.tv_sec = hb->sub_period - time_now.tv_sec;

		l_info("Sub Period (Log %2.2x) %d sec",
				uint32_to_log(time_now.tv_sec),
				(int) time_now.tv_sec);

		n = mesh_model_opcode_set(OP_CONFIG_HEARTBEAT_SUB_STATUS, msg);
		msg[n++] = b_res;
		l_put_le16(hb->sub_src, msg + n);
		n += 2;
		l_put_le16(hb->sub_dst, msg + n);
		n += 2;
		msg[n++] = uint32_to_log(time_now.tv_sec);
		msg[n++] = uint32_to_log(hb->sub_count);
		msg[n++] = hb->sub_count ? hb->sub_min_hops : 0;
		msg[n++] = hb->sub_max_hops;
		break;

	case OP_CONFIG_POLL_TIMEOUT_LIST:
		if (size != 2 || l_get_le16(pkt) == 0 ||
						l_get_le16(pkt) > 0x7fff)
			return true;

		n = mesh_model_opcode_set(OP_CONFIG_POLL_TIMEOUT_STATUS, msg);
		l_put_le16(l_get_le16(pkt), msg + n);
		n += 2;
		tmp32 = mesh_net_friend_timeout(net, l_get_le16(pkt));
		msg[n++] = tmp32;
		msg[n++] = tmp32 >> 8;
		msg[n++] = tmp32 >> 16;
		break;

	case OP_NODE_RESET:
		n = mesh_model_opcode_set(OP_NODE_RESET_STATUS, msg);
		l_timeout_create(1, node_reset, net, NULL);
		break;
	}

	if (n) {
		/* print_packet("App Tx", long_msg ? long_msg : msg, n); */
		mesh_model_send(net, unicast, src,
				APP_IDX_DEV, DEFAULT_TTL,
				long_msg ? long_msg : msg, n);
	}
	l_free(long_msg);

	return true;
}

static void cfgmod_srv_unregister(void *user_data)
{
	struct mesh_net *net = user_data;
	struct mesh_net_heartbeat *hb = mesh_net_heartbeat_get(net);

	l_timeout_remove(hb->pub_timer);
	l_timeout_remove(hb->sub_timer);
	hb->pub_timer = hb->sub_timer = NULL;
}

static const struct mesh_model_ops ops = {
	.unregister = cfgmod_srv_unregister,
	.recv = cfg_srv_pkt,
	.bind = NULL,
	.sub = NULL,
	.pub = NULL
};

void mesh_config_srv_init(struct mesh_net *net, uint8_t ele_idx)
{
	l_debug("%2.2x", ele_idx);
	mesh_model_register(net, ele_idx, CONFIG_SRV_MODEL, &ops, net);
}
