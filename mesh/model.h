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

#include <ell/ell.h>

struct mesh_model;

#define OP_UNRELIABLE			0x0100

#define MAX_BINDINGS	10
#define MAX_GRP_PER_MOD	10

#define	VIRTUAL_BASE			0x10000

#define MESH_MAX_ACCESS_PAYLOAD		380

#define MESH_STATUS_SUCCESS		0x00
#define MESH_STATUS_INVALID_ADDRESS	0x01
#define MESH_STATUS_INVALID_MODEL	0x02
#define MESH_STATUS_INVALID_APPKEY	0x03
#define MESH_STATUS_INVALID_NETKEY	0x04
#define MESH_STATUS_INSUFF_RESOURCES	0x05
#define MESH_STATUS_IDX_ALREADY_STORED	0x06
#define MESH_STATUS_INVALID_PUB_PARAM	0x07
#define MESH_STATUS_NOT_SUB_MOD		0x08
#define MESH_STATUS_STORAGE_FAIL	0x09
#define MESH_STATUS_FEATURE_NO_SUPPORT	0x0a
#define MESH_STATUS_CANNOT_UPDATE	0x0b
#define MESH_STATUS_CANNOT_REMOVE	0x0c
#define MESH_STATUS_CANNOT_BIND		0x0d
#define MESH_STATUS_UNABLE_CHANGE_STATE	0x0e
#define MESH_STATUS_CANNOT_SET		0x0f
#define MESH_STATUS_UNSPECIFIED_ERROR	0x10
#define MESH_STATUS_INVALID_BINDING	0x11

#define OP_MODEL_TEST			0x8000fffe
#define OP_MODEL_INVALID		0x8000ffff

#define USE_PUB_VALUE			0x00

#define ACTION_ADD		1
#define ACTION_UPDATE		2
#define ACTION_DELETE		3

struct mesh_model_pub {
	uint32_t addr;
	uint16_t idx;
	uint8_t ttl;
	uint8_t credential;
	uint8_t period;
	uint8_t retransmit;
};

typedef void (*mesh_model_unregister)(void *user_data);
typedef bool (*mesh_model_recv_cb)(uint16_t src, uint32_t dst, uint16_t unicast,
					uint16_t app_idx, const uint8_t *data,
					uint16_t len, uint8_t ttl,
					const void *user_data);
typedef int (*mesh_model_bind_cb)(uint16_t app_idx, int action);
typedef int (*mesh_model_pub_cb)(struct mesh_model_pub *pub);
typedef int (*mesh_model_sub_cb)(uint16_t sub_addr, int action);

struct mesh_model_ops {
	mesh_model_unregister unregister;
	mesh_model_recv_cb recv;
	mesh_model_bind_cb bind;
	mesh_model_pub_cb pub;
	mesh_model_sub_cb sub;
};

struct mesh_model *mesh_model_new(uint8_t ele_idx, uint32_t id, bool vendor);
void mesh_model_free(void *data);
uint32_t mesh_model_get_model_id(const struct mesh_model *model);
bool mesh_model_register(struct mesh_net *net, uint8_t ele_idx, uint32_t mod_id,
					const struct mesh_model_ops *cbs,
							void *user_data);
struct mesh_model_pub *mesh_model_pub_get(struct mesh_net *net, uint8_t ele_idx,
						uint32_t mod_id, int *status);
int mesh_model_pub_set(struct mesh_net *net, uint16_t addr, uint32_t id,
			const uint8_t *mod_addr, uint16_t idx, bool cred_flag,
			uint8_t ttl, uint8_t period, uint8_t retransmit,
			bool b_virt, uint16_t *dst);
struct mesh_model *mesh_model_init(struct mesh_net *net, uint8_t ele_idx,
						struct mesh_db_model *db_mod);

int mesh_model_binding_add(struct mesh_net *net, uint16_t addr, uint32_t id,
						uint16_t app_idx);
int mesh_model_binding_del(struct mesh_net *net, uint16_t addr, uint32_t id,
						uint16_t idx);
int mesh_model_get_bindings(struct mesh_net *net, uint16_t addr, uint32_t id,
				uint8_t *buf, uint16_t buf_len, uint16_t *size);
int mesh_model_sub_add(struct mesh_net *net, uint16_t addr, uint32_t id,
						const uint8_t *grp, bool b_virt,
						uint16_t *dst);
int mesh_model_sub_del(struct mesh_net *net, uint16_t addr, uint32_t id,
						const uint8_t *grp, bool b_virt,
						uint16_t *dst);
int mesh_model_sub_del_all(struct mesh_net *net, uint16_t addr, uint32_t id);
int mesh_model_sub_ovr(struct mesh_net *net, uint16_t addr, uint32_t id,
						const uint8_t *grp, bool b_virt,
						uint16_t *dst);
int mesh_model_sub_get(struct mesh_net *net, uint16_t addr, uint32_t id,
			uint8_t *buf, uint16_t buf_size, uint16_t *size);
uint16_t mesh_model_cfg_blk(uint8_t *pkt);
unsigned int mesh_model_send(struct mesh_net *net,
				uint16_t src, uint16_t target,
				uint16_t app_idx, uint8_t ttl,
				const void *msg, uint16_t msg_len);
unsigned int mesh_model_publish(struct mesh_net *net, uint32_t mod_id,
				uint16_t src, uint8_t ttl,
				const void *msg, uint16_t msg_len);
bool mesh_model_rx(struct mesh_net *net, bool szmict, uint32_t seq0,
			uint32_t seq, uint32_t iv_index, uint8_t ttl,
			uint16_t src, uint16_t dst, uint8_t key_id,
			const uint8_t *data, uint16_t size);

void mesh_model_app_key_generate_new(struct mesh_net *net, uint16_t net_idx);
void mesh_model_app_key_delete(struct mesh_net *net, struct l_queue *models,
								uint16_t idx);
struct l_queue *mesh_model_get_appkeys(struct mesh_net *net);
void *mesh_model_get_local_node_data(struct mesh_net *net);
void mesh_model_add_virtual(struct mesh_net *net, const uint8_t *v);
void mesh_model_del_virtual(struct mesh_net *net, uint32_t va24);
void mesh_model_list_virtual(struct mesh_net *net);
uint16_t mesh_model_opcode_set(uint32_t opcode, uint8_t *buf);
bool mesh_model_opcode_get(const uint8_t *buf, uint16_t size,
					uint32_t *opcode, uint16_t *n);
