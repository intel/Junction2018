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
 */


/*
size: hard define (mesh.conf)
       oob size - 8 if alpha or numeric
	             else 1 if mask is non zero
			else 0
*/
struct bt_mesh;

struct mesh_prov_caps {
	uint8_t uuid[16];
	uint32_t uri_hash;
	uint16_t oob_info;
	uint16_t algorithms;
	uint16_t output_action;
	uint16_t input_action;
	uint8_t num_ele;
	uint8_t pub_type;
	uint8_t static_type;
	uint8_t output_size;
	uint8_t input_size;
};

struct mesh_prov_node_info {
	uint32_t iv_index;
	uint16_t unicast;
	uint16_t net_index;
	uint8_t net_key[16];
	uint8_t device_key[16];
	uint8_t flags;
};

struct mesh_agent_request {
	uint8_t type; //enum (include TYPE_CANCEL
	union {
		uint32_t number; // for "DisplayNumeric"
		char data[17]; // NULL terminated string for "DisplayString"
	} u;
};

struct mesh_agent_response {
	uint8_t type; //enum
	union {
		uint32_t number; // for "PromptNumeric"
		uint8_t data[16]; // for "PromptStatic"
	} u;
};

typedef void (*mesh_prov_acceptor_agent_req_func_t)(struct bt_mesh *mesh,
						    struct mesh_agent_request *req,
						    uint8_t *user_data);

typedef void (*mesh_prov_acceptor_complete_func_t)(struct bt_mesh *mesh,
						    uint8_t status, // enum PROV_STATUS
						    struct mesh_prov_node_info *info);

/* This starts unprovisioned device beacon */
bool acceptor_start(struct bt_mesh *mesh,
		    const struct mesh_prov_caps *caps,
		    uint32_t timeout, // in seconds from mesh.conf
		    mesh_prov_acceptor_complete_func_t complete_cb,
		    mesh_prov_acceptor_agent_req_func_t agent_cb);

bool acceptor_agent_reply(uint8_t *user_data, struct mesh_agent_response *rsp);
void acceptor_cancel(struct bt_mesh *mesh);



/****************************************************************************/
struct mesh_prov;
struct l_queue;

void initiator_prov_open(struct mesh_prov *prov);
void initiator_prov_close(struct mesh_prov *prov, uint8_t reason);
void initiator_prov_receive(const void *pkt, uint16_t size,
							struct mesh_prov *prov);

void acceptor_prov_open(struct mesh_prov *prov);
void acceptor_prov_close(struct mesh_prov *prov, uint8_t reason);
void acceptor_prov_receive(const void *pkt, uint16_t size,
							struct mesh_prov *prov);
