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

#include <time.h>
#include <ell/ell.h>

#include "lib/bluetooth.h"
#include "lib/mgmt.h"

#include "src/shared/mgmt.h"

#include "mesh/mesh-defs.h"
#include "mesh/mesh-io.h"
#include "mesh/node.h"
#include "mesh/net.h"
#include "mesh/storage.h"
#include "mesh/provision.h"
#include "mesh/model.h"
#include "mesh/dbus.h"
#include "mesh/error.h"
#include "mesh/mesh.h"

#define MESH_NETWORK_INTERFACE "org.bluez.mesh.Network"

#define MESH_COMP_MAX_LEN 378

/*
 * The default values for mesh configuration. Can be
 * overwritten by values from mesh.conf
 */
#define DEFAULT_PROV_TIMEOUT 60
#define DEFAULT_ALGORITHMS 0x0001

//TODO: add more default values

struct scan_filter {
	uint8_t id;
	const char *pattern;
};

struct bt_mesh {
	struct mesh_io *io;
	struct l_queue *filters;
	uint32_t prov_timeout;
	uint16_t algorithms;
	uint16_t req_index;
	uint8_t max_filters;
};

struct join_data{
	struct l_dbus_message *msg;
	const char *agent;
	struct mesh_node *node;
	uint32_t disc_watch;
	struct mesh_prov_caps caps;
	uint8_t composition[MESH_COMP_MAX_LEN];
};

struct attach_data {
	uint64_t token;
	struct l_dbus_message *msg;
	const char *app;
};

static struct bt_mesh mesh;
static struct l_queue *controllers;
static struct mgmt *mgmt_mesh;
static bool initialized;

/* We allow only one outstanding Join request */
static struct join_data *join_pending;

/* Pending Attach requests */
static struct l_queue *attach_queue;

static bool simple_match(const void *a, const void *b)
{
	return a == b;
}

static void start_io(uint16_t index)
{
	struct mesh_io *io;
	struct mesh_io_caps caps;

	l_debug("Starting mesh on hci %u", index);

	io = mesh_io_new(index, MESH_IO_TYPE_GENERIC);
	if (!io) {
		l_error("Failed to start mesh io (hci %u)", index);
		return;
	}

	mesh_io_get_caps(io, &caps);
	mesh.max_filters = caps.max_num_filters;

	mesh.io = io;

	l_debug("Started mesh (io %p) on hci %u", mesh.io, index);

	node_attach_io(io);
}

static void read_info_cb(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	uint16_t index = L_PTR_TO_UINT(user_data);
	const struct mgmt_rp_read_info *rp = param;
	uint32_t current_settings, supported_settings;

	if (mesh.io)
		/* Already initialized */
		return;

	l_debug("hci %u status 0x%02x", index, status);

	if (status != MGMT_STATUS_SUCCESS) {
		l_error("Failed to read info for hci index %u: %s (0x%02x)",
					index, mgmt_errstr(status), status);
		return;
	}

	if (length < sizeof(*rp)) {
		l_error("Read info response too short");
		return;
	}

	current_settings = btohl(rp->current_settings);
	supported_settings = btohl(rp->supported_settings);

	l_debug("settings: supp %8.8x curr %8.8x",
					supported_settings, current_settings);

	if (current_settings & MGMT_SETTING_POWERED) {
		l_info("Controller hci %u is in use", index);
		return;
	}

	if (!(supported_settings & MGMT_SETTING_LE)) {
		l_info("Controller hci %u does not support LE", index);
		return;
	}

	start_io(index);
}

static void index_added(uint16_t index, uint16_t length, const void *param,
							void *user_data)
{
	l_debug("hci device %u", index);

	if (mesh.req_index != MGMT_INDEX_NONE &&
					index != mesh.req_index) {
		l_debug("Ignore index %d", index);
		return;
	}

	if (l_queue_find(controllers, simple_match, L_UINT_TO_PTR(index)))
		return;

	l_queue_push_tail(controllers, L_UINT_TO_PTR(index));

	if (mgmt_send(mgmt_mesh, MGMT_OP_READ_INFO, index, 0, NULL,
			read_info_cb, L_UINT_TO_PTR(index), NULL) > 0)
		return;

	l_queue_remove(controllers, L_UINT_TO_PTR(index));
}

static void index_removed(uint16_t index, uint16_t length, const void *param,
							void *user_data)
{
	l_warn("Hci dev %4.4x removed", index);
	l_queue_remove(controllers, L_UINT_TO_PTR(index));
}

static void read_index_list_cb(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	const struct mgmt_rp_read_index_list *rp = param;
	uint16_t num;
	int i;

	if (status != MGMT_STATUS_SUCCESS) {
		l_error("Failed to read index list: %s (0x%02x)",
						mgmt_errstr(status), status);
		return;
	}

	if (length < sizeof(*rp)) {
		l_error("Read index list response sixe too short");
		return;
	}

	num = btohs(rp->num_controllers);

	l_debug("Number of controllers: %u", num);

	if (num * sizeof(uint16_t) + sizeof(*rp) != length) {
		l_error("Incorrect packet size for index list response");
		return;
	}

	for (i = 0; i < num; i++) {
		uint16_t index;

		index = btohs(rp->index[i]);
		index_added(index, 0, NULL, user_data);
	}
}

static bool init_mgmt(void)
{
	mgmt_mesh = mgmt_new_default();
	if (!mgmt_mesh)
		return false;

	controllers = l_queue_new();
	if (!controllers)
		return false;

	//TODO: read mesh.conf
	mesh.prov_timeout = DEFAULT_PROV_TIMEOUT;
	mesh.algorithms = DEFAULT_ALGORITHMS;

	mgmt_register(mgmt_mesh, MGMT_EV_INDEX_ADDED, MGMT_INDEX_NONE,
						index_added, NULL, NULL);
	mgmt_register(mgmt_mesh, MGMT_EV_INDEX_REMOVED, MGMT_INDEX_NONE,
						index_removed, NULL, NULL);
	return true;
}

bool mesh_init(uint16_t index, const char *config_dir)
{
	if (initialized)
		return true;

	if (!init_mgmt()) {
		l_error("Failed to initialize mesh management");
		return false;
	}

	mesh.req_index = index;

	if (!config_dir)
		config_dir = MESH_STORAGEDIR;

	l_info("Loading node configuration from %s", config_dir);

	if (!storage_load_nodes(config_dir))
		return false;

	l_debug("send read index_list");
	if (mgmt_send(mgmt_mesh, MGMT_OP_READ_INDEX_LIST,
				MGMT_INDEX_NONE, 0, NULL,
				read_index_list_cb, NULL, NULL) <= 0)
		return false;

	return true;
}

static void attach_exit(void *data)
{
	struct l_dbus_message *reply;
	struct attach_data *pending = data;

	reply = dbus_error(pending->msg, MESH_ERROR_FAILED, "Failed. Exiting");
	l_dbus_send(dbus_get_bus(), reply);
	l_free(pending);
}

void mesh_cleanup(void)
{
	struct l_dbus_message *reply;

	mesh_io_destroy(mesh.io);
	mgmt_unref(mgmt_mesh);

	if (join_pending) {
		reply = dbus_error(join_pending->msg, MESH_ERROR_FAILED,
							"Failed. Exiting");
		l_dbus_send(dbus_get_bus(), reply);

		if (join_pending->disc_watch)
			dbus_disconnect_watch_remove(dbus_get_bus(),
						join_pending->disc_watch);
		l_free(join_pending);
	}

	l_queue_destroy(attach_queue, attach_exit);
	node_cleanup_all();

	l_queue_destroy(controllers, NULL);
	l_dbus_object_remove_interface(dbus_get_bus(), BLUEZ_MESH_PATH,
							MESH_NETWORK_INTERFACE);
	l_dbus_unregister_interface(dbus_get_bus(), MESH_NETWORK_INTERFACE);
}

const char *mesh_status_str(uint8_t err)
{
	switch (err) {
	case MESH_STATUS_SUCCESS: return "Success";
	case MESH_STATUS_INVALID_ADDRESS: return "Invalid Address";
	case MESH_STATUS_INVALID_MODEL: return "Invalid Model";
	case MESH_STATUS_INVALID_APPKEY: return "Invalid AppKey";
	case MESH_STATUS_INVALID_NETKEY: return "Invalid NetKey";
	case MESH_STATUS_INSUFF_RESOURCES: return "Insufficient Resources";
	case MESH_STATUS_IDX_ALREADY_STORED: return "Key Idx Already Stored";
	case MESH_STATUS_INVALID_PUB_PARAM: return "Invalid Publish Parameters";
	case MESH_STATUS_NOT_SUB_MOD: return "Not a Subscribe Model";
	case MESH_STATUS_STORAGE_FAIL: return "Storage Failure";
	case MESH_STATUS_FEATURE_NO_SUPPORT: return "Feature Not Supported";
	case MESH_STATUS_CANNOT_UPDATE: return "Cannot Update";
	case MESH_STATUS_CANNOT_REMOVE: return "Cannot Remove";
	case MESH_STATUS_CANNOT_BIND: return "Cannot bind";
	case MESH_STATUS_UNABLE_CHANGE_STATE: return "Unable to change state";
	case MESH_STATUS_CANNOT_SET: return "Cannot set";
	case MESH_STATUS_UNSPECIFIED_ERROR: return "Unspecified error";
	case MESH_STATUS_INVALID_BINDING: return "Invalid Binding";

	default: return "Unknown";
	}
}

/* This is being called if the app exits unexpectedly */
static void prov_disc_cb(struct l_dbus *bus, void *user_data)
{
	if (!join_pending)
		return;

	l_dbus_message_ref(join_pending->msg);

	//TODO:acceptor_cancel(&mesh);
	node_cleanup(join_pending->node);
	l_free(join_pending);
	join_pending = NULL;

	//TODO Call agent cancel
}

struct prov_action {
	const char *action;
	uint16_t output;
	uint16_t input;
	uint8_t size;
};

static struct prov_action cap_table[] = {
	{"Blink", 0x0001, 0x0000, 1},
	{"Beep", 0x0002, 0x0000, 1},
	{"Vibrate", 0x0004, 0x0000, 1},
	{"OutNumeric", 0x0008, 0x0000, 8},
	{"OutAlpha", 0x0010, 0x0000, 8},
	{"Push", 0x0000, 0x0001, 1},
	{"Twist", 0x0000, 0x0002, 1},
	{"InNumeric", 0x0000, 0x0004, 8},
	{"InAlpha", 0x0000, 0x0008, 8}
};

struct oob_info {
	const char *oob;
	uint16_t mask;
};

static struct oob_info oob_table[] = {
	{"Other", 0x0001},
	{"URI", 0x0002},
	{"MachineCode2D", 0x0004},
	{"BarCode", 0x0008},
	{"NFC", 0x0010},
	{"Number", 0x0020},
	{"String", 0x0040},
	{"OnBox", 0x0800},
	{"InBox", 0x1000},
	{"OnPaper", 0x2000},
	{"InManual", 0x4000},
	{"OnDevice", 0x8000}
};

static void set_prov_caps_from_args(struct mesh_prov_caps *caps,
					struct l_dbus_message_iter iter_caps,
					struct l_dbus_message_iter iter_oob)

{
	const char *str;
	uint32_t i;

	while (l_dbus_message_iter_next_entry(&iter_caps, &str)) {
		for (i = 0; i < L_ARRAY_SIZE(cap_table); i++) {
			if (strcmp(str, cap_table[i].action))
				continue;

			caps->output_action |= cap_table[i].output;
			if (cap_table[i].output &&
					caps->output_size < cap_table[i].size)
				caps->output_size = cap_table[i].size;

			caps->input_action |= cap_table[i].input;
			if (cap_table[i].input &&
					caps->input_size < cap_table[i].size)
				caps->input_size = cap_table[i].size;

			break;
		}

		if (!strcmp(str, "PublicOOB"))
			caps->pub_type = 1;
		else if (!strcmp(str, "StaticOOB"))
			caps->static_type = 1;
	}

	while (l_dbus_message_iter_next_entry(&iter_oob, &str)) {
		for (i = 0; i < L_ARRAY_SIZE(oob_table); i++) {
			if (strcmp(str, oob_table[i].oob))
				continue;
			caps->oob_info |= oob_table[i].mask;
		}
	}
}

static void agent_cb(struct bt_mesh *mesh, struct mesh_agent_request *req,
							uint8_t *user_data)
{
	l_debug("Agent callback");
}

static void prov_complete_cb(struct bt_mesh *mesh, uint8_t status,
					struct mesh_prov_node_info *info)
{
	struct l_dbus_message *reply;
	const uint8_t *dev_key;

	l_debug("Provisioning complete");

	//TODO agent_cancel(join_pending.agent);

	if (status != MESH_STATUS_SUCCESS) {
		reply = dbus_error(join_pending->msg, MESH_ERROR_FAILED,
							"Provisioning failed");
		goto done;
	}

	//TODO: populate node from prov_info
	//node_add_pending(join_pending->node);

	dev_key = node_get_device_key(join_pending->node);

	reply = l_dbus_message_new_method_return(join_pending->msg);
	l_dbus_message_set_arguments(reply, "t", l_get_u64(dev_key));

done:
	l_dbus_send(dbus_get_bus(), reply);
	l_free(join_pending);
	join_pending = NULL;
}

static struct l_dbus_message *join_network_call(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	const char *agent_path, *sender;
	struct l_dbus_message_iter iter_caps, iter_oob, iter_uuid, iter_comp;
	struct l_dbus_message *err_reply;
	uint32_t uri = 0, n;
	uint32_t len;

	l_debug("Join network request");

	if (join_pending)
		return dbus_error(message, MESH_ERROR_BUSY,
						"Provisioning in progress");

	if (!l_dbus_message_get_arguments(message, "oasayasuay", &agent_path,
						&iter_caps, &iter_uuid,
						&iter_oob, &uri, &iter_comp))
		return dbus_error(message, MESH_ERROR_INVALID_ARGS, NULL);

	join_pending = l_new(struct join_data, 1);

	join_pending->caps.uri_hash = uri;

	if (!l_dbus_message_iter_get_fixed_array(&iter_uuid,
				join_pending->caps.uuid, &n) || n != 16) {
		err_reply = dbus_error(message, MESH_ERROR_INVALID_ARGS,
							"Bad device UUID");
		goto fail;
	}

	/* Read composition data */
	len = dbus_get_byte_array(&iter_comp, join_pending->composition,
				L_ARRAY_SIZE(join_pending->composition));
	if (len == 0) {
		err_reply = dbus_error(message, MESH_ERROR_INVALID_ARGS,
						"Composition is required");
		goto fail;
	}

	/* Read capabilities and OOB info */
	set_prov_caps_from_args(&join_pending->caps, iter_caps, iter_oob);

	/*
	 * Create temporary node. If the provisioning is successful,
	 * the node is added to the list of local nodes.
	 */
	join_pending->node = node_init_pending(join_pending->composition, len,
						join_pending->caps.uuid);
	if (!join_pending->node) {
		err_reply = dbus_error(message, MESH_ERROR_FAILED,
							"Bad composition");
		goto fail;
	}
	/* Finish initializing provisioning info */
	join_pending->caps.num_ele = node_get_num_elements(join_pending->node);
	join_pending->caps.algorithms = mesh.algorithms;

	sender = l_dbus_message_get_sender(message);

	join_pending->disc_watch = dbus_disconnect_watch_add(dbus, sender,
							prov_disc_cb, NULL);
	join_pending->agent = agent_path;
	join_pending->msg = l_dbus_message_ref(message);

	if (acceptor_start(&mesh, &join_pending->caps, mesh.prov_timeout,
						prov_complete_cb, agent_cb))
		return NULL;

	err_reply = dbus_error(message, MESH_ERROR_FAILED,
					"Failed to set up provisioning");

fail:
	l_free(join_pending);
	join_pending = NULL;

	return err_reply;
}

static struct l_dbus_message *cancel_join_call(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct l_dbus_message *reply;

	l_debug("Cancel Join");

	l_free(join_pending);

	reply = l_dbus_message_new_method_return(message);
	l_dbus_message_set_arguments(reply, "");

	return reply;
}

static bool match_attach_request(const void *a, const void *b)
{
	const struct attach_data *pending = a;
	const uint64_t *token = b;

	return *token == pending->token;
}

static void attach_ready_cb(int status, char *node_path, uint64_t token)
{
	struct l_dbus_message *reply;
	struct attach_data *pending;

	pending = l_queue_find(attach_queue, match_attach_request, &token);
	if (!pending)
		return;

	if (status != MESH_ERROR_NONE) {
		const char *desc = (status == MESH_ERROR_NOT_FOUND) ?
				"Node match not found" : "Attach failed";
		reply = dbus_error(pending->msg, status, desc);
		goto done;
	}

	reply = l_dbus_message_new_method_return(pending->msg);

	node_build_attach_reply(reply, token);

done:
	l_dbus_send(dbus_get_bus(), reply);
	l_queue_remove(attach_queue, pending);
	l_free(pending);
}

static struct l_dbus_message *attach_call(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	uint64_t token = 1;
	const char *app_path, *sender;
	struct attach_data *pending;

	l_debug("Attach");

	if (!l_dbus_message_get_arguments(message, "ot", &app_path, &token))
		return dbus_error(message, MESH_ERROR_INVALID_ARGS, NULL);

	sender = l_dbus_message_get_sender(message);

	if (node_attach(app_path, sender, token, attach_ready_cb) !=
								MESH_ERROR_NONE)
		return dbus_error(message, MESH_ERROR_NOT_FOUND,
						"Matching node not found");

	pending = l_new(struct attach_data, 1);

	pending->token = token;
	pending->msg = l_dbus_message_ref(message);

	if (!attach_queue)
		attach_queue = l_queue_new();

	l_queue_push_tail(attach_queue, pending);

	return NULL;
}

static void setup_network_interface(struct l_dbus_interface *iface)
{
	l_dbus_interface_method(iface, "Join", 0, join_network_call, "t",
				"oasayasuay",
				"token", "agent", "capabilities", "uuid",
				"oob", "uri", "composition");

	l_dbus_interface_method(iface, "Cancel", 0, cancel_join_call, "", "");

	l_dbus_interface_method(iface, "Attach", 0, attach_call,
				"oa(ya(qa{sv}))", "ot", "node", "configuration",
				"app", "token");

#if 0 //TODO
	l_dbus_interface_method(iface, "Leave", 0, leave_network_call, "", "t");
#endif
}

bool mesh_dbus_init(struct l_dbus *dbus)
{
	if (!l_dbus_register_interface(dbus, MESH_NETWORK_INTERFACE,
						setup_network_interface,
						NULL, false)) {
		l_info("Unable to register %s interface",
			       MESH_NETWORK_INTERFACE);
		return false;
	}

	if (!l_dbus_object_add_interface(dbus, BLUEZ_MESH_PATH,
						MESH_NETWORK_INTERFACE, NULL)) {
		l_info("Unable to register the mesh object on '%s'",
							MESH_NETWORK_INTERFACE);
		l_dbus_unregister_interface(dbus, MESH_NETWORK_INTERFACE);
		return false;
	}

	l_info("Added Network Interface on %s", BLUEZ_MESH_PATH);

	return true;
}
