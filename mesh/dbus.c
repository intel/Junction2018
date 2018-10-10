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
#include "mesh/cfgmod.h"
#include "mesh/model.h"
#include "mesh/mesh.h"
#include "mesh/dbus.h"


#define ERROR_INTERFACE "org.bluez.mesh.Error"

struct l_dbus *dbus;

uint32_t dbus_get_byte_array(struct l_dbus_message_iter *array, uint8_t *buf,
							uint32_t max_len)
{
	uint32_t i;

	for (i = 0; i < max_len; i++) {
		if (!l_dbus_message_iter_next_entry(array, buf + i))
			break;
	}

	return i;
}

uint32_t dbus_disconnect_watch_add(struct l_dbus *dbus, const char *name,
					l_dbus_disconnect_func_t callback)
{
	return l_dbus_add_signal_watch(dbus, "org.freedesktop.DBus",
				"/org/freedesktop/DBus",
				L_DBUS_INTERFACE_DBUS, "NameOwnerChanged",
					L_DBUS_MATCH_NONE, callback, NULL);
}

bool dbus_disconnect_watch_remove(struct l_dbus *dbus, uint32_t id)
{
	return l_dbus_remove_signal_watch(dbus, id);
}

bool dbus_init(struct l_dbus *bus)
{
	/* Network interface */
	if (!mesh_dbus_init(bus))
		return false;

	/* TODO: Node interface */

	dbus = bus;

	return true;
}

struct l_dbus *dbus_get_bus(void)
{
	return dbus;
}

struct l_dbus_message *dbus_error_invalid_args(struct l_dbus_message *msg,
						const char *description)
{
	if (description)
		return l_dbus_message_new_error(msg,
						ERROR_INTERFACE ".InvalidArgs",
						description);
	else
		return l_dbus_message_new_error(msg,
						ERROR_INTERFACE ".InvalidArgs",
						"Invalid arguments");
}

struct l_dbus_message *dbus_error_busy(struct l_dbus_message *msg,
						const char *description)
{
	if (description)
		return l_dbus_message_new_error(msg,
						ERROR_INTERFACE ".InProgress",
						description);
	else
		return l_dbus_message_new_error(msg,
						ERROR_INTERFACE ".InProgress",
						"Already in progress");
}

struct l_dbus_message *dbus_error_already_exists(struct l_dbus_message *msg,
						const char *description)
{
	if (description)
		return l_dbus_message_new_error(msg,
					ERROR_INTERFACE ".AlreadyExists",
					description);
	else
		return l_dbus_message_new_error(msg,
					ERROR_INTERFACE ".AlreadyExists",
						"Already exists");
}

struct l_dbus_message *dbus_error_failed(struct l_dbus_message *msg,
						const char *description)
{
	if (description)
		return l_dbus_message_new_error(msg,
					ERROR_INTERFACE ".Failed",
					description);
	else
		return l_dbus_message_new_error(msg,
					ERROR_INTERFACE ".Failed",
						"Operation failed");
}
