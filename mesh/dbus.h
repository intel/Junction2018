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

#define BLUEZ_MESH_PATH "/org/bluez/mesh"
#define BLUEZ_MESH_SERVICE "org.bluez.mesh"

bool dbus_init(struct l_dbus *dbus);
struct l_dbus *dbus_get_bus(void);
uint32_t dbus_disconnect_watch_add(struct l_dbus *dbus, const char *name,
					l_dbus_disconnect_func_t callback);
bool dbus_disconnect_watch_remove(struct l_dbus *dbus, uint32_t id);
uint32_t dbus_get_byte_array(struct l_dbus_message_iter *array, uint8_t *buf,
							uint32_t max_len);
bool dbus_append_byte_array(struct l_dbus_message_builder *builder,
						const uint8_t *data, int len);
bool dbus_match_interface(struct l_dbus_message_iter *interfaces,
							const char *match);
struct l_dbus_message *dbus_error(struct l_dbus_message *msg, int err,
						const char *description);
