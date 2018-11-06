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

#define BLUEZ_MESH_NAME "org.bluez.mesh1"

#define MESH_NETWORK_INTERFACE "org.bluez.mesh1.Network"
#define MESH_NODE_INTERFACE "org.bluez.mesh1.Node"
#define MESH_ELEMENT_INTERFACE "org.bluez.mesh1.Element"
#define ERROR_INTERFACE "org.bluez.mesh1.Error"

bool mesh_init(uint16_t index, const char *in_config_name);
void mesh_cleanup(void);
bool mesh_dbus_init(struct l_dbus *dbus);

const char *mesh_status_str(uint8_t err);

