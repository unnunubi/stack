/*
 *  C wrapper for librina
 *
 *    Addy Bombeke      <addy.bombeke@ugent.be>
 *    Sander Vrijders   <sander.vrijders@intec.ugent.be>
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
 *
 *    Copyright (C) 2015
 *
 *  This software was written as part of the MSc thesis in electrical
 *  engineering,
 *
 *  "Comparing RINA to TCP/IP for latency-constrained applications",
 *
 *  at Ghent University, Academic Year 2014-2015
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 */

#include <string>
#include <librina/librina.h>
#include "librina-c/librina-c.h"

using namespace std;
using namespace rina;

extern "C"
{

int rinaFlow_getPortId(rina_flow_t flow)
{
	return flow;
}

int rinaFlow_readSDU(rina_flow_t flow, void *sdu, int maxBytes)
{
	return ipcManager->readSDU(flow, sdu, maxBytes);
}

void rinaFlow_writeSDU(rina_flow_t flow, void *sdu, int size)
{
	ipcManager->writeSDU(flow, sdu, size);
}

int rinaFlow_getState(rina_flow_t flow)
{
	return static_cast<int>(
		ipcManager->getFlowInformation(flow).state);
}

char rinaFlow_isAllocated(rina_flow_t flow)
{
	return rinaFlow_getState(flow) == 1;
}

}
