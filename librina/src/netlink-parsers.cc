/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/*
 * librina-netlink-parsers.cc
 *
 *  Created on: 14/06/2013
 *      Author: eduardgrasa
 */

#define RINA_PREFIX "netlink-parsers"

#include "logs.h"
#include "netlink-parsers.h"

namespace rina {

int putBaseNetlinkMessage(nl_msg* netlinkMessage,
		BaseNetlinkMessage * message) {
	switch (message->getOperationCode()) {
	case RINA_C_APP_ALLOCATE_FLOW_REQUEST: {
		AppAllocateFlowRequestMessage * allocateObject =
				dynamic_cast<AppAllocateFlowRequestMessage *>(message);
		if (putAppAllocateFlowRequestMessageObject(netlinkMessage,
				*allocateObject) < 0) {
			return -1;
		}
		return 0;
	}
	case RINA_C_APP_ALLOCATE_FLOW_REQUEST_RESULT: {
		AppAllocateFlowRequestResultMessage * allocateFlowRequestResultObject =
				dynamic_cast<AppAllocateFlowRequestResultMessage *>(message);
		if (putAppAllocateFlowRequestResultMessageObject(netlinkMessage,
				*allocateFlowRequestResultObject) < 0) {
			return -1;
		}
		return 0;
	}
	case RINA_C_APP_ALLOCATE_FLOW_REQUEST_ARRIVED: {
		AppAllocateFlowRequestArrivedMessage * allocateFlowRequestArrivedObject =
				dynamic_cast<AppAllocateFlowRequestArrivedMessage *>(message);
		if (putAppAllocateFlowRequestArrivedMessageObject(netlinkMessage,
				*allocateFlowRequestArrivedObject) < 0) {
			return -1;
		}
		return 0;
	}
	case RINA_C_APP_ALLOCATE_FLOW_RESPONSE: {
		AppAllocateFlowResponseMessage * allocateFlowResponseObject =
				dynamic_cast<AppAllocateFlowResponseMessage *>(message);
		if (putAppAllocateFlowResponseMessageObject(netlinkMessage,
				*allocateFlowResponseObject) < 0) {
			return -1;
		}
		return 0;
	}
	case RINA_C_APP_DEALLOCATE_FLOW_REQUEST: {
		AppDeallocateFlowRequestMessage * deallocateFlowRequestObject =
				dynamic_cast<AppDeallocateFlowRequestMessage *>(message);
		if (putAppDeallocateFlowRequestMessageObject(netlinkMessage,
				*deallocateFlowRequestObject) < 0) {
			return -1;
		}
		return 0;
	}
	case RINA_C_APP_DEALLOCATE_FLOW_RESPONSE: {
		AppDeallocateFlowResponseMessage * deallocateFlowResponseObject =
				dynamic_cast<AppDeallocateFlowResponseMessage *>(message);
		if (putAppDeallocateFlowResponseMessageObject(netlinkMessage,
				*deallocateFlowResponseObject) < 0) {
			return -1;
		}
		return 0;
	}
	case RINA_C_APP_FLOW_DEALLOCATED_NOTIFICATION: {
		AppFlowDeallocatedNotificationMessage * flowDeallocatedNotificationObject =
				dynamic_cast<AppFlowDeallocatedNotificationMessage *>(message);
		if (putAppFlowDeallocatedNotificationMessageObject(netlinkMessage,
				*flowDeallocatedNotificationObject) < 0) {
			return -1;
		}
		return 0;
	}
	case RINA_C_APP_REGISTER_APPLICATION_REQUEST: {
		AppRegisterApplicationRequestMessage * registerApplicationRequestObject =
				dynamic_cast<AppRegisterApplicationRequestMessage *>(message);
		if (putAppRegisterApplicationRequestMessageObject(netlinkMessage,
				*registerApplicationRequestObject) < 0) {
			return -1;
		}
		return 0;
	}
	case RINA_C_APP_REGISTER_APPLICATION_RESPONSE: {
		AppRegisterApplicationResponseMessage * registerApplicationResponseObject =
				dynamic_cast<AppRegisterApplicationResponseMessage *>(message);
		if (putAppRegisterApplicationResponseMessageObject(netlinkMessage,
				*registerApplicationResponseObject) < 0) {
			return -1;
		}
		return 0;
	}
	case RINA_C_IPCM_REGISTER_APPLICATION_REQUEST: {
		IpcmRegisterApplicationRequestMessage * registerApplicationRequestObject =
				dynamic_cast<IpcmRegisterApplicationRequestMessage *>(message);
		if (putIpcmRegisterApplicationRequestMessageObject(netlinkMessage,
				*registerApplicationRequestObject) < 0) {
			return -1;
		}
		return 0;
	}
	case RINA_C_IPCM_REGISTER_APPLICATION_RESPONSE: {
		IpcmRegisterApplicationResponseMessage * registerApplicationResponseObject =
				dynamic_cast<IpcmRegisterApplicationResponseMessage *>(message);
		if (putIpcmRegisterApplicationResponseMessageObject(netlinkMessage,
				*registerApplicationResponseObject) < 0) {
			return -1;
		}
		return 0;
	}
	case RINA_C_IPCM_ASSIGN_TO_DIF_REQUEST: {
		IpcmAssignToDIFRequestMessage * assignToDIFRequestObject =
				dynamic_cast<IpcmAssignToDIFRequestMessage *>(message);
		if (putIpcmAssignToDIFRequestMessageObject(netlinkMessage,
				*assignToDIFRequestObject) < 0) {
			return -1;
		}
		return 0;
	}
	case RINA_C_IPCM_ASSIGN_TO_DIF_RESPONSE: {
		IpcmAssignToDIFResponseMessage * assignToDIFResponseObject =
				dynamic_cast<IpcmAssignToDIFResponseMessage *>(message);
		if (putIpcmAssignToDIFResponseMessageObject(netlinkMessage,
				*assignToDIFResponseObject) < 0) {
			return -1;
		}
		return 0;
	}
	case RINA_C_IPCM_ALLOCATE_FLOW_REQUEST: {
		IpcmAllocateFlowRequestMessage * allocateFlowRequestObject =
				dynamic_cast<IpcmAllocateFlowRequestMessage *>(message);
		if (putIpcmAllocateFlowRequestMessageObject(netlinkMessage,
				*allocateFlowRequestObject) < 0) {
			return -1;
		}
		return 0;
	}
	case RINA_C_IPCM_ALLOCATE_FLOW_RESPONSE: {
		IpcmAllocateFlowResponseMessage * allocateFlowResponseObject =
				dynamic_cast<IpcmAllocateFlowResponseMessage *>(message);
		if (putIpcmAllocateFlowResponseMessageObject(netlinkMessage,
				*allocateFlowResponseObject) < 0) {
			return -1;
		}
		return 0;
	}
	case RINA_C_IPCM_IPC_PROCESS_REGISTERED_TO_DIF_NOTIFICATION: {
		IpcmIPCProcessRegisteredToDIFNotification * notificationMessage =
			dynamic_cast<IpcmIPCProcessRegisteredToDIFNotification *>(message);
		if (putIpcmIPCProcessRegisteredToDIFNotificationObject(netlinkMessage,
				*notificationMessage) < 0) {
			return -1;
		}
		return 0;
	}

	default: {
		return -1;
	}

	}
}

BaseNetlinkMessage * parseBaseNetlinkMessage(nlmsghdr* netlinkMessageHeader) {
	struct genlmsghdr *nlhdr;
	nlhdr = (genlmsghdr *) nlmsg_data(netlinkMessageHeader);

	switch (nlhdr->cmd) {
	case RINA_C_APP_ALLOCATE_FLOW_REQUEST: {
		return parseAppAllocateFlowRequestMessage(netlinkMessageHeader);
	}
	case RINA_C_APP_ALLOCATE_FLOW_REQUEST_RESULT: {
		return parseAppAllocateFlowRequestResultMessage(netlinkMessageHeader);
	}
	case RINA_C_APP_ALLOCATE_FLOW_REQUEST_ARRIVED: {
		return parseAppAllocateFlowRequestArrivedMessage(
				netlinkMessageHeader);
	}
	case RINA_C_APP_ALLOCATE_FLOW_RESPONSE: {
		return parseAppAllocateFlowResponseMessage(netlinkMessageHeader);
	}
	case RINA_C_APP_DEALLOCATE_FLOW_REQUEST: {
		return parseAppDeallocateFlowRequestMessage(netlinkMessageHeader);
	}
	case RINA_C_APP_DEALLOCATE_FLOW_RESPONSE: {
		return parseAppDeallocateFlowResponseMessage(netlinkMessageHeader);
	}
	case RINA_C_APP_FLOW_DEALLOCATED_NOTIFICATION: {
		return parseAppFlowDeallocatedNotificationMessage(
				netlinkMessageHeader);
	}
	case RINA_C_APP_REGISTER_APPLICATION_REQUEST: {
		return parseAppRegisterApplicationRequestMessage(
				netlinkMessageHeader);
	}
	case RINA_C_APP_REGISTER_APPLICATION_RESPONSE: {
		return parseAppRegisterApplicationResponseMessage(
				netlinkMessageHeader);
	}
	case RINA_C_IPCM_REGISTER_APPLICATION_REQUEST: {
		return parseIpcmRegisterApplicationRequestMessage(
				netlinkMessageHeader);
	}
	case RINA_C_IPCM_REGISTER_APPLICATION_RESPONSE: {
		return parseIpcmRegisterApplicationResponseMessage(
				netlinkMessageHeader);
	}
	case RINA_C_IPCM_ASSIGN_TO_DIF_REQUEST: {
		return parseIpcmAssignToDIFRequestMessage(netlinkMessageHeader);
	}
	case RINA_C_IPCM_ASSIGN_TO_DIF_RESPONSE: {
		return parseIpcmAssignToDIFResponseMessage(netlinkMessageHeader);
	}
	case RINA_C_IPCM_ALLOCATE_FLOW_REQUEST: {
		return parseIpcmAllocateFlowRequestMessage(netlinkMessageHeader);
	}
	case RINA_C_IPCM_ALLOCATE_FLOW_RESPONSE: {
		return parseIpcmAllocateFlowResponseMessage(netlinkMessageHeader);
	}
	case RINA_C_IPCM_IPC_PROCESS_REGISTERED_TO_DIF_NOTIFICATION: {
		return parseIpcmIPCProcessRegisteredToDIFNotification(
				netlinkMessageHeader);
	}
	default: {
		LOG_ERR(
				"Generic Netlink message contains unrecognized command code: %d",
				nlhdr->cmd);
		return NULL;
	}
	}
}

int putApplicationProcessNamingInformationObject(nl_msg* netlinkMessage,
		const ApplicationProcessNamingInformation& object) {
	NLA_PUT_STRING(netlinkMessage, APNI_ATTR_PROCESS_NAME,
			object.getProcessName().c_str());
	NLA_PUT_STRING(netlinkMessage, APNI_ATTR_PROCESS_INSTANCE,
			object.getProcessInstance().c_str());
	NLA_PUT_STRING(netlinkMessage, APNI_ATTR_ENTITY_NAME,
			object.getEntityName().c_str());
	NLA_PUT_STRING(netlinkMessage, APNI_ATTR_ENTITY_INSTANCE,
			object.getEntityInstance().c_str());

	return 0;

	nla_put_failure: LOG_ERR(
			"Error building ApplicationProcessNamingInformation Netlink object");
	return -1;
}

ApplicationProcessNamingInformation *
parseApplicationProcessNamingInformationObject(nlattr *nested) {
	struct nla_policy attr_policy[APNI_ATTR_MAX + 1];
	attr_policy[APNI_ATTR_PROCESS_NAME].type = NLA_STRING;
	attr_policy[APNI_ATTR_PROCESS_NAME].minlen = 0;
	attr_policy[APNI_ATTR_PROCESS_NAME].maxlen = 65535;
	attr_policy[APNI_ATTR_PROCESS_INSTANCE].type = NLA_STRING;
	attr_policy[APNI_ATTR_PROCESS_INSTANCE].minlen = 0;
	attr_policy[APNI_ATTR_PROCESS_INSTANCE].maxlen = 65535;
	attr_policy[APNI_ATTR_ENTITY_NAME].type = NLA_STRING;
	attr_policy[APNI_ATTR_ENTITY_NAME].minlen = 0;
	attr_policy[APNI_ATTR_ENTITY_NAME].maxlen = 65535;
	attr_policy[APNI_ATTR_ENTITY_INSTANCE].type = NLA_STRING;
	attr_policy[APNI_ATTR_ENTITY_INSTANCE].minlen = 0;
	attr_policy[APNI_ATTR_ENTITY_INSTANCE].maxlen = 65535;
	struct nlattr *attrs[APNI_ATTR_MAX + 1];

	int err = nla_parse_nested(attrs, APNI_ATTR_MAX, nested, attr_policy);
	if (err < 0) {
		LOG_ERR(
				"Error parsing ApplicationProcessNaming information from Netlink message: %d",
				err);
		return NULL;
	}

	ApplicationProcessNamingInformation * result =
			new ApplicationProcessNamingInformation();
	if (attrs[APNI_ATTR_PROCESS_NAME]) {
		result->setProcessName(nla_get_string(attrs[APNI_ATTR_PROCESS_NAME]));
	}

	if (attrs[APNI_ATTR_PROCESS_INSTANCE]) {
		result->setProcessInstance(
				nla_get_string(attrs[APNI_ATTR_PROCESS_INSTANCE]));
	}

	if (attrs[APNI_ATTR_ENTITY_NAME]) {
		result->setEntityName(nla_get_string(attrs[APNI_ATTR_ENTITY_NAME]));
	}

	if (attrs[APNI_ATTR_ENTITY_INSTANCE]) {
		result->setEntityInstance(
				nla_get_string(attrs[APNI_ATTR_ENTITY_INSTANCE]));
	}

	return result;
}

int putFlowSpecificationObject(nl_msg* netlinkMessage,
		const FlowSpecification& object) {
	if (object.getAverageBandwidth() > 0) {
		NLA_PUT_U32(netlinkMessage, FSPEC_ATTR_AVG_BWITH,
				object.getAverageBandwidth());
	}
	if (object.getAverageSduBandwidth() > 0) {
		NLA_PUT_U32(netlinkMessage, FSPEC_ATTR_AVG_SDU_BWITH,
				object.getAverageSduBandwidth());
	}
	if (object.getDelay() > 0) {
		NLA_PUT_U32(netlinkMessage, FSPEC_ATTR_DELAY, object.getDelay());
	}
	if (object.getJitter() > 0) {
		NLA_PUT_U32(netlinkMessage, FSPEC_ATTR_JITTER, object.getJitter());
	}
	if (object.getMaxAllowableGap() >= 0) {
		NLA_PUT_U32(netlinkMessage, FSPEC_ATTR_MAX_GAP,
				object.getMaxAllowableGap());
	}
	if (object.getMaxSDUSize() > 0) {
		NLA_PUT_U32(netlinkMessage, FSPEC_ATTR_MAX_SDU_SIZE,
				object.getMaxSDUSize());
	}
	if (object.isOrderedDelivery()) {
		NLA_PUT_FLAG(netlinkMessage, FSPEC_ATTR_IN_ORD_DELIVERY);
	}
	if (object.isPartialDelivery()) {
		NLA_PUT_FLAG(netlinkMessage, FSPEC_ATTR_PART_DELIVERY);
	}
	if (object.getPeakBandwidthDuration() > 0) {
		NLA_PUT_U32(netlinkMessage, FSPEC_ATTR_PEAK_BWITH_DURATION,
				object.getPeakBandwidthDuration());
	}
	if (object.getPeakSduBandwidthDuration() > 0) {
		NLA_PUT_U32(netlinkMessage, FSPEC_ATTR_PEAK_SDU_BWITH_DURATION,
				object.getPeakSduBandwidthDuration());
	}
	if (object.getUndetectedBitErrorRate() > 0) {
		NLA_PUT_U32(netlinkMessage, FSPEC_ATTR_UNDETECTED_BER,
				object.getUndetectedBitErrorRate());
	}

	return 0;

	nla_put_failure: LOG_ERR(
			"Error building ApplicationProcessNamingInformation Netlink object");
	return -1;
}

FlowSpecification * parseFlowSpecificationObject(nlattr *nested) {
	struct nla_policy attr_policy[FSPEC_ATTR_MAX + 1];
	attr_policy[FSPEC_ATTR_AVG_BWITH].type = NLA_U32;
	attr_policy[FSPEC_ATTR_AVG_BWITH].minlen = 4;
	attr_policy[FSPEC_ATTR_AVG_BWITH].maxlen = 4;
	attr_policy[FSPEC_ATTR_AVG_SDU_BWITH].type = NLA_U32;
	attr_policy[FSPEC_ATTR_AVG_SDU_BWITH].minlen = 4;
	attr_policy[FSPEC_ATTR_AVG_SDU_BWITH].maxlen = 4;
	attr_policy[FSPEC_ATTR_DELAY].type = NLA_U32;
	attr_policy[FSPEC_ATTR_DELAY].minlen = 4;
	attr_policy[FSPEC_ATTR_DELAY].maxlen = 4;
	attr_policy[FSPEC_ATTR_JITTER].type = NLA_U32;
	attr_policy[FSPEC_ATTR_JITTER].minlen = 4;
	attr_policy[FSPEC_ATTR_JITTER].maxlen = 4;
	attr_policy[FSPEC_ATTR_MAX_GAP].type = NLA_U32;
	attr_policy[FSPEC_ATTR_MAX_GAP].minlen = 4;
	attr_policy[FSPEC_ATTR_MAX_GAP].maxlen = 4;
	attr_policy[FSPEC_ATTR_MAX_SDU_SIZE].type = NLA_U32;
	attr_policy[FSPEC_ATTR_MAX_SDU_SIZE].minlen = 4;
	attr_policy[FSPEC_ATTR_MAX_SDU_SIZE].maxlen = 4;
	attr_policy[FSPEC_ATTR_IN_ORD_DELIVERY].type = NLA_FLAG;
	attr_policy[FSPEC_ATTR_IN_ORD_DELIVERY].minlen = 0;
	attr_policy[FSPEC_ATTR_IN_ORD_DELIVERY].maxlen = 0;
	attr_policy[FSPEC_ATTR_PART_DELIVERY].type = NLA_FLAG;
	attr_policy[FSPEC_ATTR_PART_DELIVERY].minlen = 0;
	attr_policy[FSPEC_ATTR_PART_DELIVERY].maxlen = 0;
	attr_policy[FSPEC_ATTR_PEAK_BWITH_DURATION].type = NLA_U32;
	attr_policy[FSPEC_ATTR_PEAK_BWITH_DURATION].minlen = 4;
	attr_policy[FSPEC_ATTR_PEAK_BWITH_DURATION].maxlen = 4;
	attr_policy[FSPEC_ATTR_PEAK_SDU_BWITH_DURATION].type = NLA_U32;
	attr_policy[FSPEC_ATTR_PEAK_SDU_BWITH_DURATION].minlen = 4;
	attr_policy[FSPEC_ATTR_PEAK_SDU_BWITH_DURATION].maxlen = 4;
	attr_policy[FSPEC_ATTR_UNDETECTED_BER].type = NLA_U32;
	attr_policy[FSPEC_ATTR_UNDETECTED_BER].minlen = 4;
	attr_policy[FSPEC_ATTR_UNDETECTED_BER].maxlen = 4;
	struct nlattr *attrs[FSPEC_ATTR_MAX + 1];

	int err = nla_parse_nested(attrs, FSPEC_ATTR_MAX, nested, attr_policy);
	if (err < 0) {
		LOG_ERR(
				"Error parsing FlowSpecification object from Netlink message: %d",
				err);
		return NULL;
	}

	FlowSpecification * result = new FlowSpecification();
	if (attrs[FSPEC_ATTR_AVG_BWITH]) {
		result->setAverageBandwidth(nla_get_u32(attrs[FSPEC_ATTR_AVG_BWITH]));
	}

	if (attrs[FSPEC_ATTR_AVG_SDU_BWITH]) {
		result->setAverageSduBandwidth(
				nla_get_u32(attrs[FSPEC_ATTR_AVG_SDU_BWITH]));
	}

	if (attrs[FSPEC_ATTR_DELAY]) {
		result->setDelay(nla_get_u32(attrs[FSPEC_ATTR_DELAY]));
	}

	if (attrs[FSPEC_ATTR_JITTER]) {
		result->setJitter(nla_get_u32(attrs[FSPEC_ATTR_JITTER]));
	}

	if (attrs[FSPEC_ATTR_MAX_GAP]) {
		result->setMaxAllowableGap(nla_get_u32(attrs[FSPEC_ATTR_MAX_GAP]));
	}

	if (attrs[FSPEC_ATTR_MAX_SDU_SIZE]) {
		result->setMaxSDUSize(nla_get_u32(attrs[FSPEC_ATTR_MAX_SDU_SIZE]));
	}

	if (attrs[FSPEC_ATTR_IN_ORD_DELIVERY]) {
		result->setOrderedDelivery(true);
	} else {
		result->setOrderedDelivery(false);
	}

	if (attrs[FSPEC_ATTR_PART_DELIVERY]) {
		result->setPartialDelivery(true);
	} else {
		result->setPartialDelivery(false);
	}

	if (attrs[FSPEC_ATTR_PEAK_BWITH_DURATION]) {
		result->setPeakBandwidthDuration(
				nla_get_u32(attrs[FSPEC_ATTR_PEAK_BWITH_DURATION]));
	}

	if (attrs[FSPEC_ATTR_PEAK_SDU_BWITH_DURATION]) {
		result->setPeakSduBandwidthDuration(
				nla_get_u32(attrs[FSPEC_ATTR_PEAK_SDU_BWITH_DURATION]));
	}

	return result;
}

int putAppAllocateFlowRequestMessageObject(nl_msg* netlinkMessage,
		const AppAllocateFlowRequestMessage& object) {
	struct nlattr *sourceAppName, *destinationAppName, *flowSpec;

	if (!(sourceAppName = nla_nest_start(netlinkMessage,
			AAFR_ATTR_SOURCE_APP_NAME))) {
		goto nla_put_failure;
	}
	if (putApplicationProcessNamingInformationObject(netlinkMessage,
			object.getSourceAppName()) < 0) {
		goto nla_put_failure;
	}
	nla_nest_end(netlinkMessage, sourceAppName);

	if (!(destinationAppName = nla_nest_start(netlinkMessage,
			AAFR_ATTR_DEST_APP_NAME))) {
		goto nla_put_failure;
	}

	if (putApplicationProcessNamingInformationObject(netlinkMessage,
			object.getDestAppName()) < 0) {
		goto nla_put_failure;
	}
	nla_nest_end(netlinkMessage, destinationAppName);

	if (!(flowSpec = nla_nest_start(netlinkMessage, AAFR_ATTR_FLOW_SPEC))) {
		goto nla_put_failure;
	}

	if (putFlowSpecificationObject(netlinkMessage,
			object.getFlowSpecification()) < 0) {
		goto nla_put_failure;
	}
	nla_nest_end(netlinkMessage, flowSpec);

	return 0;

	nla_put_failure: LOG_ERR(
			"Error building AppAllocateFlowRequestMessage Netlink object");
	return -1;
}

int putAppAllocateFlowRequestResultMessageObject(nl_msg* netlinkMessage,
		const AppAllocateFlowRequestResultMessage& object) {

	struct nlattr *sourceAppName, *difName;

	if (!(sourceAppName = nla_nest_start(netlinkMessage,
			AAFRR_ATTR_SOURCE_APP_NAME))) {
		goto nla_put_failure;
	}
	if (putApplicationProcessNamingInformationObject(netlinkMessage,
			object.getSourceAppName()) < 0) {
		goto nla_put_failure;
	}
	nla_nest_end(netlinkMessage, sourceAppName);

	NLA_PUT_U32(netlinkMessage, AAFRR_ATTR_PORT_ID, object.getPortId());

	NLA_PUT_STRING(netlinkMessage, AAFRR_ATTR_ERROR_DESCRIPTION,
			object.getErrorDescription().c_str());

	if (object.getPortId() > 0) {
		if (!(difName = nla_nest_start(netlinkMessage, AAFRR_ATTR_DIF_NAME))) {
			goto nla_put_failure;
		}
		if (putApplicationProcessNamingInformationObject(netlinkMessage,
				object.getDifName()) < 0) {
			goto nla_put_failure;
		}
		nla_nest_end(netlinkMessage, difName);

		NLA_PUT_U32(netlinkMessage, AAFRR_ATTR_IPC_PROCESS_PORT_ID,
				object.getIpcProcessPortId());

		NLA_PUT_U16(netlinkMessage, AAFRR_ATTR_IPC_PROCESS_ID,
						object.getIpcProcessId());
	}

	return 0;

	nla_put_failure: LOG_ERR(
			"Error building AppAllocateFlowRequestResponseMessage Netlink object");
	return -1;
}

int putAppAllocateFlowRequestArrivedMessageObject(nl_msg* netlinkMessage,
		const AppAllocateFlowRequestArrivedMessage& object) {
	struct nlattr *sourceAppName, *destinationAppName, *flowSpec, *difName;

	if (!(sourceAppName = nla_nest_start(netlinkMessage,
			AAFRA_ATTR_SOURCE_APP_NAME))) {
		goto nla_put_failure;
	}
	if (putApplicationProcessNamingInformationObject(netlinkMessage,
			object.getSourceAppName()) < 0) {
		goto nla_put_failure;
	}
	nla_nest_end(netlinkMessage, sourceAppName);

	if (!(destinationAppName = nla_nest_start(netlinkMessage,
			AAFRA_ATTR_DEST_APP_NAME))) {
		goto nla_put_failure;
	}

	if (putApplicationProcessNamingInformationObject(netlinkMessage,
			object.getDestAppName()) < 0) {
		goto nla_put_failure;
	}
	nla_nest_end(netlinkMessage, destinationAppName);

	if (!(flowSpec = nla_nest_start(netlinkMessage, AAFRA_ATTR_FLOW_SPEC))) {
		goto nla_put_failure;
	}

	if (putFlowSpecificationObject(netlinkMessage,
			object.getFlowSpecification()) < 0) {
		goto nla_put_failure;
	}
	nla_nest_end(netlinkMessage, flowSpec);

	NLA_PUT_U32(netlinkMessage, AAFRA_ATTR_PORT_ID, object.getPortId());

	if (!(difName = nla_nest_start(netlinkMessage, AAFRA_ATTR_DIF_NAME))) {
		goto nla_put_failure;
	}
	if (putApplicationProcessNamingInformationObject(netlinkMessage,
			object.getDifName()) < 0) {
		goto nla_put_failure;
	}
	nla_nest_end(netlinkMessage, difName);

	return 0;

	nla_put_failure: LOG_ERR(
			"Error building AppAllocateFlowRequestArrivedMessage Netlink object");
	return -1;
}

int putAppAllocateFlowResponseMessageObject(nl_msg* netlinkMessage,
		const AppAllocateFlowResponseMessage& object) {

	struct nlattr *difName;

	if (!(difName = nla_nest_start(netlinkMessage, AAFRE_ATTR_DIF_NAME))) {
		goto nla_put_failure;
	}
	if (putApplicationProcessNamingInformationObject(netlinkMessage,
			object.getDifName()) < 0) {
		goto nla_put_failure;
	}
	nla_nest_end(netlinkMessage, difName);

	NLA_PUT_FLAG(netlinkMessage, AAFRE_ATTR_ACCEPT);
	NLA_PUT_STRING(netlinkMessage, AAFRE_ATTR_DENY_REASON,
			object.getDenyReason().c_str());
	NLA_PUT_FLAG(netlinkMessage, AAFRE_ATTR_NOTIFY_SOURCE);

	return 0;

	nla_put_failure: LOG_ERR(
			"Error building ApplicationProcessNamingInformation Netlink object");
	return -1;
}

int putAppDeallocateFlowRequestMessageObject(nl_msg* netlinkMessage,
		const AppDeallocateFlowRequestMessage& object) {

	struct nlattr *difName, *applicationName;

	NLA_PUT_U32(netlinkMessage, ADFRT_ATTR_PORT_ID, object.getPortId());

	if (!(difName = nla_nest_start(netlinkMessage, ADFRT_ATTR_DIF_NAME))) {
		goto nla_put_failure;
	}
	if (putApplicationProcessNamingInformationObject(netlinkMessage,
			object.getDifName()) < 0) {
		goto nla_put_failure;
	}
	nla_nest_end(netlinkMessage, difName);

	if (!(applicationName = nla_nest_start(netlinkMessage, ADFRT_ATTR_APP_NAME))) {
		goto nla_put_failure;
	}
	if (putApplicationProcessNamingInformationObject(netlinkMessage,
			object.getApplicationName()) < 0) {
		goto nla_put_failure;
	}
	nla_nest_end(netlinkMessage, applicationName);

	return 0;

	nla_put_failure: LOG_ERR(
			"Error building AppDeallocateFlowRequestMessage Netlink object");
	return -1;
}

int putAppDeallocateFlowResponseMessageObject(nl_msg* netlinkMessage,
		const AppDeallocateFlowResponseMessage& object) {

	struct nlattr *applicationName;

	NLA_PUT_U32(netlinkMessage, ADFRE_ATTR_RESULT, object.getResult());
	NLA_PUT_STRING(netlinkMessage, ADFRE_ATTR_ERROR_DESCRIPTION,
			object.getErrorDescription().c_str());

	if (!(applicationName = nla_nest_start(netlinkMessage, ADFRE_ATTR_APP_NAME))) {
		goto nla_put_failure;
	}
	if (putApplicationProcessNamingInformationObject(netlinkMessage,
			object.getApplicationName()) < 0) {
		goto nla_put_failure;
	}
	nla_nest_end(netlinkMessage, applicationName);

	return 0;

	nla_put_failure: LOG_ERR(
			"Error building AppDeallocateFlowResponseMessage Netlink object");
	return -1;
}

int putAppFlowDeallocatedNotificationMessageObject(nl_msg* netlinkMessage,
		const AppFlowDeallocatedNotificationMessage& object) {
	struct nlattr *difName, *applicationName;

	NLA_PUT_U32(netlinkMessage, AFDN_ATTR_PORT_ID, object.getPortId());
	NLA_PUT_U32(netlinkMessage, AFDN_ATTR_CODE, object.getCode());
	NLA_PUT_STRING(netlinkMessage, AFDN_ATTR_REASON,
			object.getReason().c_str());

	if (!(applicationName = nla_nest_start(netlinkMessage, AFDN_ATTR_APP_NAME))) {
		goto nla_put_failure;
	}
	if (putApplicationProcessNamingInformationObject(netlinkMessage,
			object.getApplicationName()) < 0) {
		goto nla_put_failure;
	}
	nla_nest_end(netlinkMessage, applicationName);

	if (!(difName = nla_nest_start(netlinkMessage, AFDN_ATTR_DIF_NAME))) {
		goto nla_put_failure;
	}
	if (putApplicationProcessNamingInformationObject(netlinkMessage,
			object.getDifName()) < 0) {
		goto nla_put_failure;
	}
	nla_nest_end(netlinkMessage, difName);

	return 0;

	nla_put_failure: LOG_ERR(
			"Error building AppFlowDeallocatedNotificationMessage Netlink object");
	return -1;
}

int putAppRegisterApplicationRequestMessageObject(nl_msg* netlinkMessage,
		const AppRegisterApplicationRequestMessage& object) {
	struct nlattr *difName, *applicationName;

	if (!(applicationName = nla_nest_start(netlinkMessage, ARAR_ATTR_APP_NAME))) {
		goto nla_put_failure;
	}
	if (putApplicationProcessNamingInformationObject(netlinkMessage,
			object.getApplicationName()) < 0) {
		goto nla_put_failure;
	}
	nla_nest_end(netlinkMessage, applicationName);

	if (!(difName = nla_nest_start(netlinkMessage, ARAR_ATTR_DIF_NAME))) {
		goto nla_put_failure;
	}
	if (putApplicationProcessNamingInformationObject(netlinkMessage,
			object.getDifName()) < 0) {
		goto nla_put_failure;
	}
	nla_nest_end(netlinkMessage, difName);

	return 0;

	nla_put_failure: LOG_ERR(
			"Error building AppRegisterApplicationRequestMessage Netlink object");
	return -1;
}

int putAppRegisterApplicationResponseMessageObject(nl_msg* netlinkMessage,
		const AppRegisterApplicationResponseMessage& object) {
	struct nlattr *difName, *applicationName;

	NLA_PUT_U32(netlinkMessage, ARARE_ATTR_RESULT, object.getResult());
	NLA_PUT_STRING(netlinkMessage, ARARE_ATTR_ERROR_DESCRIPTION,
			object.getErrorDescription().c_str());
	NLA_PUT_U32(netlinkMessage, ARARE_ATTR_PROCESS_PORT_ID,
			object.getIpcProcessPortId());
	NLA_PUT_U16(netlinkMessage, ARARE_ATTR_PROCESS_IPC_PROCESS_ID,
				object.getIpcProcessId());

	if (!(applicationName = nla_nest_start(netlinkMessage, ARARE_ATTR_APP_NAME))) {
		goto nla_put_failure;
	}
	if (putApplicationProcessNamingInformationObject(netlinkMessage,
			object.getApplicationName()) < 0) {
		goto nla_put_failure;
	}
	nla_nest_end(netlinkMessage, applicationName);

	if (!(difName = nla_nest_start(netlinkMessage, ARARE_ATTR_DIF_NAME))) {
		goto nla_put_failure;
	}
	if (putApplicationProcessNamingInformationObject(netlinkMessage,
			object.getDifName()) < 0) {
		goto nla_put_failure;
	}
	nla_nest_end(netlinkMessage, difName);

	return 0;

	nla_put_failure: LOG_ERR(
			"Error building AppRegisterApplicationResponseMessage Netlink object");
	return -1;
}

int putIpcmRegisterApplicationRequestMessageObject(nl_msg* netlinkMessage,
		const IpcmRegisterApplicationRequestMessage& object){
	struct nlattr *difName, *applicationName;

	if (!(applicationName = nla_nest_start(netlinkMessage, IRAR_ATTR_APP_NAME))) {
		goto nla_put_failure;
	}
	if (putApplicationProcessNamingInformationObject(netlinkMessage,
			object.getApplicationName()) < 0) {
		goto nla_put_failure;
	}
	nla_nest_end(netlinkMessage, applicationName);

	if (!(difName = nla_nest_start(netlinkMessage, IRAR_ATTR_DIF_NAME))) {
		goto nla_put_failure;
	}
	if (putApplicationProcessNamingInformationObject(netlinkMessage,
			object.getDifName()) < 0) {
		goto nla_put_failure;
	}
	nla_nest_end(netlinkMessage, difName);

	NLA_PUT_U32(netlinkMessage, IRAR_ATTR_APP_PORT_ID,
			object.getApplicationPortId());

	return 0;

	nla_put_failure: LOG_ERR(
			"Error building IpcmRegisterApplicationRequestMessage Netlink object");
	return -1;
}

int putIpcmRegisterApplicationResponseMessageObject(nl_msg* netlinkMessage,
		const IpcmRegisterApplicationResponseMessage& object) {
	struct nlattr *difName, *applicationName;

	NLA_PUT_U32(netlinkMessage, IRARE_ATTR_RESULT, object.getResult());
	NLA_PUT_STRING(netlinkMessage, IRARE_ATTR_ERROR_DESCRIPTION,
			object.getErrorDescription().c_str());

	if (!(applicationName = nla_nest_start(netlinkMessage, IRARE_ATTR_APP_NAME))) {
		goto nla_put_failure;
	}
	if (putApplicationProcessNamingInformationObject(netlinkMessage,
			object.getApplicationName()) < 0) {
		goto nla_put_failure;
	}
	nla_nest_end(netlinkMessage, applicationName);

	if (!(difName = nla_nest_start(netlinkMessage, IRARE_ATTR_DIF_NAME))) {
		goto nla_put_failure;
	}
	if (putApplicationProcessNamingInformationObject(netlinkMessage,
			object.getDifName()) < 0) {
		goto nla_put_failure;
	}
	nla_nest_end(netlinkMessage, difName);

	return 0;

	nla_put_failure: LOG_ERR(
			"Error building IpcmRegisterApplicationResponseMessage Netlink object");
	return -1;
}

int putDIFConfigurationObject(nl_msg* netlinkMessage,
		const DIFConfiguration& object){
	struct nlattr *difName;

	NLA_PUT_U16(netlinkMessage, DCONF_ATTR_DIF_TYPE, object.getDifType());

	if (!(difName = nla_nest_start(netlinkMessage, DCONF_ATTR_DIF_NAME))) {
		goto nla_put_failure;
	}
	if (putApplicationProcessNamingInformationObject(netlinkMessage,
			object.getDifName()) < 0) {
		goto nla_put_failure;
	}
	nla_nest_end(netlinkMessage, difName);

	return 0;

	nla_put_failure: LOG_ERR(
			"Error building DIFConfiguration Netlink object");
	return -1;
}

int putIpcmAssignToDIFRequestMessageObject(nl_msg* netlinkMessage,
		const IpcmAssignToDIFRequestMessage& object){
	struct nlattr *difConfiguration;

	if (!(difConfiguration =
			nla_nest_start(netlinkMessage, IATDR_ATTR_DIF_CONFIGURATION))) {
		goto nla_put_failure;
	}

	if (putDIFConfigurationObject(
			netlinkMessage, object.getDIFConfiguration()) < 0) {
		goto nla_put_failure;
	}

	nla_nest_end(netlinkMessage, difConfiguration);

	return 0;

	nla_put_failure: LOG_ERR(
			"Error building IpcmAssignToDIFRequestMessage Netlink object");
	return -1;
}

int putIpcmAssignToDIFResponseMessageObject(nl_msg* netlinkMessage,
		const IpcmAssignToDIFResponseMessage& object){

	NLA_PUT_U32(netlinkMessage, IATDRE_ATTR_RESULT, object.getResult());
	NLA_PUT_STRING(netlinkMessage,IATDRE_ATTR_ERROR_DESCRIPTION,
			object.getErrorDescription().c_str());

	return 0;

	nla_put_failure: LOG_ERR(
			"Error building IpcmAssignToDIFResponseMessage Netlink object");
	return -1;
}

int putIpcmAllocateFlowRequestMessageObject(nl_msg* netlinkMessage,
		const IpcmAllocateFlowRequestMessage& object){
	struct nlattr *sourceName, *destName, *flowSpec, *difName;

	if (!(sourceName = nla_nest_start(netlinkMessage, IAFRM_ATTR_SOURCE_APP))){
		goto nla_put_failure;
	}
	if (putApplicationProcessNamingInformationObject(netlinkMessage,
			object.getSourceAppName()) < 0) {
		goto nla_put_failure;
	}
	nla_nest_end(netlinkMessage, sourceName);

	if (!(destName = nla_nest_start(netlinkMessage, IAFRM_ATTR_DEST_APP))){
		goto nla_put_failure;
	}
	if (putApplicationProcessNamingInformationObject(netlinkMessage,
			object.getDestAppName()) < 0) {
		goto nla_put_failure;
	}
	nla_nest_end(netlinkMessage, destName);

	if (!(flowSpec = nla_nest_start(netlinkMessage, IAFRM_ATTR_FLOW_SPEC))){
		goto nla_put_failure;
	}
	if (putFlowSpecificationObject(netlinkMessage, object.getFlowSpec()) < 0) {
		goto nla_put_failure;
	}
	nla_nest_end(netlinkMessage, flowSpec);

	if (!(difName = nla_nest_start(netlinkMessage, IAFRM_ATTR_DIF_NAME))){
		goto nla_put_failure;
	}
	if (putApplicationProcessNamingInformationObject(netlinkMessage,
			object.getDifName()) < 0) {
		goto nla_put_failure;
	}
	nla_nest_end(netlinkMessage, difName);

	NLA_PUT_U32(netlinkMessage, IAFRM_ATTR_PORT_ID, object.getPortId());
	NLA_PUT_U32(netlinkMessage,
			IAFRM_ATTR_APP_PORT, object.getApplicationPortId());

	return 0;

	nla_put_failure: LOG_ERR(
			"Error building IpcmAllocateFlowRequestMessage Netlink object");
	return -1;
}

int putIpcmAllocateFlowResponseMessageObject(nl_msg* netlinkMessage,
		const IpcmAllocateFlowResponseMessage& object){

	NLA_PUT_U32(netlinkMessage, IAFREM_ATTR_RESULT, object.getResult());
	NLA_PUT_STRING(netlinkMessage,IAFREM_ATTR_ERROR_DESCRIPTION,
			object.getErrorDescription().c_str());

	return 0;

	nla_put_failure: LOG_ERR(
			"Error building IpcmAllocateFlowResponseeMessage Netlink object");
	return -1;
}

int putIpcmIPCProcessRegisteredToDIFNotificationObject(nl_msg* netlinkMessage,
		const IpcmIPCProcessRegisteredToDIFNotification& object){
	struct nlattr *ipcProcessName, *difName;

	if (!(ipcProcessName = nla_nest_start(
			netlinkMessage, IIPRTDN_ATTR_IPC_PROCESS_NAME))){
		goto nla_put_failure;
	}
	if (putApplicationProcessNamingInformationObject(netlinkMessage,
			object.getIpcProcessName()) < 0) {
		goto nla_put_failure;
	}
	nla_nest_end(netlinkMessage, ipcProcessName);

	if (!(difName = nla_nest_start(
			netlinkMessage, IIPRTDN_ATTR_DIF_NAME))){
		goto nla_put_failure;
	}
	if (putApplicationProcessNamingInformationObject(netlinkMessage,
			object.getDifName()) < 0) {
		goto nla_put_failure;
	}
	nla_nest_end(netlinkMessage, difName);

	return 0;

	nla_put_failure: LOG_ERR(
			"Error building IpcmIPCProcessRegisteredToDIFNotification Netlink object");
	return -1;
}

AppAllocateFlowRequestMessage * parseAppAllocateFlowRequestMessage(
		nlmsghdr *hdr) {
	struct nla_policy attr_policy[AAFR_ATTR_MAX + 1];
	attr_policy[AAFR_ATTR_SOURCE_APP_NAME].type = NLA_NESTED;
	attr_policy[AAFR_ATTR_SOURCE_APP_NAME].minlen = 0;
	attr_policy[AAFR_ATTR_SOURCE_APP_NAME].maxlen = 0;
	attr_policy[AAFR_ATTR_DEST_APP_NAME].type = NLA_NESTED;
	attr_policy[AAFR_ATTR_DEST_APP_NAME].minlen = 0;
	attr_policy[AAFR_ATTR_DEST_APP_NAME].maxlen = 0;
	attr_policy[AAFR_ATTR_FLOW_SPEC].type = NLA_NESTED;
	attr_policy[AAFR_ATTR_FLOW_SPEC].minlen = 0;
	attr_policy[AAFR_ATTR_FLOW_SPEC].maxlen = 0;
	struct nlattr *attrs[AAFR_ATTR_MAX + 1];

	/*
	 * The nlmsg_parse() function will make sure that the message contains
	 * enough payload to hold the header (struct my_hdr), validates any
	 * attributes attached to the messages and stores a pointer to each
	 * attribute in the attrs[] array accessable by attribute type.
	 */
	int err = genlmsg_parse(hdr, sizeof(struct rinaHeader), attrs,
			AAFR_ATTR_MAX, attr_policy);
	if (err < 0) {
		LOG_ERR(
				"Error parsing AppAllocateFlowRequestMessage information from Netlink message: %d",
				err);
		return 0;
	}

	AppAllocateFlowRequestMessage * result =
			new AppAllocateFlowRequestMessage();
	ApplicationProcessNamingInformation * sourceName;
	ApplicationProcessNamingInformation * destName;
	FlowSpecification * flowSpec;

	if (attrs[AAFR_ATTR_SOURCE_APP_NAME]) {
		sourceName = parseApplicationProcessNamingInformationObject(
				attrs[AAFR_ATTR_SOURCE_APP_NAME]);
		if (sourceName == 0) {
			delete result;
			return 0;
		} else {
			result->setSourceAppName(*sourceName);
			delete sourceName;
		}
	}

	if (attrs[AAFR_ATTR_DEST_APP_NAME]) {
		destName = parseApplicationProcessNamingInformationObject(
				attrs[AAFR_ATTR_DEST_APP_NAME]);
		if (destName == 0) {
			delete result;
			return 0;
		} else {
			result->setDestAppName(*destName);
			delete destName;
		}
	}

	if (attrs[AAFR_ATTR_FLOW_SPEC]) {
		flowSpec = parseFlowSpecificationObject(attrs[AAFR_ATTR_FLOW_SPEC]);
		if (flowSpec == 0) {
			delete result;
			return 0;
		} else {
			result->setFlowSpecification(*flowSpec);
			delete flowSpec;
		}
	}

	return result;
}

AppAllocateFlowRequestResultMessage * parseAppAllocateFlowRequestResultMessage(
		nlmsghdr *hdr) {
	struct nla_policy attr_policy[AAFRR_ATTR_MAX + 1];
	attr_policy[AAFRR_ATTR_SOURCE_APP_NAME].type = NLA_NESTED;
	attr_policy[AAFRR_ATTR_SOURCE_APP_NAME].minlen = 0;
	attr_policy[AAFRR_ATTR_SOURCE_APP_NAME].maxlen = 0;
	attr_policy[AAFRR_ATTR_PORT_ID].type = NLA_U32;
	attr_policy[AAFRR_ATTR_PORT_ID].minlen = 4;
	attr_policy[AAFRR_ATTR_PORT_ID].maxlen = 4;
	attr_policy[AAFRR_ATTR_ERROR_DESCRIPTION].type = NLA_STRING;
	attr_policy[AAFRR_ATTR_ERROR_DESCRIPTION].minlen = 0;
	attr_policy[AAFRR_ATTR_ERROR_DESCRIPTION].maxlen = 65535;
	attr_policy[AAFRR_ATTR_DIF_NAME].type = NLA_NESTED;
	attr_policy[AAFRR_ATTR_DIF_NAME].minlen = 0;
	attr_policy[AAFRR_ATTR_DIF_NAME].maxlen = 0;
	attr_policy[AAFRR_ATTR_IPC_PROCESS_PORT_ID].type = NLA_U32;
	attr_policy[AAFRR_ATTR_IPC_PROCESS_PORT_ID].minlen = 4;
	attr_policy[AAFRR_ATTR_IPC_PROCESS_PORT_ID].maxlen = 4;
	attr_policy[AAFRR_ATTR_IPC_PROCESS_ID].type = NLA_U16;
	attr_policy[AAFRR_ATTR_IPC_PROCESS_ID].minlen = 2;
	attr_policy[AAFRR_ATTR_IPC_PROCESS_ID].maxlen = 2;
	struct nlattr *attrs[AAFRR_ATTR_MAX + 1];

	/*
	 * The nlmsg_parse() function will make sure that the message contains
	 * enough payload to hold the header (struct my_hdr), validates any
	 * attributes attached to the messages and stores a pointer to each
	 * attribute in the attrs[] array accessable by attribute type.
	 */
	int err = genlmsg_parse(hdr, sizeof(struct rinaHeader), attrs,
			AAFRR_ATTR_MAX, attr_policy);
	if (err < 0) {
		LOG_ERR(
				"Error parsing AppAllocateFlowRequestResultMessage information from Netlink message: %d",
				err);
		return 0;
	}

	AppAllocateFlowRequestResultMessage * result =
			new AppAllocateFlowRequestResultMessage();

	ApplicationProcessNamingInformation * sourceName;
	ApplicationProcessNamingInformation * difName;

	if (attrs[AAFRR_ATTR_SOURCE_APP_NAME]) {
		sourceName = parseApplicationProcessNamingInformationObject(
				attrs[AAFRR_ATTR_SOURCE_APP_NAME]);
		if (sourceName == 0) {
			delete result;
			return 0;
		} else {
			result->setSourceAppName(*sourceName);
			delete sourceName;
		}
	}

	if (attrs[AAFRR_ATTR_PORT_ID]) {
		result->setPortId(nla_get_u32(attrs[AAFRR_ATTR_PORT_ID]));
	}

	if (attrs[AAFRR_ATTR_ERROR_DESCRIPTION]) {
		result->setErrorDescription(
				nla_get_string(attrs[AAFRR_ATTR_ERROR_DESCRIPTION]));
	}

	if (attrs[AAFRR_ATTR_DIF_NAME]) {
		difName = parseApplicationProcessNamingInformationObject(
				attrs[AAFRR_ATTR_DIF_NAME]);
		if (difName == 0) {
			delete result;
			return 0;
		} else {
			result->setDifName(*difName);
			delete difName;
		}
	}

	if (attrs[AAFRR_ATTR_IPC_PROCESS_PORT_ID]) {
		result->setIpcProcessPortId(
				nla_get_u32(attrs[AAFRR_ATTR_IPC_PROCESS_PORT_ID]));
	}

	if (attrs[AAFRR_ATTR_IPC_PROCESS_ID]) {
		result->setIpcProcessId(
				nla_get_u16(attrs[AAFRR_ATTR_IPC_PROCESS_ID]));
	}

	return result;
}

AppAllocateFlowRequestArrivedMessage * parseAppAllocateFlowRequestArrivedMessage(
		nlmsghdr *hdr) {
	struct nla_policy attr_policy[AAFRA_ATTR_MAX + 1];
	attr_policy[AAFRA_ATTR_SOURCE_APP_NAME].type = NLA_NESTED;
	attr_policy[AAFRA_ATTR_SOURCE_APP_NAME].minlen = 0;
	attr_policy[AAFRA_ATTR_SOURCE_APP_NAME].maxlen = 0;
	attr_policy[AAFRA_ATTR_DEST_APP_NAME].type = NLA_NESTED;
	attr_policy[AAFRA_ATTR_DEST_APP_NAME].minlen = 0;
	attr_policy[AAFRA_ATTR_DEST_APP_NAME].maxlen = 0;
	attr_policy[AAFRA_ATTR_FLOW_SPEC].type = NLA_NESTED;
	attr_policy[AAFRA_ATTR_FLOW_SPEC].minlen = 0;
	attr_policy[AAFRA_ATTR_FLOW_SPEC].maxlen = 0;
	attr_policy[AAFRA_ATTR_PORT_ID].type = NLA_U32;
	attr_policy[AAFRA_ATTR_PORT_ID].minlen = 4;
	attr_policy[AAFRA_ATTR_PORT_ID].maxlen = 4;
	attr_policy[AAFRA_ATTR_DIF_NAME].type = NLA_NESTED;
	attr_policy[AAFRA_ATTR_DIF_NAME].minlen = 0;
	attr_policy[AAFRA_ATTR_DIF_NAME].maxlen = 0;
	struct nlattr *attrs[AAFRA_ATTR_MAX + 1];

	/*
	 * The nlmsg_parse() function will make sure that the message contains
	 * enough payload to hold the header (struct my_hdr), validates any
	 * attributes attached to the messages and stores a pointer to each
	 * attribute in the attrs[] array accessable by attribute type.
	 */
	int err = genlmsg_parse(hdr, sizeof(struct rinaHeader), attrs,
			AAFRA_ATTR_MAX, attr_policy);
	if (err < 0) {
		LOG_ERR(
				"Error parsing AppAllocateFlowRequestArrivedMessage information from Netlink message: %d",
				err);
		return 0;
	}

	AppAllocateFlowRequestArrivedMessage * result =
			new AppAllocateFlowRequestArrivedMessage();
	ApplicationProcessNamingInformation * sourceName;
	ApplicationProcessNamingInformation * destName;
	FlowSpecification * flowSpec;
	ApplicationProcessNamingInformation * difName;

	if (attrs[AAFRA_ATTR_SOURCE_APP_NAME]) {
		sourceName = parseApplicationProcessNamingInformationObject(
				attrs[AAFRA_ATTR_SOURCE_APP_NAME]);
		if (sourceName == 0) {
			delete result;
			return 0;
		} else {
			result->setSourceAppName(*sourceName);
			delete sourceName;
		}
	}

	if (attrs[AAFRA_ATTR_DEST_APP_NAME]) {
		destName = parseApplicationProcessNamingInformationObject(
				attrs[AAFRA_ATTR_DEST_APP_NAME]);
		if (destName == 0) {
			delete result;
			return 0;
		} else {
			result->setDestAppName(*destName);
			delete destName;
		}
	}

	if (attrs[AAFRA_ATTR_FLOW_SPEC]) {
		flowSpec = parseFlowSpecificationObject(attrs[AAFRA_ATTR_FLOW_SPEC]);
		if (flowSpec == 0) {
			delete result;
			return 0;
		} else {
			result->setFlowSpecification(*flowSpec);
			delete flowSpec;
		}
	}

	if (attrs[AAFRA_ATTR_PORT_ID]) {
		result->setPortId(nla_get_u32(attrs[AAFRA_ATTR_PORT_ID]));

		if (attrs[AAFRA_ATTR_DIF_NAME]) {
			difName = parseApplicationProcessNamingInformationObject(
					attrs[AAFRA_ATTR_DIF_NAME]);
			if (difName == 0) {
				delete result;
				return 0;
			} else {
				result->setDifName(*difName);
				delete difName;
			}
		}
	}
	return result;
}

AppAllocateFlowResponseMessage * parseAppAllocateFlowResponseMessage(
		nlmsghdr *hdr) {
	struct nla_policy attr_policy[AAFRE_ATTR_MAX + 1];
	attr_policy[AAFRE_ATTR_DIF_NAME].type = NLA_NESTED;
	attr_policy[AAFRE_ATTR_DIF_NAME].minlen = 0;
	attr_policy[AAFRE_ATTR_DIF_NAME].maxlen = 0;
	attr_policy[AAFRE_ATTR_ACCEPT].type = NLA_FLAG;
	attr_policy[AAFRE_ATTR_ACCEPT].minlen = 0;
	attr_policy[AAFRE_ATTR_ACCEPT].maxlen = 0;
	attr_policy[AAFRE_ATTR_DENY_REASON].type = NLA_STRING;
	attr_policy[AAFRE_ATTR_DENY_REASON].minlen = 0;
	attr_policy[AAFRE_ATTR_DENY_REASON].maxlen = 65535;
	attr_policy[AAFRE_ATTR_NOTIFY_SOURCE].type = NLA_FLAG;
	attr_policy[AAFRE_ATTR_NOTIFY_SOURCE].minlen = 0;
	attr_policy[AAFRE_ATTR_NOTIFY_SOURCE].maxlen = 0;
	struct nlattr *attrs[AAFRE_ATTR_MAX + 1];

	/*
	 * The nlmsg_parse() function will make sure that the message contains
	 * enough payload to hold the header (struct my_hdr), validates any
	 * attributes attached to the messages and stores a pointer to each
	 * attribute in the attrs[] array accessable by attribute type.
	 */
	int err = genlmsg_parse(hdr, sizeof(struct rinaHeader), attrs,
			AAFRA_ATTR_MAX, attr_policy);
	if (err < 0) {
		LOG_ERR(
				"Error parsing AppAllocateFlowResponseMessage information from Netlink message: %d",
				err);
		return 0;
	}

	AppAllocateFlowResponseMessage * result =
			new AppAllocateFlowResponseMessage();
	ApplicationProcessNamingInformation * difName;

	if (attrs[AAFRE_ATTR_DIF_NAME]) {
		difName = parseApplicationProcessNamingInformationObject(
				attrs[AAFRE_ATTR_DIF_NAME]);
		if (difName == 0) {
			delete result;
			return 0;
		} else {
			result->setDifName(*difName);
			delete difName;
		}
	}

	if (attrs[AAFRE_ATTR_ACCEPT]) {
		result->setAccept((nla_get_flag(attrs[AAFRE_ATTR_ACCEPT])));
	}

	if (attrs[AAFRE_ATTR_DENY_REASON]) {
		result->setDenyReason(nla_get_string(attrs[AAFRE_ATTR_DENY_REASON]));
	}
	if (attrs[AAFRE_ATTR_NOTIFY_SOURCE]) {
		result->setNotifySource(
				(nla_get_flag(attrs[AAFRE_ATTR_NOTIFY_SOURCE])));
	}

	return result;
}

AppDeallocateFlowRequestMessage * parseAppDeallocateFlowRequestMessage(
		nlmsghdr *hdr) {
	struct nla_policy attr_policy[ADFRT_ATTR_MAX + 1];
	attr_policy[ADFRT_ATTR_PORT_ID].type = NLA_U32;
	attr_policy[ADFRT_ATTR_PORT_ID].minlen = 4;
	attr_policy[ADFRT_ATTR_PORT_ID].maxlen = 4;
	attr_policy[ADFRT_ATTR_DIF_NAME].type = NLA_NESTED;
	attr_policy[ADFRT_ATTR_DIF_NAME].minlen = 0;
	attr_policy[ADFRT_ATTR_DIF_NAME].maxlen = 0;
	attr_policy[ADFRT_ATTR_APP_NAME].type = NLA_NESTED;
	attr_policy[ADFRT_ATTR_APP_NAME].minlen = 0;
	attr_policy[ADFRT_ATTR_APP_NAME].maxlen = 0;
	struct nlattr *attrs[ADFRT_ATTR_MAX + 1];

	/*
	 * The nlmsg_parse() function will make sure that the message contains
	 * enough payload to hold the header (struct my_hdr), validates any
	 * attributes attached to the messages and stores a pointer to each
	 * attribute in the attrs[] array accessable by attribute type.
	 */
	int err = genlmsg_parse(hdr, sizeof(struct rinaHeader), attrs, ADFRT_ATTR_MAX,
			attr_policy);
	if (err < 0) {
		LOG_ERR(
				"Error parsing AppDeallocateFlowRequestMessage information from Netlink message: %d",
				err);
		return 0;
	}

	AppDeallocateFlowRequestMessage * result =
			new AppDeallocateFlowRequestMessage();

	ApplicationProcessNamingInformation * difName;
	ApplicationProcessNamingInformation * applicationName;

	if (attrs[ADFRT_ATTR_PORT_ID]) {
		result->setPortId(nla_get_u32(attrs[ADFRT_ATTR_PORT_ID]));
	}

	if (attrs[ADFRT_ATTR_DIF_NAME]) {
		difName = parseApplicationProcessNamingInformationObject(
				attrs[ADFRT_ATTR_DIF_NAME]);
		if (difName == 0) {
			delete result;
			return 0;
		} else {
			result->setDifName(*difName);
			delete difName;
		}
	}

	if (attrs[ADFRT_ATTR_APP_NAME]) {
		applicationName = parseApplicationProcessNamingInformationObject(
				attrs[ADFRT_ATTR_APP_NAME]);
		if (applicationName == 0) {
			delete result;
			return 0;
		} else {
			result->setApplicationName(*applicationName);
			delete applicationName;
		}
	}

	return result;
}

AppDeallocateFlowResponseMessage * parseAppDeallocateFlowResponseMessage(
		nlmsghdr *hdr) {
	struct nla_policy attr_policy[ADFRE_ATTR_MAX + 1];
	attr_policy[ADFRE_ATTR_RESULT].type = NLA_U32;
	attr_policy[ADFRE_ATTR_RESULT].minlen = 4;
	attr_policy[ADFRE_ATTR_RESULT].maxlen = 4;
	attr_policy[ADFRE_ATTR_ERROR_DESCRIPTION].type = NLA_STRING;
	attr_policy[ADFRE_ATTR_ERROR_DESCRIPTION].minlen = 0;
	attr_policy[ADFRE_ATTR_ERROR_DESCRIPTION].maxlen = 65535;
	attr_policy[ADFRE_ATTR_APP_NAME].type = NLA_NESTED;
	attr_policy[ADFRE_ATTR_APP_NAME].minlen = 0;
	attr_policy[ADFRE_ATTR_APP_NAME].maxlen = 0;
	struct nlattr *attrs[ADFRE_ATTR_MAX + 1];

	/*
	 * The nlmsg_parse() function will make sure that the message contains
	 * enough payload to hold the header (struct my_hdr), validates any
	 * attributes attached to the messages and stores a pointer to each
	 * attribute in the attrs[] array accessable by attribute type.
	 */
	int err = genlmsg_parse(hdr, sizeof(struct rinaHeader), attrs,
			ADFRE_ATTR_MAX, attr_policy);
	if (err < 0) {
		LOG_ERR(
				"Error parsing AppDeallocateFlowResponseMessage information from Netlink message: %d",
				err);
		return 0;
	}

	AppDeallocateFlowResponseMessage * result =
			new AppDeallocateFlowResponseMessage();

	ApplicationProcessNamingInformation * applicationName;

	if (attrs[ADFRE_ATTR_RESULT]) {
		result->setResult(nla_get_u32(attrs[ADFRE_ATTR_RESULT]));
	}

	if (attrs[ADFRE_ATTR_ERROR_DESCRIPTION]) {
		result->setErrorDescription(
				nla_get_string(attrs[ADFRE_ATTR_ERROR_DESCRIPTION]));
	}

	if (attrs[ADFRE_ATTR_APP_NAME]) {
		applicationName = parseApplicationProcessNamingInformationObject(
				attrs[ADFRE_ATTR_APP_NAME]);
		if (applicationName == 0) {
			delete result;
			return 0;
		} else {
			result->setApplicationName(*applicationName);
			delete applicationName;
		}
	}

	return result;
}

AppFlowDeallocatedNotificationMessage * parseAppFlowDeallocatedNotificationMessage(
		nlmsghdr *hdr) {
	struct nla_policy attr_policy[AFDN_ATTR_MAX + 1];
	attr_policy[AFDN_ATTR_PORT_ID].type = NLA_U32;
	attr_policy[AFDN_ATTR_PORT_ID].minlen = 4;
	attr_policy[AFDN_ATTR_PORT_ID].maxlen = 4;
	attr_policy[AFDN_ATTR_CODE].type = NLA_U32;
	attr_policy[AFDN_ATTR_CODE].minlen = 4;
	attr_policy[AFDN_ATTR_CODE].maxlen = 4;
	attr_policy[AFDN_ATTR_REASON].type = NLA_STRING;
	attr_policy[AFDN_ATTR_REASON].minlen = 0;
	attr_policy[AFDN_ATTR_REASON].maxlen = 65535;
	attr_policy[AFDN_ATTR_APP_NAME].type = NLA_NESTED;
	attr_policy[AFDN_ATTR_APP_NAME].minlen = 0;
	attr_policy[AFDN_ATTR_APP_NAME].maxlen = 0;
	attr_policy[AFDN_ATTR_DIF_NAME].type = NLA_NESTED;
	attr_policy[AFDN_ATTR_DIF_NAME].minlen = 0;
	attr_policy[AFDN_ATTR_DIF_NAME].maxlen = 0;
	struct nlattr *attrs[AFDN_ATTR_MAX + 1];

	/*
	 * The nlmsg_parse() function will make sure that the message contains
	 * enough payload to hold the header (struct my_hdr), validates any
	 * attributes attached to the messages and stores a pointer to each
	 * attribute in the attrs[] array accessable by attribute type.
	 */
	int err = genlmsg_parse(hdr, sizeof(struct rinaHeader), attrs,
			AFDN_ATTR_MAX, attr_policy);
	if (err < 0) {
		LOG_ERR(
				"Error parsing AppFlowDeallocatedNotificationMessage information from Netlink message: %d",
				err);
		return 0;
	}

	AppFlowDeallocatedNotificationMessage * result =
			new AppFlowDeallocatedNotificationMessage();

	ApplicationProcessNamingInformation * applicationName;
	ApplicationProcessNamingInformation * difName;

	if (attrs[AFDN_ATTR_PORT_ID]) {
		result->setPortId(nla_get_u32(attrs[AFDN_ATTR_PORT_ID]));
	}

	if (attrs[AFDN_ATTR_CODE]) {
		result->setCode(nla_get_u32(attrs[AFDN_ATTR_CODE]));
	}

	if (attrs[AFDN_ATTR_REASON]) {
		result->setReason(nla_get_string(attrs[AFDN_ATTR_REASON]));
	}

	if (attrs[AFDN_ATTR_APP_NAME]) {
		applicationName = parseApplicationProcessNamingInformationObject(
				attrs[AFDN_ATTR_APP_NAME]);
		if (applicationName == 0) {
			delete result;
			return 0;
		} else {
			result->setApplicationName(*applicationName);
			delete applicationName;
		}
	}
	if (attrs[AFDN_ATTR_DIF_NAME]) {
		difName = parseApplicationProcessNamingInformationObject(
				attrs[AFDN_ATTR_DIF_NAME]);
		if (difName == NULL) {
			delete result;
			return NULL;
		} else {
			result->setDifName(*difName);
			delete difName;
		}
	}

	return result;
}

AppRegisterApplicationRequestMessage * parseAppRegisterApplicationRequestMessage(
		nlmsghdr *hdr) {
	struct nla_policy attr_policy[ARAR_ATTR_MAX + 1];
	attr_policy[ARAR_ATTR_APP_NAME].type = NLA_NESTED;
	attr_policy[ARAR_ATTR_APP_NAME].minlen = 0;
	attr_policy[ARAR_ATTR_APP_NAME].maxlen = 0;
	attr_policy[ARAR_ATTR_DIF_NAME].type = NLA_NESTED;
	attr_policy[ARAR_ATTR_DIF_NAME].minlen = 0;
	attr_policy[ARAR_ATTR_DIF_NAME].maxlen = 0;
	struct nlattr *attrs[ARAR_ATTR_MAX + 1];

	/*
	 * The nlmsg_parse() function will make sure that the message contains
	 * enough payload to hold the header (struct my_hdr), validates any
	 * attributes attached to the messages and stores a pointer to each
	 * attribute in the attrs[] array accessable by attribute type.
	 */
	int err = genlmsg_parse(hdr, sizeof(struct rinaHeader), attrs,
			ARAR_ATTR_MAX, attr_policy);
	if (err < 0) {
		LOG_ERR(
				"Error parsing AppRegisterApplicationRequestMessage information from Netlink message: %d",
				err);
		return 0;
	}

	AppRegisterApplicationRequestMessage * result =
			new AppRegisterApplicationRequestMessage();

	ApplicationProcessNamingInformation * applicationName;
	ApplicationProcessNamingInformation * difName;

	if (attrs[ARAR_ATTR_APP_NAME]) {
		applicationName = parseApplicationProcessNamingInformationObject(
				attrs[ARAR_ATTR_APP_NAME]);
		if (applicationName == 0) {
			delete result;
			return 0;
		} else {
			result->setApplicationName(*applicationName);
			delete applicationName;
		}
	}
	if (attrs[ARAR_ATTR_DIF_NAME]) {
		difName = parseApplicationProcessNamingInformationObject(
				attrs[ARAR_ATTR_DIF_NAME]);
		if (difName == 0) {
			delete result;
			return 0;
		} else {
			result->setDifName(*difName);
			delete difName;
		}
	}

	return result;
}

AppRegisterApplicationResponseMessage * parseAppRegisterApplicationResponseMessage(
		nlmsghdr *hdr) {
	struct nla_policy attr_policy[ARARE_ATTR_MAX + 1];
	attr_policy[ARARE_ATTR_RESULT].type = NLA_U32;
	attr_policy[ARARE_ATTR_RESULT].minlen = 4;
	attr_policy[ARARE_ATTR_RESULT].maxlen = 4;
	attr_policy[ARARE_ATTR_PROCESS_PORT_ID].type = NLA_U32;
	attr_policy[ARARE_ATTR_PROCESS_PORT_ID].minlen = 4;
	attr_policy[ARARE_ATTR_PROCESS_PORT_ID].maxlen = 4;
	attr_policy[ARARE_ATTR_PROCESS_IPC_PROCESS_ID].type = NLA_U16;
	attr_policy[ARARE_ATTR_PROCESS_IPC_PROCESS_ID].minlen = 2;
	attr_policy[ARARE_ATTR_PROCESS_IPC_PROCESS_ID].maxlen = 2;
	attr_policy[ARARE_ATTR_ERROR_DESCRIPTION].type = NLA_STRING;
	attr_policy[ARARE_ATTR_ERROR_DESCRIPTION].minlen = 0;
	attr_policy[ARARE_ATTR_ERROR_DESCRIPTION].maxlen = 65535;
	attr_policy[ARARE_ATTR_APP_NAME].type = NLA_NESTED;
	attr_policy[ARARE_ATTR_APP_NAME].minlen = 0;
	attr_policy[ARARE_ATTR_APP_NAME].maxlen = 0;
	attr_policy[ARARE_ATTR_DIF_NAME].type = NLA_NESTED;
	attr_policy[ARARE_ATTR_DIF_NAME].minlen = 0;
	attr_policy[ARARE_ATTR_DIF_NAME].maxlen = 0;
	struct nlattr *attrs[ARARE_ATTR_MAX + 1];

	/*
	 * The nlmsg_parse() function will make sure that the message contains
	 * enough payload to hold the header (struct my_hdr), validates any
	 * attributes attached to the messages and stores a pointer to each
	 * attribute in the attrs[] array accessable by attribute type.
	 */
	int err = genlmsg_parse(hdr, sizeof(struct rinaHeader), attrs,
			ARARE_ATTR_MAX, attr_policy);
	if (err < 0) {
		LOG_ERR(
				"Error parsing AppRegisterApplicationResponseMessage information from Netlink message: %d",
				err);
		return 0;
	}

	AppRegisterApplicationResponseMessage * result =
			new AppRegisterApplicationResponseMessage();

	ApplicationProcessNamingInformation * applicationName;
	ApplicationProcessNamingInformation * difName;

	if (attrs[ARARE_ATTR_RESULT]) {
		result->setResult(nla_get_u32(attrs[ARARE_ATTR_RESULT]));
	}

	if (attrs[ARARE_ATTR_PROCESS_PORT_ID]) {
		result->setIpcProcessPortId(
				nla_get_u32(attrs[ARARE_ATTR_PROCESS_PORT_ID]));
	}

	if (attrs[ARARE_ATTR_PROCESS_IPC_PROCESS_ID]) {
		result->setIpcProcessId(
				nla_get_u16(attrs[ARARE_ATTR_PROCESS_IPC_PROCESS_ID]));
	}

	if (attrs[ARARE_ATTR_ERROR_DESCRIPTION]) {
		result->setErrorDescription(
				nla_get_string(attrs[ARARE_ATTR_ERROR_DESCRIPTION]));
	}

	if (attrs[ARARE_ATTR_APP_NAME]) {
		applicationName = parseApplicationProcessNamingInformationObject(
				attrs[ARARE_ATTR_APP_NAME]);
		if (applicationName == 0) {
			delete result;
			return 0;
		} else {
			result->setApplicationName(*applicationName);
			delete applicationName;
		}
	}
	if (attrs[ARARE_ATTR_DIF_NAME]) {
		difName = parseApplicationProcessNamingInformationObject(
				attrs[ARARE_ATTR_DIF_NAME]);
		if (difName == 0) {
			delete result;
			return 0;
		} else {
			result->setDifName(*difName);
			delete difName;
		}
	}

	return result;
}

IpcmRegisterApplicationRequestMessage *
	parseIpcmRegisterApplicationRequestMessage(nlmsghdr *hdr){
	struct nla_policy attr_policy[IRAR_ATTR_MAX + 1];
	attr_policy[IRAR_ATTR_APP_NAME].type = NLA_NESTED;
	attr_policy[IRAR_ATTR_APP_NAME].minlen = 0;
	attr_policy[IRAR_ATTR_APP_NAME].maxlen = 0;
	attr_policy[IRAR_ATTR_DIF_NAME].type = NLA_NESTED;
	attr_policy[IRAR_ATTR_DIF_NAME].minlen = 0;
	attr_policy[IRAR_ATTR_DIF_NAME].maxlen = 0;
	attr_policy[IRAR_ATTR_APP_PORT_ID].type = NLA_U32;
	attr_policy[IRAR_ATTR_APP_PORT_ID].minlen = 4;
	attr_policy[IRAR_ATTR_APP_PORT_ID].maxlen = 4;
	struct nlattr *attrs[IRAR_ATTR_MAX + 1];

	/*
	 * The nlmsg_parse() function will make sure that the message contains
	 * enough payload to hold the header (struct my_hdr), validates any
	 * attributes attached to the messages and stores a pointer to each
	 * attribute in the attrs[] array accessable by attribute type.
	 */
	int err = genlmsg_parse(hdr, sizeof(struct rinaHeader), attrs,
			IRAR_ATTR_MAX, attr_policy);
	if (err < 0) {
		LOG_ERR(
				"Error parsing IpcmRegisterApplicationRequestMessage information from Netlink message: %d",
				err);
		return 0;
	}

	IpcmRegisterApplicationRequestMessage * result =
			new IpcmRegisterApplicationRequestMessage();

	ApplicationProcessNamingInformation * applicationName;
	ApplicationProcessNamingInformation * difName;

	if (attrs[IRAR_ATTR_APP_NAME]) {
		applicationName = parseApplicationProcessNamingInformationObject(
				attrs[IRAR_ATTR_APP_NAME]);
		if (applicationName == 0) {
			delete result;
			return 0;
		} else {
			result->setApplicationName(*applicationName);
			delete applicationName;
		}
	}

	if (attrs[IRAR_ATTR_DIF_NAME]) {
		difName = parseApplicationProcessNamingInformationObject(
				attrs[IRAR_ATTR_DIF_NAME]);
		if (difName == 0) {
			delete result;
			return 0;
		} else {
			result->setDifName(*difName);
			delete difName;
		}
	}

	if (attrs[IRAR_ATTR_APP_PORT_ID]) {
		result->setApplicationPortId(
				nla_get_u32(attrs[IRAR_ATTR_APP_PORT_ID]));
	}

	return result;
}

IpcmRegisterApplicationResponseMessage *
	parseIpcmRegisterApplicationResponseMessage(nlmsghdr *hdr) {
	struct nla_policy attr_policy[IRARE_ATTR_MAX + 1];
	attr_policy[IRARE_ATTR_RESULT].type = NLA_U32;
	attr_policy[IRARE_ATTR_RESULT].minlen = 4;
	attr_policy[IRARE_ATTR_RESULT].maxlen = 4;
	attr_policy[IRARE_ATTR_ERROR_DESCRIPTION].type = NLA_STRING;
	attr_policy[IRARE_ATTR_ERROR_DESCRIPTION].minlen = 0;
	attr_policy[IRARE_ATTR_ERROR_DESCRIPTION].maxlen = 65535;
	attr_policy[IRARE_ATTR_APP_NAME].type = NLA_NESTED;
	attr_policy[IRARE_ATTR_APP_NAME].minlen = 0;
	attr_policy[IRARE_ATTR_APP_NAME].maxlen = 0;
	attr_policy[IRARE_ATTR_DIF_NAME].type = NLA_NESTED;
	attr_policy[IRARE_ATTR_DIF_NAME].minlen = 0;
	attr_policy[IRARE_ATTR_DIF_NAME].maxlen = 0;
	struct nlattr *attrs[IRARE_ATTR_MAX + 1];

	/*
	 * The nlmsg_parse() function will make sure that the message contains
	 * enough payload to hold the header (struct my_hdr), validates any
	 * attributes attached to the messages and stores a pointer to each
	 * attribute in the attrs[] array accessable by attribute type.
	 */
	int err = genlmsg_parse(hdr, sizeof(struct rinaHeader), attrs,
			IRARE_ATTR_MAX, attr_policy);
	if (err < 0) {
		LOG_ERR(
				"Error parsing IpcmRegisterApplicationResponseMessage information from Netlink message: %d",
				err);
		return 0;
	}

	IpcmRegisterApplicationResponseMessage * result =
			new IpcmRegisterApplicationResponseMessage();

	ApplicationProcessNamingInformation * applicationName;
	ApplicationProcessNamingInformation * difName;

	if (attrs[IRARE_ATTR_RESULT]) {
		result->setResult(nla_get_u32(attrs[IRARE_ATTR_RESULT]));
	}

	if (attrs[IRARE_ATTR_ERROR_DESCRIPTION]) {
		result->setErrorDescription(
				nla_get_string(attrs[IRARE_ATTR_ERROR_DESCRIPTION]));
	}

	if (attrs[IRARE_ATTR_APP_NAME]) {
		applicationName = parseApplicationProcessNamingInformationObject(
				attrs[IRARE_ATTR_APP_NAME]);
		if (applicationName == 0) {
			delete result;
			return 0;
		} else {
			result->setApplicationName(*applicationName);
			delete applicationName;
		}
	}
	if (attrs[IRARE_ATTR_DIF_NAME]) {
		difName = parseApplicationProcessNamingInformationObject(
				attrs[IRARE_ATTR_DIF_NAME]);
		if (difName == 0) {
			delete result;
			return 0;
		} else {
			result->setDifName(*difName);
			delete difName;
		}
	}

	return result;
}

DIFConfiguration * parseDIFConfigurationObject(nlattr *nested){
	struct nla_policy attr_policy[DCONF_ATTR_MAX + 1];
	attr_policy[DCONF_ATTR_DIF_TYPE].type = NLA_U16;
	attr_policy[DCONF_ATTR_DIF_TYPE].minlen = 2;
	attr_policy[DCONF_ATTR_DIF_TYPE].maxlen = 2;
	attr_policy[DCONF_ATTR_DIF_NAME].type = NLA_NESTED;
	attr_policy[DCONF_ATTR_DIF_NAME].minlen = 0;
	attr_policy[DCONF_ATTR_DIF_NAME].maxlen = 0;
	struct nlattr *attrs[DCONF_ATTR_MAX + 1];

	int err = nla_parse_nested(attrs, DCONF_ATTR_MAX, nested, attr_policy);
	if (err < 0) {
		LOG_ERR(
				"Error parsing DIFConfiguration information from Netlink message: %d",
				err);
		return 0;
	}

	DIFConfiguration * result = new DIFConfiguration();
	ApplicationProcessNamingInformation * difName;

	if (attrs[DCONF_ATTR_DIF_TYPE]) {
		result->setDifType(
				static_cast<DIFType>(nla_get_u16(attrs[DCONF_ATTR_DIF_TYPE])));
	}

	if (attrs[DCONF_ATTR_DIF_NAME]) {
		difName = parseApplicationProcessNamingInformationObject(
				attrs[DCONF_ATTR_DIF_NAME]);
		if (difName == 0) {
			delete result;
			return 0;
		} else {
			result->setDifName(*difName);
			delete difName;
		}
	}

	return result;
}

IpcmAssignToDIFRequestMessage *
	parseIpcmAssignToDIFRequestMessage(nlmsghdr *hdr){
	struct nla_policy attr_policy[IATDR_ATTR_MAX + 1];
	attr_policy[IATDR_ATTR_DIF_CONFIGURATION].type = NLA_NESTED;
	attr_policy[IATDR_ATTR_DIF_CONFIGURATION].minlen = 0;
	attr_policy[IATDR_ATTR_DIF_CONFIGURATION].maxlen = 0;
	struct nlattr *attrs[IRARE_ATTR_MAX + 1];

	int err = genlmsg_parse(hdr, sizeof(struct rinaHeader), attrs,
			IATDR_ATTR_MAX, attr_policy);
	if (err < 0) {
		LOG_ERR(
				"Error parsing IpcmAssignToDIFRequestMessage information from Netlink message: %d",
				err);
		return 0;
	}

	IpcmAssignToDIFRequestMessage * result =
			new IpcmAssignToDIFRequestMessage();
	DIFConfiguration * difConfiguration;

	if (attrs[IATDR_ATTR_DIF_CONFIGURATION]) {
		difConfiguration = parseDIFConfigurationObject(
				attrs[IATDR_ATTR_DIF_CONFIGURATION]);
		if (difConfiguration == 0) {
			delete result;
			return 0;
		} else {
			result->setDIFConfiguration(*difConfiguration);
			delete difConfiguration;
		}
	}

	return result;
}

IpcmAssignToDIFResponseMessage *
	parseIpcmAssignToDIFResponseMessage(nlmsghdr *hdr){
	struct nla_policy attr_policy[IATDRE_ATTR_MAX + 1];
	attr_policy[IATDRE_ATTR_RESULT].type = NLA_U32;
	attr_policy[IATDRE_ATTR_RESULT].minlen = 4;
	attr_policy[IATDRE_ATTR_RESULT].maxlen = 4;
	attr_policy[IATDRE_ATTR_ERROR_DESCRIPTION].type = NLA_STRING;
	attr_policy[IATDRE_ATTR_ERROR_DESCRIPTION].minlen = 0;
	attr_policy[IATDRE_ATTR_ERROR_DESCRIPTION].maxlen = 65535;
	struct nlattr *attrs[IATDRE_ATTR_MAX + 1];

	int err = genlmsg_parse(hdr, sizeof(struct rinaHeader), attrs,
			IATDRE_ATTR_MAX, attr_policy);
	if (err < 0) {
		LOG_ERR(
				"Error parsing IpcmAssignToDIFResponseMessage information from Netlink message: %d",
				err);
		return 0;
	}

	IpcmAssignToDIFResponseMessage * result =
				new IpcmAssignToDIFResponseMessage();

	if (attrs[IATDRE_ATTR_RESULT]) {
		result->setResult(nla_get_u32(attrs[IATDRE_ATTR_RESULT]));
	}

	if (attrs[IATDRE_ATTR_ERROR_DESCRIPTION]) {
			result->setErrorDescription(
					nla_get_string(attrs[IATDRE_ATTR_ERROR_DESCRIPTION]));
	}

	return result;
}

IpcmAllocateFlowRequestMessage *
	parseIpcmAllocateFlowRequestMessage(nlmsghdr *hdr){
	struct nla_policy attr_policy[IAFRM_ATTR_MAX + 1];
	attr_policy[IAFRM_ATTR_SOURCE_APP].type = NLA_NESTED;
	attr_policy[IAFRM_ATTR_SOURCE_APP].minlen = 0;
	attr_policy[IAFRM_ATTR_SOURCE_APP].maxlen = 0;
	attr_policy[IAFRM_ATTR_DEST_APP].type = NLA_NESTED;
	attr_policy[IAFRM_ATTR_DEST_APP].minlen = 0;
	attr_policy[IAFRM_ATTR_DEST_APP].maxlen = 0;
	attr_policy[IAFRM_ATTR_FLOW_SPEC].type = NLA_NESTED;
	attr_policy[IAFRM_ATTR_FLOW_SPEC].minlen = 0;
	attr_policy[IAFRM_ATTR_FLOW_SPEC].maxlen = 0;
	attr_policy[IAFRM_ATTR_DIF_NAME].type = NLA_NESTED;
	attr_policy[IAFRM_ATTR_DIF_NAME].minlen = 0;
	attr_policy[IAFRM_ATTR_DIF_NAME].maxlen = 0;
	attr_policy[IAFRM_ATTR_PORT_ID].type = NLA_U32;
	attr_policy[IAFRM_ATTR_PORT_ID].minlen = 0;
	attr_policy[IAFRM_ATTR_PORT_ID].maxlen = 0;
	attr_policy[IAFRM_ATTR_APP_PORT].type = NLA_U32;
	attr_policy[IAFRM_ATTR_APP_PORT].minlen = 0;
	attr_policy[IAFRM_ATTR_APP_PORT].maxlen = 0;
	struct nlattr *attrs[IAFRM_ATTR_MAX + 1];

	int err = genlmsg_parse(hdr, sizeof(struct rinaHeader), attrs,
			IAFRM_ATTR_MAX, attr_policy);
	if (err < 0) {
		LOG_ERR(
				"Error parsing IpcmAssignToDIFRequestMessage information from Netlink message: %d",
				err);
		return 0;
	}

	IpcmAllocateFlowRequestMessage * result =
			new IpcmAllocateFlowRequestMessage();
	ApplicationProcessNamingInformation * sourceName;
	ApplicationProcessNamingInformation * destName;
	FlowSpecification * flowSpec;
	ApplicationProcessNamingInformation * difName;

	if (attrs[IAFRM_ATTR_SOURCE_APP]) {
		sourceName = parseApplicationProcessNamingInformationObject(
				attrs[IAFRM_ATTR_SOURCE_APP]);
		if (sourceName == 0) {
			delete result;
			return 0;
		} else {
			result->setSourceAppName(*sourceName);
			delete sourceName;
		}
	}

	if (attrs[IAFRM_ATTR_DEST_APP]) {
		destName = parseApplicationProcessNamingInformationObject(
				attrs[IAFRM_ATTR_DEST_APP]);
		if (destName == 0) {
			delete result;
			return 0;
		} else {
			result->setDestAppName(*destName);
			delete destName;
		}
	}

	if (attrs[IAFRM_ATTR_FLOW_SPEC]) {
		flowSpec = parseFlowSpecificationObject(attrs[IAFRM_ATTR_FLOW_SPEC]);
		if (flowSpec == 0) {
			delete result;
			return 0;
		} else {
			result->setFlowSpec(*flowSpec);
			delete flowSpec;
		}
	}

	if (attrs[IAFRM_ATTR_DIF_NAME]) {
		difName = parseApplicationProcessNamingInformationObject(
				attrs[IAFRM_ATTR_DIF_NAME]);
		if (difName == 0) {
			delete result;
			return 0;
		} else {
			result->setDifName(*difName);
			delete difName;
		}
	}

	if (attrs[IAFRM_ATTR_PORT_ID]) {
		result->setPortId(nla_get_u32(attrs[IAFRM_ATTR_PORT_ID]));
	}

	if (attrs[IAFRM_ATTR_APP_PORT]) {
		result->setApplicationPortId(nla_get_u32(attrs[IAFRM_ATTR_APP_PORT]));
	}

	return result;
}

IpcmAllocateFlowResponseMessage *
	parseIpcmAllocateFlowResponseMessage(nlmsghdr *hdr){
	struct nla_policy attr_policy[IAFREM_ATTR_MAX + 1];
	attr_policy[IAFREM_ATTR_RESULT].type = NLA_U32;
	attr_policy[IAFREM_ATTR_RESULT].minlen = 4;
	attr_policy[IAFREM_ATTR_RESULT].maxlen = 4;
	attr_policy[IAFREM_ATTR_ERROR_DESCRIPTION].type = NLA_STRING;
	attr_policy[IAFREM_ATTR_ERROR_DESCRIPTION].minlen = 0;
	attr_policy[IAFREM_ATTR_ERROR_DESCRIPTION].maxlen = 65535;
	struct nlattr *attrs[IAFREM_ATTR_MAX + 1];

	int err = genlmsg_parse(hdr, sizeof(struct rinaHeader), attrs,
			IAFREM_ATTR_MAX, attr_policy);
	if (err < 0) {
		LOG_ERR(
				"Error parsing IpcmAllocateFlowResponseMessage information from Netlink message: %d",
				err);
		return 0;
	}

	IpcmAllocateFlowResponseMessage * result =
				new IpcmAllocateFlowResponseMessage();

	if (attrs[IAFREM_ATTR_RESULT]) {
		result->setResult(nla_get_u32(attrs[IAFREM_ATTR_RESULT]));
	}

	if (attrs[IAFREM_ATTR_ERROR_DESCRIPTION]) {
			result->setErrorDescription(
					nla_get_string(attrs[IAFREM_ATTR_ERROR_DESCRIPTION]));
	}

	return result;
}

IpcmIPCProcessRegisteredToDIFNotification *
	parseIpcmIPCProcessRegisteredToDIFNotification(nlmsghdr *hdr){
	struct nla_policy attr_policy[IIPRTDN_ATTR_MAX + 1];
	attr_policy[IIPRTDN_ATTR_IPC_PROCESS_NAME].type = NLA_NESTED;
	attr_policy[IIPRTDN_ATTR_IPC_PROCESS_NAME].minlen = 0;
	attr_policy[IIPRTDN_ATTR_IPC_PROCESS_NAME].maxlen = 0;
	attr_policy[IIPRTDN_ATTR_DIF_NAME].type = NLA_NESTED;
	attr_policy[IIPRTDN_ATTR_DIF_NAME].minlen = 0;
	attr_policy[IIPRTDN_ATTR_DIF_NAME].maxlen = 0;
	struct nlattr *attrs[IIPRTDN_ATTR_MAX + 1];

	int err = genlmsg_parse(hdr, sizeof(struct rinaHeader), attrs,
			IIPRTDN_ATTR_MAX, attr_policy);
	if (err < 0) {
		LOG_ERR(
				"Error parsing IpcmIPCProcessRegisteredToDIFNotification information from Netlink message: %d",
				err);
		return 0;
	}

	IpcmIPCProcessRegisteredToDIFNotification * result =
			new IpcmIPCProcessRegisteredToDIFNotification ();
	ApplicationProcessNamingInformation * ipcProcessName;
	ApplicationProcessNamingInformation * difName;

	if (attrs[IIPRTDN_ATTR_IPC_PROCESS_NAME]) {
		ipcProcessName = parseApplicationProcessNamingInformationObject(
				attrs[IIPRTDN_ATTR_IPC_PROCESS_NAME]);
		if (ipcProcessName == 0) {
			delete result;
			return 0;
		} else {
			result->setIpcProcessName(*ipcProcessName);
			delete ipcProcessName;
		}
	}

	if (attrs[IIPRTDN_ATTR_DIF_NAME]) {
		difName = parseApplicationProcessNamingInformationObject(
				attrs[IIPRTDN_ATTR_DIF_NAME]);
		if (difName == 0) {
			delete result;
			return 0;
		} else {
			result->setDifName(*difName);
			delete difName;
		}
	}

	return result;
}

}
