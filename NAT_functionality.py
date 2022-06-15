#BITI POLYXENI 2582
# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Two OpenFlow 1.0 L3 Static Routers and two OpenFlow 1.0 L2 learning switches.
"""


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet.arp import arp
from ryu.lib.packet import icmp
from ryu.lib.packet import udp
from ryu.lib.packet.packet import Packet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ether_types

"""
fill in the code here for any used constant (optional)
"""

class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        #changes made
        self.port_counter = -1
        self.ports_pool = list(range(5001, 65536))

    def add_flow(self, datapath, match, actions):
        ofproto = datapath.ofproto

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = msg.datapath_id

        self.logger.info("Datapath ID is %s", hex(dpid))

        if dpid == 0x1A:
            '''
            fill in the code here for the proactive setup of flows
            '''
            match = datapath.ofproto_parser.OFPMatch(dl_type=0x800, nw_dst="192.168.2.0", nw_dst_mask=24, nw_src="192.168.1.0", nw_src_mask=24, nw_tos=8)
            actions = []
            actions.append(datapath.ofproto_parser.OFPActionSetDlSrc("00:00:00:00:05:01"))
            actions.append(datapath.ofproto_parser.OFPActionSetDlDst("00:00:00:00:05:02"))
            actions.append(datapath.ofproto_parser.OFPActionOutput(4))
            self.add_flow(datapath, match, actions)

            #PACKET FROM 200.0.0.0/24 TO 192.168.2.0/24
            #match = datapath.ofproto_parser.OFPMatch(dl_type=0x800, nw_dst="192.168.2.0", nw_src="200.0.0.0",nw_dst_mask=24, nw_src_mask=24, nw_proto=17)
            #actions = []
            #actions.append(datapath.ofproto_parser.OFPActionSetDlSrc("00:00:00:00:03:01"))
            #actions.append(datapath.ofproto_parser.OFPActionSetDlDst("00:00:00:00:03:02"))
            #actions.append(datapath.ofproto_parser.OFPActionOutput(1))
            #self.add_flow(datapath, match, actions)

        elif dpid == 0x1B:
            '''
            fill in the code here for the proactive setup of flows
            '''
           #PACKET WITH TOS = 8
            match_tos = datapath.ofproto_parser.OFPMatch(dl_type=0x800, nw_dst="192.168.1.0",nw_dst_mask=24, nw_src="192.168.2.0", nw_src_mask=24, nw_tos=8)
            actions_tos = []
            actions_tos.append(datapath.ofproto_parser.OFPActionSetDlSrc("00:00:00:00:05:02"))
            actions_tos.append(datapath.ofproto_parser.OFPActionSetDlDst("00:00:00:00:05:01"))
            actions_tos.append(datapath.ofproto_parser.OFPActionOutput(4))
            self.add_flow(datapath, match_tos, actions_tos)

           #PACKET FOR 200.0.0.0/24 IP NETWORK
            match = datapath.ofproto_parser.OFPMatch(dl_type=0x800, nw_dst="200.0.0.2", nw_dst_mask=24, nw_proto=17)
            actions = []
            actions.append(datapath.ofproto_parser.OFPActionSetDlSrc("00:00:00:00:03:02"))
            actions.append(datapath.ofproto_parser.OFPActionSetDlDst("00:00:00:00:03:01"))
            actions.append(datapath.ofproto_parser.OFPActionOutput(1))
            self.add_flow(datapath, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        inPort = msg.in_port
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        dst = eth.dst
        src = eth.src
        ethertype = eth.ethertype

        #self.logger.info("packet in %s %s %s %s %s", hex(dpid).ljust(4), hex(ethertype), src, dst, msg.in_port)

        if dpid == 0x2 or dpid == 0x3:
            self.mac_to_port.setdefault(dpid, {})
            # learn a mac address to avoid FLOOD next time.
            self.mac_to_port[dpid][src] = msg.in_port
            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD
            match = datapath.ofproto_parser.OFPMatch(
                in_port=msg.in_port, dl_dst=haddr_to_bin(dst))
            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
            # install a flow to avoid packet_in next time
            if out_port != ofproto.OFPP_FLOOD:
                self.add_flow(datapath, match, actions)
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
            out = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
                actions=actions, data=data)
            datapath.send_msg(out)
            return
        if dpid == 0x1A:
            if ethertype == ether_types.ETH_TYPE_ARP: # this packet is ARP packet
                """
                fill in the code here for the ARP requests operation, creating and sending ARP replies.
                """
                arpPacket = pkt.get_protocol(arp)
                if ((arpPacket.opcode == 1) and (str(arpPacket.dst_ip) == "192.168.1.1" or str(arpPacket.dst_ip) == "200.0.0.1")):
                    arp_dstIp = arpPacket.dst_ip
                    self.logger.info("receive ARP request %s => %s (port%d)", eth.src, eth.dst, msg.in_port)
                    self.reply_arp(datapath, eth, arpPacket, str(arpPacket.dst_ip), str(arpPacket.src_ip), src, inPort)
                return
            elif ethertype == ether_types.ETH_TYPE_IP: # this packet is IP packet
                """
                fill in the code here for the IP packets operation
                You must i) handle the packets coming to the controller with a packet_out message and then
                ii) add an appropriate flow, modifying and using the add_flow function, in order the controller to not receive a packet with the same headers again.
                """
                ip = pkt.get_protocol(ipv4.ipv4)
                srcip = ip.src
                dstip = ip.dst
                pkt_ipv4_proto = ip.proto
                pkt_udp = pkt.get_protocol(udp.udp)
                #self.logger.info("PROTO: %s", pkt_ipv4_proto)
                if(dstip == "192.168.2.2" or dstip == "192.168.2.3"):
                    outPort = 1
                    match = datapath.ofproto_parser.OFPMatch(dl_type=0x800, nw_dst="192.168.2.0", nw_dst_mask=24, nw_tos=0)
                    actions = []
                    actions.append(datapath.ofproto_parser.OFPActionSetDlSrc("00:00:00:00:03:01"))
                    actions.append(datapath.ofproto_parser.OFPActionSetDlDst("00:00:00:00:03:02"))
                    actions.append(datapath.ofproto_parser.OFPActionOutput(outPort))
                    self.add_flow(datapath, match, actions)
                    
                    out = datapath.ofproto_parser.OFPPacketOut(
                        datapath=datapath, buffer_id=0xffffffff, in_port=datapath.ofproto.OFPP_CONTROLLER,
                        actions=actions, data = msg.data)
                    datapath.send_msg(out)
                elif(dstip == "192.168.1.2"):
                    outPort = 2
                    match = datapath.ofproto_parser.OFPMatch(dl_type=0x800, nw_dst="192.168.1.2", nw_src="192.168.2.0", nw_src_mask=24)
                    actions = []
                    actions.append(datapath.ofproto_parser.OFPActionSetDlSrc("00:00:00:00:01:01"))
                    actions.append(datapath.ofproto_parser.OFPActionSetDlDst("00:00:00:00:01:02"))
                    actions.append(datapath.ofproto_parser.OFPActionOutput(outPort))
                    self.add_flow(datapath, match, actions)
                    
                    out = datapath.ofproto_parser.OFPPacketOut(
                        datapath=datapath, buffer_id=0xffffffff, in_port=datapath.ofproto.OFPP_CONTROLLER,
                        actions=actions, data = msg.data)
                    datapath.send_msg(out)
                elif(dstip == "192.168.1.3"):
                    outPort = 2
                    match = datapath.ofproto_parser.OFPMatch(dl_type=0x800, nw_dst="192.168.1.3", nw_src="192.168.2.0", nw_src_mask=24)
                    actions = []
                    actions.append(datapath.ofproto_parser.OFPActionSetDlSrc("00:00:00:00:01:01"))
                    actions.append(datapath.ofproto_parser.OFPActionSetDlDst("00:00:00:00:01:03"))
                    actions.append(datapath.ofproto_parser.OFPActionOutput(outPort))
                    self.add_flow(datapath, match, actions)
                    
                    out = datapath.ofproto_parser.OFPPacketOut(
                        datapath=datapath, buffer_id=0xffffffff, in_port=datapath.ofproto.OFPP_CONTROLLER,
                        actions=actions, data = msg.data)
                    datapath.send_msg(out)
                elif("200.0.0.2" in dstip and pkt_udp):
                    #pkt_udp = pkt.get_protocol(udp.udp)
                    #if pkt_udp:
                    self.logger.info("GOT UDP PACKET FOR: %s", dstip)
                    pkt_udp_src_port = pkt_udp.src_port
                    pkt_udp_dst_port = pkt_udp.dst_port
                       #COUNTER TO GIVE NEW NAT PORT FOR EVERY NEW CONNECTION
                    self.port_counter += 1
                    nat_port = self.ports_pool.pop(self.port_counter)
                        
                    match = datapath.ofproto_parser.OFPMatch(dl_type=0x800, nw_dst=dstip, nw_proto=17, nw_src=srcip, tp_src = pkt_udp_src_port, tp_dst=pkt_udp_dst_port)
                    actions = []
                    actions.append(datapath.ofproto_parser.OFPActionSetDlSrc("00:00:00:00:04:01"))
                    actions.append(datapath.ofproto_parser.OFPActionSetDlDst("00:00:00:00:04:02"))
                    actions.append(datapath.ofproto_parser.OFPActionSetNwSrc("200.0.0.1"))
                    actions.append(datapath.ofproto_parser.OFPActionSetTpSrc(nat_port))
                    actions.append(datapath.ofproto_parser.OFPActionOutput(3))
                    self.add_flow(datapath, match, actions)

                    match_back = datapath.ofproto_parser.OFPMatch(dl_type=0x800, nw_dst="200.0.0.1", nw_src=dstip, nw_proto=17, tp_dst=nat_port) 
                    #self.logger.info("INSTALLING FLOW FOR: %s, PORT: %s, INPORT: %s, NAT PORT: %s, ", srcip, pkt_udp_dst_port, inPort, nat_port)
                    actions_back = []
                    actions_back.append(datapath.ofproto_parser.OFPActionSetDlSrc("00:00:00:00:04:01"))
                    actions_back.append(datapath.ofproto_parser.OFPActionSetDlDst(src))
                    actions_back.append(datapath.ofproto_parser.OFPActionSetNwDst(srcip))
                    actions_back.append(datapath.ofproto_parser.OFPActionSetTpDst(pkt_udp_src_port))
                    actions_back.append(datapath.ofproto_parser.OFPActionOutput(inPort))
                    self.add_flow(datapath, match_back, actions_back)

                    out = datapath.ofproto_parser.OFPPacketOut(
                        datapath=datapath, buffer_id=0xffffffff, in_port=datapath.ofproto.OFPP_CONTROLLER,
                        actions=actions, data = msg.data)
                    datapath.send_msg(out)

                elif(("192.168.1" not in dstip) and ("192.168.2" not in dstip)):
                    dstMac = src
                    srcMac = "00:00:00:00:01:01"
                    pkt_icmp = pkt.get_protocol(icmp.icmp)
                    send_pkt = packet.Packet()
                    send_pkt.add_protocol(ethernet.ethernet(dst = dstMac, src = srcMac, ethertype = ethertype))
                    send_pkt.add_protocol(ipv4.ipv4(dst=srcip, src="192.168.1.1", proto=pkt_ipv4_proto))
                    send_pkt.add_protocol(icmp.icmp(type_=icmp.ICMP_DEST_UNREACH, code=icmp.ICMP_HOST_UNREACH_CODE, data = icmp.dest_unreach(data=bytearray()+msg.data[14:])))
                    send_pkt.serialize()
                    outPort = 2
                    actions = [datapath.ofproto_parser.OFPActionOutput(outPort)]
                    out = datapath.ofproto_parser.OFPPacketOut(
                        datapath=datapath, buffer_id=0xffffffff, in_port=datapath.ofproto.OFPP_CONTROLLER,
                        actions=actions, data = send_pkt.data)
                    datapath.send_msg(out)
                return
            return
        if dpid == 0x1B:
            if ethertype == ether_types.ETH_TYPE_ARP: # this packet is ARP packet
                """
                fill in the code here for the ARP requests operation, creating and sending ARP replies.
                """
                arpPacket = pkt.get_protocol(arp)
                if ((arpPacket.opcode == 1) and str(arpPacket.dst_ip) == "192.168.2.1"):
                    arp_dstIp = arpPacket.dst_ip
                    self.logger.info("receive ARP request %s => %s (port%d)", eth.src, eth.dst, msg.in_port)
                    self.reply_arp(datapath, eth, arpPacket, str(arpPacket.dst_ip), str(arpPacket.src_ip), src, inPort)
                return
            elif ethertype == ether_types.ETH_TYPE_IP: # this packet is IP packet
                """
                fill in the code here for the IP packets operation
                You must i) handle the packets coming to the controller with a packet_out message and then
                ii) add an appropriate flow, modifying and using the add_flow function, in order the controller to not receive a packet with the same headers again.
                """
                ip = pkt.get_protocol(ipv4.ipv4)
                srcip = ip.src
                dstip = ip.dst
                pkt_ipv4_proto = ip.proto
                pkt_udp = pkt.get_protocol(udp.udp)
                if(dstip == "192.168.1.2" or dstip == "192.168.1.3"):
                    outPort = 1
                    match = datapath.ofproto_parser.OFPMatch(dl_type=0x800, nw_dst="192.168.1.0", nw_dst_mask=24, nw_tos = 0)
                    actions = []
                    actions.append(datapath.ofproto_parser.OFPActionSetDlSrc("00:00:00:00:03:02"))
                    actions.append(datapath.ofproto_parser.OFPActionSetDlDst("00:00:00:00:03:01"))
                    actions.append(datapath.ofproto_parser.OFPActionOutput(outPort))
                    self.add_flow(datapath, match, actions)

                    out = datapath.ofproto_parser.OFPPacketOut(
                        datapath=datapath, buffer_id=0xffffffff, in_port=datapath.ofproto.OFPP_CONTROLLER,
                        actions=actions, data = msg.data)
                    datapath.send_msg(out)
                elif(dstip == "192.168.2.2"):
                    outPort = 2
                    match = datapath.ofproto_parser.OFPMatch(dl_type=0x800, nw_dst="192.168.2.2", nw_src="192.168.1.0", nw_src_mask=24)
                    actions = []
                    actions.append(datapath.ofproto_parser.OFPActionSetDlSrc("00:00:00:00:02:01"))
                    actions.append(datapath.ofproto_parser.OFPActionSetDlDst("00:00:00:00:02:02"))
                    actions.append(datapath.ofproto_parser.OFPActionOutput(outPort))
                    self.add_flow(datapath, match, actions)
                    out = datapath.ofproto_parser.OFPPacketOut(
                        datapath=datapath, buffer_id=0xffffffff, in_port=datapath.ofproto.OFPP_CONTROLLER,
                        actions=actions, data = msg.data)
                    datapath.send_msg(out)
                elif(dstip == "192.168.2.3"):
                    outPort = 2
                    match = datapath.ofproto_parser.OFPMatch(dl_type=0x800, nw_dst="192.168.2.3", nw_src="192.168.1.1", nw_src_mask=24)
                    actions = []
                    actions.append(datapath.ofproto_parser.OFPActionSetDlSrc("00:00:00:00:02:01"))
                    actions.append(datapath.ofproto_parser.OFPActionSetDlDst("00:00:00:00:02:03"))
                    actions.append(datapath.ofproto_parser.OFPActionOutput(outPort))
                    self.add_flow(datapath, match, actions)
                    out = datapath.ofproto_parser.OFPPacketOut(
                        datapath=datapath, buffer_id=0xffffffff, in_port=datapath.ofproto.OFPP_CONTROLLER,
                        actions=actions, data = msg.data)
                    datapath.send_msg(out)
                elif(("192.168.1" not in dstip) and ("192.168.2" not in dstip)):
                    #self.logger.info("GOT PACKET FOR UNKNOWN NETWORK FROM: %s", srcip)
                    dstMac = src
                    srcMac = "00:00:00:00:02:01"
                    pkt_icmp = pkt.get_protocol(icmp.icmp)
                    send_pkt = packet.Packet()
                    send_pkt.add_protocol(ethernet.ethernet(dst = dstMac, src = srcMac, ethertype = ethertype))
                    send_pkt.add_protocol(ipv4.ipv4(dst=srcip, src="192.168.2.1", proto=pkt_ipv4_proto))
                    send_pkt.add_protocol(icmp.icmp(type_=icmp.ICMP_DEST_UNREACH, code=icmp.ICMP_HOST_UNREACH_CODE, data=icmp.dest_unreach(data=msg.data[14:])))
                    send_pkt.serialize()
                    outPort = 2
                    actions = [datapath.ofproto_parser.OFPActionOutput(outPort)]
                    out = datapath.ofproto_parser.OFPPacketOut(
                        datapath=datapath, buffer_id=0xffffffff, in_port=datapath.ofproto.OFPP_CONTROLLER,
                        actions=actions, data = send_pkt.data)
                    datapath.send_msg(out)
                return
            return

    """
    fill in the code here for the ARP reply functions.
    """
    def reply_arp(self, datapath, etherFrame, arpPacket, arp_dstIp, arp_srcIp, src, inPort):
        dstIp = arp_srcIp
        srcIp = arp_dstIp
        dstMac = src
        if arp_dstIp == "192.168.1.1":
            srcMac = "00:00:00:00:01:01"
        elif arp_dstIp == "192.168.2.1":
            srcMac = "00:00:00:00:02:01"
        elif arp_dstIp == "200.0.0.1":
            srcMac = "00:00:00:00:04:01"
        self.send_arp(datapath, 2, srcMac, srcIp, dstMac, dstIp, inPort)

    def send_arp(self, datapath, opcode, srcMac, srcIp, dstMac, dstIp, outPort):
        e = ethernet.ethernet(dstMac, srcMac, ether_types.ETH_TYPE_ARP)
        a = arp(1, 0x0800, 6, 4, opcode, srcMac, srcIp, dstMac, dstIp)
        p = Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()

        actions = [datapath.ofproto_parser.OFPActionOutput(outPort)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=0xffffffff,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=p.data)
        datapath.send_msg(out)
    

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)
