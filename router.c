
#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h> 
#include <string.h>
#include <net/if_arp.h>

#define ETHERTYPE_IP 0x0800  /* IP */
#define ETHERTYPE_ARP 0x0806 /* Address resolution */
#define ARPOP_REQUEST 1  /* ARP request */
#define ARPOP_REPLY 2  /* ARP reply */

#define MAX_ROUTE_ENTRIES 100000
#define MAX_ARP_ENTRIES 10

/* Struct for the packets */
typedef struct {
	char *payload;
	int interface;
	int len;
} packet;

/* Routing table */
struct route_table_entry *rtable;
int rtable_len;

/* Arp table */
struct arp_entry *arp_table;
int arp_entries;

/**
 * @brief Get the best route from the routing table
 * 		for the given destination address.
 * 
 * @param ip_dest 
 * @return struct route_table_entry* 
 */
struct route_table_entry *get_best_route(uint32_t ip_dest) {

	/* Binary search for the best route */
	int left = 0;
	int right = rtable_len - 1;
	int middle = 0;

	struct route_table_entry *found_entry = NULL;

	while (left <= right) {

		middle = left + (right - left) / 2;

		struct route_table_entry *entry = &rtable[middle];

		if (ntohl(entry->prefix & entry->mask) == ntohl(ip_dest & entry->mask)) {
			found_entry = entry;
			left = middle + 1;

		} else if (ntohl(entry->prefix & entry->mask) < ntohl(ip_dest & entry->mask)) {
			left = middle + 1;

		} else {
			right = middle - 1;
		}
	}

	return found_entry;
}

struct arp_entry *get_arp_entry(uint32_t given_ip) {

	/* Iterate through the MAC table and search for an entry
	 * that matches given_ip. */
    for (int i = 0; i < arp_entries; i++) {
    	if (arp_table[i].ip == given_ip) {
    		return &arp_table[i];
    	}
    }
	return NULL;
}

/**
 * @brief compare function for qsort
 * 
 * @param a 
 * @param b 
 * @return int 
 */
int compare_rtable(const void *a, const void *b) {

	struct route_table_entry *entry_a = (struct route_table_entry *)a;
	struct route_table_entry *entry_b = (struct route_table_entry *)b;

	/* if the first address is bigger than the second one, return 1 */
	if (ntohl(entry_a->prefix & entry_a->mask) 
			> ntohl(entry_b->prefix & entry_b->mask)) {
		return 1;
	} else if (ntohl(entry_a->prefix & entry_a->mask) 
				< ntohl(entry_b->prefix & entry_b->mask)) {
		return -1;
	} else {
		/* if the addresses are equal, return the difference between the masks */
		return ntohl(entry_a->mask) - ntohl(entry_b->mask);
	}
}

/**
 * @brief function that send an icmp message
 * 
 * @param source_ip
 * @param dest_ip 
 * @param source_MAC 
 * @param dest_MAC 
 * @param interface on which the message will be sent
 * @param type of the icmp message
 * @param code of the icmp message
 */
void send_icmp(uint32_t source_ip, uint32_t dest_ip, uint8_t *source_MAC, uint8_t *dest_MAC,
				int interface, uint8_t type, uint8_t code) {

	/* create the ethernet header */
	struct ether_header *eth_hdr = (struct ether_header *) malloc(sizeof(struct ether_header));
	DIE(eth_hdr == NULL, "error at malloc eth_hdr");

	memcpy(eth_hdr->ether_dhost, dest_MAC, 6);
	memcpy(eth_hdr->ether_shost, source_MAC, 6);
	eth_hdr->ether_type = htons(ETHERTYPE_IP);

	/* create the ip header */
	struct iphdr *ip_hdr = (struct iphdr *) malloc(sizeof(struct iphdr));
	DIE(ip_hdr == NULL, "error at malloc ip_hdr");

	ip_hdr->version = 4;
	ip_hdr->ihl = 5;
	ip_hdr->tos = 0;
	ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	ip_hdr->id = htons(1);
	ip_hdr->frag_off = 0;
	ip_hdr->ttl = 64;
	ip_hdr->protocol = IPPROTO_ICMP;
	ip_hdr->check = 0;
	ip_hdr->saddr = source_ip;
	ip_hdr->daddr = dest_ip;
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

	/* create the icmp header */
	struct icmphdr *icmp_hdr = (struct icmphdr *) malloc(sizeof(struct icmphdr));
	DIE(icmp_hdr == NULL, "error at malloc icmp_hdr");

	icmp_hdr->type = type;
	icmp_hdr->code = code;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr)));

	/* create the packet */
	char buf[MAX_PACKET_LEN];

	memcpy(buf, eth_hdr, sizeof(struct ether_header));
	memcpy(buf + sizeof(struct ether_header), ip_hdr, sizeof(struct iphdr));
	memcpy(buf + sizeof(struct ether_header) + sizeof(struct iphdr), icmp_hdr, sizeof(struct icmphdr));

	int len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);

	/* send the packet */
	send_to_link(interface, buf, len);
}

/**
 * @brief send and arp request
 * 
 * @param source_ip 
 * @param dest_ip 
 * @param source_MAC 
 * @param interface on which the request will be sent
 */
void send_arp_request(uint32_t source_ip, uint32_t dest_ip, uint8_t *source_MAC, int interface) {

	/* create the ethernet header */
	struct ether_header *eth_hdr = (struct ether_header *) malloc(sizeof(struct ether_header));
	DIE(eth_hdr == NULL, "error at malloc eth_hdr");

	memset(eth_hdr->ether_dhost, 0xFF, 6);
	memcpy(eth_hdr->ether_shost, source_MAC, 6);
	eth_hdr->ether_type = htons(ETHERTYPE_ARP);

	/* create the arp header */
	struct arp_header *arp_hdr = (struct arp_header *) malloc(sizeof(struct arp_header));
	DIE(arp_hdr == NULL, "error at malloc arp_hdr");

	arp_hdr->htype= htons(1);
	arp_hdr->ptype = htons(2048);
	arp_hdr->hlen = 6;
	arp_hdr->plen = 4;
	arp_hdr->op = htons(ARPOP_REQUEST);
	memcpy(arp_hdr->sha, source_MAC, 6);
	arp_hdr->spa = source_ip;

	memset(arp_hdr->tha, 0, 6);
	arp_hdr->tpa= dest_ip;

	/* create the packet */
	char buf[MAX_PACKET_LEN];

	memcpy(buf, eth_hdr, sizeof(struct ether_header));
	memcpy(buf + sizeof(struct ether_header), arp_hdr, sizeof(struct arp_header));

	int len = sizeof(struct ether_header) + sizeof(struct arp_header);

	/* send the packet */
	send_to_link(interface, buf, len);
}


int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	init(argc - 2, argv + 2);

	rtable = malloc(sizeof(struct route_table_entry) * MAX_ROUTE_ENTRIES);
	DIE(rtable == NULL, "error at malloc rtable");

	arp_table = malloc(sizeof(struct  arp_entry) * MAX_ARP_ENTRIES);
	DIE(arp_table == NULL, "error at malloc arp_table");

	rtable_len = read_rtable(argv[1], rtable);

	/* sort the routing table */
	qsort(rtable, rtable_len, sizeof(struct route_table_entry), compare_rtable);

	/* create the arp queue */
	queue arp_queue = queue_create();

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;

		uint8_t interface_mac[6];

		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {

			struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

			/* Verify checksum */
			uint16_t old_checksum = ntohs(ip_hdr->check);
			ip_hdr->check = 0;
			uint16_t new_checksum = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));

			if (old_checksum != new_checksum) {
				continue;
			}

			/* Verify TTL and actualize it */

			if (ip_hdr->ttl <= 1) {
				/* Send icmp error for TIME LIMIT EXCEEDED */
				send_icmp(ip_hdr->daddr, ip_hdr->saddr, eth_hdr->ether_dhost,
							 eth_hdr->ether_shost, interface, 11, 0);
				continue;
			}

			ip_hdr->ttl--;

			/* Verify if the packet is an ICMP echo request for the router */

			if (ip_hdr->daddr == inet_addr(get_interface_ip(interface)) 
				&& ip_hdr->protocol == IPPROTO_ICMP) {

				struct icmphdr *icmp_hdr 
					= (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));

				if (icmp_hdr->type == 8 && icmp_hdr->code == 0) {
					/* Send ICMP echo reply */
					send_icmp(ip_hdr->daddr, ip_hdr->saddr, eth_hdr->ether_dhost,
								 eth_hdr->ether_shost, interface, 0, 0);
					continue;
				}
			}

			/* Look in the route table for the best route */

			struct route_table_entry *best_route = get_best_route(ip_hdr->daddr);

			if (best_route == NULL) {
				/* Send icmp error for DESTINATION UNREACHABLE */
				send_icmp(ip_hdr->daddr, ip_hdr->saddr, eth_hdr->ether_dhost,
							 eth_hdr->ether_shost, interface, 3, 0);
				continue;
			}

			/* Update the checksum */
			ip_hdr->check = 0;
			ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));


			/* Look for the MAC address of the next hop */
			struct arp_entry *arp_entry = get_arp_entry(best_route->next_hop);

			if (arp_entry == NULL) {

				/* Form the packet that need to be queued */
				packet *queue_entry = malloc(sizeof(packet));
				DIE(queue_entry == NULL, "error at malloc queue_entry");
				queue_entry->interface = interface;
				queue_entry->len = len;
				queue_entry->payload = malloc(len);
				DIE(queue_entry->payload == NULL, "error at malloc queue_entry->payload");
				memcpy(queue_entry->payload, buf, len);

				/* Add the packet to the queue */
				queue_enq(arp_queue, queue_entry);

				/* Send ARP request */
				get_interface_mac(best_route->interface, interface_mac);

				send_arp_request(inet_addr(get_interface_ip(best_route->interface)),
								 best_route->next_hop, interface_mac ,best_route->interface);

				continue;

			} else {
				/* Update the MAC addresses */
				get_interface_mac(best_route->interface, eth_hdr->ether_shost);
				memcpy(eth_hdr->ether_dhost, arp_entry->mac, sizeof(eth_hdr->ether_dhost));

				/* Just send the packet */
				send_to_link(best_route->interface, buf, len);
			}

		} else if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {

			struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));

			/* Verify if the arp packet is a request message and if it is for the router */
			if (arp_hdr->op == htons(ARPOP_REQUEST) 
				&& arp_hdr->tpa == inet_addr(get_interface_ip(interface))) {

				/* Send ARP reply */
				get_interface_mac(interface, interface_mac);

				memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_dhost));
				memcpy(eth_hdr->ether_shost, interface_mac, sizeof(eth_hdr->ether_shost));

				memcpy(arp_hdr->tha, arp_hdr->sha, sizeof(arp_hdr->tha));
				memcpy(arp_hdr->sha, interface_mac, sizeof(arp_hdr->sha));

				arp_hdr->tpa = arp_hdr->spa;
				arp_hdr->spa = inet_addr(get_interface_ip(interface));

				arp_hdr->op = htons(ARPOP_REPLY);

				send_to_link(interface, buf, len);
				continue;
			}
			
			/* Verify if the arp packet is a reply message and if it is for the router */
			if (arp_hdr->op == htons(ARPOP_REPLY) 
				&& arp_hdr->tpa == inet_addr(get_interface_ip(interface))) {

				/* Add the entry to the arp table */
				struct arp_entry arp_entry;
				arp_entry.ip = arp_hdr->spa;
				memcpy(arp_entry.mac, arp_hdr->sha, sizeof(arp_entry.mac));

				arp_table[arp_entries] = arp_entry;
				arp_entries++;

				/* Send the packets from the queue that were waiting for this arp reply */
				while (!queue_empty(arp_queue)) {
					packet *pack = (packet *)queue_deq(arp_queue);

					struct ether_header *eth_hdr = (struct ether_header *)pack->payload;
					struct iphdr *ip_hdr = (struct iphdr *)(pack->payload + sizeof(struct ether_header));

					struct route_table_entry *best_route = get_best_route(ip_hdr->daddr);
					struct arp_entry *entry = get_arp_entry((best_route->next_hop));

					if (entry) {
						memcpy(eth_hdr->ether_dhost, entry->mac, sizeof(eth_hdr->ether_dhost));
						get_interface_mac(best_route->interface, eth_hdr->ether_shost);

						send_to_link(best_route->interface, pack->payload, pack->len);
					} else {
						queue_enq(arp_queue, pack);
						break;
					}
				}
			}

		}

	}
}
