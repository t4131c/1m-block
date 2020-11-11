#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <string.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnet.h>
#define MAX_TABLE 1000000

typedef struct Node {
	char hostname[100];
	struct Node * next;
}node;

int block_chk;
int block_idx;

char target_block[100];

node *block_list[1000000];
//char block_list[1000000][100];

void usage() {
    printf("1m-block <site list file>\n");
    printf("1m-block top-1m.txt\n");
}

int myhash(const char * str) {
	int hash = 401;
	int c;

	while (*str != '\0') {
		hash = ((hash << 4) + (int)(*str)) % MAX_TABLE;
		str++;
	}

	return hash % MAX_TABLE;
}

void add_host(const char * data) {
	node * new_node = (node *)malloc(sizeof(node));
	strncpy(new_node->hostname, data, strlen(data));
	new_node->next = NULL;

	int idx = myhash(data);

	if (block_list[idx] == NULL) {
		block_list[idx] = new_node;
	}
	else {
		node * root = block_list[idx];
		while (root != NULL) {
			root = root -> next;
		}
		block_list[idx] -> next = new_node;
	}
}

int find_host(const char * data){
	int idx = myhash(data);
	if(block_list[idx] == NULL){
		return 0;
	}
	node *root = block_list[idx];
	while(root != NULL){
		if(!strncmp(data, root -> hostname, strlen(root -> hostname))){
			return 1;
		}
		root = root -> next;
	}
	return 0;
}

int get_host(u_char *data){
	if(data[0] != 0x45){
		return 0;
	}
	data = data + sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_tcp_hdr);

	for(int i = 0; i < 100; i++){
		u_char *chk = data + i;
		if(strncmp(chk,"Host: ",6)){
			continue;
		}
		//printf("host\n\n\n");
		chk += 6;
		for(int j = 0; j < 100; j++){
			if(chk[j] == '\r' && chk[j+1] == '\n'){
				memset(target_block,0x00,100);
				strncpy(target_block,chk,j);
				return 1;
			}
		}
	}
	return 0;
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{

	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0){
		
		printf("payload_len=%d ", ret);
	}
	int have_host = get_host(data);
	if(have_host){
		block_chk = find_host(target_block);
	}	
	fputc('\n', stdout);

	return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
	printf("entering callback\n");
	if(block_chk == 1){
		printf("[*] blocked %s\n", target_block);
		block_chk = 0;
		memset(target_block,0x00,100);
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	}
	else{
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}
	
}



int main(int argc, char **argv)
{
	if(argc != 2){
		usage();
		exit(1);
	}
	FILE *inputFile = NULL;
	
	inputFile = fopen(argv[1], "r" );
	if( inputFile != NULL )
	{
		while( !feof( inputFile ) )
		{
			char strTemp[100];
			fgets( strTemp, sizeof(strTemp), inputFile );
			char * result = strchr(strTemp,',');
			result[strlen(result) - 1] = '\x00';
			result += 1;
			//printf("%s\n",result);
			add_host(result);
			block_idx++;
			//printf( "%s", strTemp );

		}
		fclose( inputFile );
	}
	else
	{
		printf("[*] Error check the input file!\n");
		exit(1);
	}
	// for(int i = 0; i < block_idx; i++){
	// 	printf("%s\n",block_list[i]);
	// }
	//block = argv[1]; 
	//block_len = strlen(block);

	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
