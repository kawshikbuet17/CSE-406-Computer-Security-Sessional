#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/inet.h>

static struct nf_hook_ops hook1, hook2; 
int p = 5;
int countArr[7] = {0,0,0,0,0,0,0};
char ippc1[16] = "10.9.0.1";
char ippc2[16] = "10.9.0.5";
char ippc3[16] = "10.9.0.11";
char ippc4[16] = "192.168.60.5";
char ippc5[16] = "192.168.60.6";
char ippc6[16] = "192.168.60.7";

unsigned int blockICMP(void *priv, struct sk_buff *skb,
                       const struct nf_hook_state *state)
{
printk(KERN_WARNING "*** Blocking");
   struct iphdr *iph;
   //struct udphdr *udph;
   struct icmphdr *icmph;

   u16  port   = 53;
   char ip[16] = "192.168.60.5";
   u32  ip_addr;

   u32 src_addr_pc1;
   u32 src_addr_pc2;
   u32 src_addr_pc3;
   u32 src_addr_pc4;
   u32 src_addr_pc5;
   u32 src_addr_pc6;

   if (!skb) return NF_ACCEPT;

   iph = ip_hdr(skb);
   // Convert the IPv4 address from dotted decimal to 32-bit binary
   in4_pton(ip, -1, (u8 *)&ip_addr, '\0', NULL);
   
   in4_pton(ip, -1, (u8 *)&src_addr_pc1, '\0', NULL);
   in4_pton(ip, -1, (u8 *)&src_addr_pc2, '\0', NULL);
   in4_pton(ip, -1, (u8 *)&src_addr_pc3, '\0', NULL);
   in4_pton(ip, -1, (u8 *)&src_addr_pc4, '\0', NULL);
   in4_pton(ip, -1, (u8 *)&src_addr_pc5, '\0', NULL);
   in4_pton(ip, -1, (u8 *)&src_addr_pc6, '\0', NULL);

   if (iph->protocol == IPPROTO_ICMP) {
       //int num;
	   //FILE *fptr;
	   //fptr = fopen(iph->saddr+".txt","w");
	   //if(fptr == NULL)
	   //{
		 // printf("Error!");   
		 // exit(1);             
	   //}
	   //sfcanf(fptr, "%d",&num);
	   
	   if(iph->saddr == src_addr_pc1) {
	   	countArr[1]++;
	   	icmph = icmp_hdr(skb);
       	//udph = udp_hdr(skb);
       	if (iph->daddr == ip_addr && countArr[1] >= p){
            printk(KERN_WARNING "*** Dropping %pI4 (ICMP), port %d\n", &(iph->daddr), port);
            return NF_DROP;
        	}
	   }
	   
	   if(iph->saddr == src_addr_pc2) {
	   	countArr[2]++;
	   	icmph = icmp_hdr(skb);
       	//udph = udp_hdr(skb);
       	if (iph->daddr == ip_addr && countArr[2] >= p){
            printk(KERN_WARNING "*** Dropping %pI4 (ICMP), port %d\n", &(iph->daddr), port);
            return NF_DROP;
        	}
	   }
	   
	   if(iph->saddr == src_addr_pc3) {
	   	countArr[3]++;
	   	icmph = icmp_hdr(skb);
       	//udph = udp_hdr(skb);
       	if (iph->daddr == ip_addr && countArr[3] >= p){
            printk(KERN_WARNING "*** Dropping %pI4 (ICMP), port %d\n", &(iph->daddr), port);
            return NF_DROP;
        	}
	   }
	   
	   if(iph->saddr == src_addr_pc4) {
	   	countArr[4]++;
	   	icmph = icmp_hdr(skb);
       	//udph = udp_hdr(skb);
       	if (iph->daddr == ip_addr && countArr[4] >= p){
            printk(KERN_WARNING "*** Dropping %pI4 (ICMP), port %d\n", &(iph->daddr), port);
            return NF_DROP;
        	}
	   }
	   
	   if(iph->saddr == src_addr_pc5) {
	   	countArr[5]++;
	   	icmph = icmp_hdr(skb);
       	//udph = udp_hdr(skb);
       	if (iph->daddr == ip_addr && countArr[5] >= p){
            printk(KERN_WARNING "*** Dropping %pI4 (ICMP), port %d\n", &(iph->daddr), port);
            return NF_DROP;
        	}
	   }
	   
	   if(iph->saddr == src_addr_pc6) {
	   	countArr[6]++;
	   	icmph = icmp_hdr(skb);
       	//udph = udp_hdr(skb);
       	if (iph->daddr == ip_addr  && countArr[6] >= p){
            printk(KERN_WARNING "*** Dropping %pI4 (ICMP), port %d\n", &(iph->daddr), port);
            return NF_DROP;
        	}
	   }
       //fprintf(fptr,"%d",num+1);
	   //fclose(fptr);
   }
   return NF_ACCEPT;
}

unsigned int printInfo(void *priv, struct sk_buff *skb,
                 const struct nf_hook_state *state)
{
   struct iphdr *iph;
   char *hook;
   char *protocol;

   switch (state->hook){
     case NF_INET_LOCAL_IN:     hook = "LOCAL_IN";     break; 
     case NF_INET_LOCAL_OUT:    hook = "LOCAL_OUT";    break; 
     case NF_INET_PRE_ROUTING:  hook = "PRE_ROUTING";  break; 
     case NF_INET_POST_ROUTING: hook = "POST_ROUTING"; break; 
     case NF_INET_FORWARD:      hook = "FORWARD";      break; 
     default:                   hook = "IMPOSSIBLE";   break;
   }
   printk(KERN_INFO "*** %s\n", hook); // Print out the hook info

   iph = ip_hdr(skb);
   switch (iph->protocol){
     case IPPROTO_UDP:  protocol = "UDP";   break;
     case IPPROTO_TCP:  protocol = "TCP";   break;
     case IPPROTO_ICMP: protocol = "ICMP";  break;
     default:           protocol = "OTHER"; break;

   }
   // Print out the IP addresses and protocol
   printk(KERN_INFO "    %pI4  --> %pI4 (%s)\n", 
                    &(iph->saddr), &(iph->daddr), protocol);

   return NF_ACCEPT;
}


int registerFilter(void) {
   printk(KERN_INFO "Registering filters.\n");

   hook1.hook = printInfo;
   hook1.hooknum = NF_INET_LOCAL_OUT;
   hook1.pf = PF_INET;
   hook1.priority = NF_IP_PRI_FIRST;
   nf_register_net_hook(&init_net, &hook1);

   hook2.hook = blockICMP;
   hook2.hooknum = NF_INET_POST_ROUTING;
   hook2.pf = PF_INET;
   hook2.priority = NF_IP_PRI_FIRST;
   nf_register_net_hook(&init_net, &hook2);

   return 0;
}

void removeFilter(void) {
   printk(KERN_INFO "The filters are being removed.\n");
   nf_unregister_net_hook(&init_net, &hook1);
   nf_unregister_net_hook(&init_net, &hook2);
}

module_init(registerFilter);
module_exit(removeFilter);

MODULE_LICENSE("GPL");

