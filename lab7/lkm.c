#include<linux/kernel.h>
#include<linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include<linux/inet.h>

static struct nf_hook_ops nfho;


unsigned int hook_func(void *priv, struct sk_buff *skb,
                 const struct nf_hook_state *state)
{
  struct iphdr *iph;
  struct tcphdr *tcph;

  iph = ip_hdr(skb);
  tcph = (void *)iph+iph->ihl*4;
  unsigned int src_ip = (unsigned int)iph->saddr;
  unsigned int dest_ip = (unsigned int)iph->daddr;
  //Rule 1
  if(iph->protocol == IPPROTO_TCP && tcph -> dest == htons(23) && iph->saddr == in_aton("10.0.2.9") && iph->daddr == in_aton("10.0.2.11")){
  return NF_DROP;
}
  //Rule 3
  if(iph->protocol == IPPROTO_TCP && tcph -> dest == htons(22) && src_ip == in_aton("10.0.2.9") && dest_ip == in_aton("10.0.2.11")){
  return NF_DROP;
}
  //Rule 2
  if(iph -> protocol == IPPROTO_TCP && src_ip == in_aton("10.0.2.9") && dest_ip == in_aton("157.240.13.35")){
   return NF_DROP;
}
  else{
  return NF_ACCEPT;
  }
  // Rule 1: Preventing VM A from doing telnet to VM B
  // Rule 2: Preventing VM A from visiting a website
  // Rule 3: Preventing VM A from doing SSH to VM B


return 0;
}


int setUpFilter(void) {
        printk(KERN_INFO "Registering a Telnet filter.\n");
        nfho.hook = hook_func; 
        nfho.hooknum = NF_INET_POST_ROUTING;
        nfho.pf = PF_INET;
        nfho.priority = NF_IP_PRI_FIRST;

        // Register the hook.
        nf_register_hook(&nfho);
        return 0;
}

void removeFilter(void) {
        printk(KERN_INFO "Telnet filter is being removed.\n");
        nf_unregister_hook(&nfho);
}

module_init(setUpFilter);
module_exit(removeFilter);

MODULE_LICENSE("GPL");