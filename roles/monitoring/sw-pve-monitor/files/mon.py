from proxmoxer import ProxmoxAPI
import os 

prox = ProxmoxAPI(sudo=False, timeout=10, backend='local')

prometheus_output_file = os.getenv("OUTPUT", "/tmp/cluster.prom")

version = prox.version.get()
print(version['release'])

Nodes_maxmem_usage = {}
Nodes_mem_usage = {}

res = prox.cluster.resources.get()

for pve_node in res:
        if (pve_node['type'] != 'node' ):
                continue
        Nodes_maxmem_usage[pve_node['node']]=0
        Nodes_mem_usage[pve_node['node']]=0

with open(prometheus_output_file, 'w') as prom_file:
        for pve_vm in res:
                if (pve_vm['type'] != 'lxc' and pve_vm['type'] != 'qemu' ):
                        continue
                node_name=pve_vm['node']
                name=pve_vm['name']
                cpu=pve_vm['cpu']
                maxcpu=pve_vm['maxcpu']
                mem=pve_vm['mem']
                maxmem=pve_vm['maxmem']
                status=0
                if pve_vm['status'] == 'running':
                    status=1
                id=pve_vm['vmid']
                Nodes_maxmem_usage[node_name]+=maxmem
                Nodes_mem_usage[node_name]+=mem
                prom_file.write(f'pve_rosource_cpu{{node="{node_name}",name="{name}",pve_id="{id}"}} {cpu}\n')
                prom_file.write(f'pve_rosource_maxcpu{{node="{node_name}",name="{name}",pve_id="{id}"}} {maxcpu}\n')
                prom_file.write(f'pve_rosource_mem{{node="{node_name}",name="{name}",pve_id="{id}"}} {mem}\n')
                prom_file.write(f'pve_rosource_maxmem{{node="{node_name}",name="{name}",pve_id="{id}"}} {maxmem}\n')
                prom_file.write(f'pve_rosource_status{{node="{node_name}",name="{name}",pve_id="{id}"}} {status}\n')


        for pve_node in res:
                if (pve_node['type'] != 'node' ):
                        continue
                node_name=pve_node['node']
                cpu=pve_node['cpu']
                maxcpu=pve_node['maxcpu']
                mem=pve_node['mem']
                maxmem=pve_node['maxmem']
                resource_maxmem_usage = Nodes_maxmem_usage[node_name] / maxmem * 100
                resource_mem_usage =  Nodes_mem_usage[node_name] / maxmem * 100
                prom_file.write(f'pve_overview_node_maxmem_bytes{{node="{node_name}"}} {maxmem}\n')
                prom_file.write(f'pve_overview_node_mem_usage_bytes{{node="{node_name}"}} {mem}\n')
                prom_file.write(f'pve_overview_node_maxcpu_count{{node="{node_name}"}} {maxcpu}\n')
                prom_file.write(f'pve_overview_node_cpu_usage_count{{node="{node_name}"}} {cpu}\n')
                prom_file.write(f'pve_overview_node_maxmem_percent{{node="{node_name}"}} {resource_maxmem_usage}\n')
                prom_file.write(f'pve_overview_node_mem_percent{{node="{node_name}"}} {resource_mem_usage}\n')
