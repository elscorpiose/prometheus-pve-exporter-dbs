"""
Prometheus collecters for Proxmox VE cluster.
"""
# pylint: disable=too-few-public-methods
# pylint: disable=missing-docstring
# pylint: disable=line-too-long
# pylint: disable=too-many-locals

import random
import itertools

from prometheus_client.core import GaugeMetricFamily


class StatusCollector:
    """
    Collects Proxmox VE Node/VM/CT-Status

    # HELP pve_up Node/VM/CT-Status is online/running
    # TYPE pve_up gauge
    pve_up{id="node/proxmox-host"} 1.0
    pve_up{id="cluster/pvec"} 1.0
    pve_up{id="lxc/101"} 1.0
    pve_up{id="qemu/102"} 1.0
    """

    def __init__(self, pve):
        self._pve = pve

    def collect(self):  # pylint: disable=missing-docstring
        status_metrics = GaugeMetricFamily(
            'pve_up',
            'Node/VM/CT-Status is online/running',
            labels=['id'])

        for entry in self._pve.cluster.status.get():
            if entry['type'] == 'node':
                label_values = [entry['id']]
                status_metrics.add_metric(label_values, entry['online'])
            elif entry['type'] == 'cluster':
                label_values = [f"cluster/{entry['name']}"]
                status_metrics.add_metric(label_values, entry['quorate'])
            else:
                raise ValueError(f"Got unexpected status entry type {entry['type']}")

        for resource in self._pve.cluster.resources.get(type='vm'):
            label_values = [resource['id']]
            status_metrics.add_metric(label_values, resource['status'] == 'running')

        yield status_metrics


class VersionCollector:
    """
    Collects Proxmox VE build information. E.g.:

    # HELP pve_version_info Proxmox VE version info
    # TYPE pve_version_info gauge
    pve_version_info{release="15",repoid="7599e35a",version="4.4"} 1.0
    """

    LABEL_WHITELIST = ['release', 'repoid', 'version']

    def __init__(self, pve):
        self._pve = pve

    def collect(self):  # pylint: disable=missing-docstring
        version_items = self._pve.version.get().items()
        version = {key: value for key, value in version_items if key in self.LABEL_WHITELIST}

        labels, label_values = zip(*version.items())
        metric = GaugeMetricFamily(
            'pve_version_info',
            'Proxmox VE version info',
            labels=labels
        )
        metric.add_metric(label_values, 1)

        yield metric


class ClusterNodeCollector:
    """
    Collects Proxmox VE cluster node information. E.g.:

    # HELP pve_node_info Node info
    # TYPE pve_node_info gauge
    pve_node_info{id="node/proxmox-host", level="c", name="proxmox-host",
        nodeid="0"} 1.0
    """

    def __init__(self, pve):
        self._pve = pve

    def collect(self):  # pylint: disable=missing-docstring
        nodes = [entry for entry in self._pve.cluster.status.get() if entry['type'] == 'node']
        labels = ['id', 'level', 'name', 'nodeid']

        if nodes:
            info_metrics = GaugeMetricFamily(
                'pve_node_info',
                'Node info',
                labels=labels)

            for node in nodes:
                label_values = [str(node[key]) for key in labels]
                info_metrics.add_metric(label_values, 1)

            yield info_metrics


class ClusterInfoCollector:
    """
    Collects Proxmox VE cluster information. E.g.:

    # HELP pve_cluster_info Cluster info
    # TYPE pve_cluster_info gauge
    pve_cluster_info{id="cluster/pvec",nodes="2",quorate="1",version="2"} 1.0
    """

    def __init__(self, pve):
        self._pve = pve

    def collect(self):  # pylint: disable=missing-docstring
        clusters = [entry for entry in self._pve.cluster.status.get() if entry['type'] == 'cluster']

        if clusters:
            # Remove superflous keys.
            for cluster in clusters:
                del cluster['type']

            # Add cluster-prefix to id.
            for cluster in clusters:
                cluster['id'] = f"cluster/{cluster['name']}"
                del cluster['name']

            # Yield remaining data.
            labels = clusters[0].keys()
            info_metrics = GaugeMetricFamily(
                'pve_cluster_info',
                'Cluster info',
                labels=labels)

            for cluster in clusters:
                label_values = [str(cluster[key]) for key in labels]
                info_metrics.add_metric(label_values, 1)

            yield info_metrics


class ClusterResourcesCollector:
    """
    Collects Proxmox VE cluster resources information, i.e. memory, storage, cpu
    usage for cluster nodes and guests.
    """

    def __init__(self, pve):
        self._pve = pve

    def collect(self):  # pylint: disable=missing-docstring
        metrics = {
            'maxdisk': GaugeMetricFamily(
                'pve_disk_size_bytes',
                'Size of storage device',
                labels=['id']),
            'disk': GaugeMetricFamily(
                'pve_disk_usage_bytes',
                'Disk usage in bytes',
                labels=['id']),
            'maxmem': GaugeMetricFamily(
                'pve_memory_size_bytes',
                'Size of memory',
                labels=['id']),
            'mem': GaugeMetricFamily(
                'pve_memory_usage_bytes',
                'Memory usage in bytes',
                labels=['id']),
            'netout': GaugeMetricFamily(
                'pve_network_transmit_bytes',
                'Number of bytes transmitted over the network',
                labels=['id']),
            'netin': GaugeMetricFamily(
                'pve_network_receive_bytes',
                'Number of bytes received over the network',
                labels=['id']),
            'diskwrite': GaugeMetricFamily(
                'pve_disk_write_bytes',
                'Number of bytes written to storage',
                labels=['id']),
            'diskread': GaugeMetricFamily(
                'pve_disk_read_bytes',
                'Number of bytes read from storage',
                labels=['id']),
            'cpu': GaugeMetricFamily(
                'pve_cpu_usage_ratio',
                'CPU usage (value between 0.0 and pve_cpu_usage_limit)',
                labels=['id']),
            'maxcpu': GaugeMetricFamily(
                'pve_cpu_usage_limit',
                'Maximum allowed CPU usage',
                labels=['id']),
            'uptime': GaugeMetricFamily(
                'pve_uptime_seconds',
                'Number of seconds since the last boot',
                labels=['id']),
            'shared': GaugeMetricFamily(
                'pve_storage_shared',
                'Whether or not the storage is shared among cluster nodes',
                labels=['id']),
        }

        info_metrics = {
            'guest': GaugeMetricFamily(
                'pve_guest_info',
                'VM/CT info',
                labels=['id', 'node', 'name', 'type', 'template', 'tags']),
            'storage': GaugeMetricFamily(
                'pve_storage_info',
                'Storage info',
                labels=['id', 'node', 'storage']),
        }

        info_lookup = {
            'lxc': {
                'labels': ['id', 'node', 'name', 'type', 'template', 'tags'],
                'gauge': info_metrics['guest'],
            },
            'qemu': {
                'labels': ['id', 'node', 'name', 'type', 'template', 'tags'],
                'gauge': info_metrics['guest'],
            },
            'storage': {
                'labels': ['id', 'node', 'storage'],
                'gauge': info_metrics['storage'],
            },
        }

        for resource in self._pve.cluster.resources.get():
            restype = resource['type']

            if restype in info_lookup:
                labels = info_lookup[restype]['labels']
                label_values = [str(resource.get(key, '')) for key in labels]
                info_lookup[restype]['gauge'].add_metric(label_values, 1)

            label_values = [resource['id']]
            for key, metric_value in resource.items():
                if key in metrics:
                    metrics[key].add_metric(label_values, metric_value)

        return itertools.chain(metrics.values(), info_metrics.values())

class SnapshotsCollector:
    """
    Collects info about QEMU VM Snapshots
    """
    def __init__(self,pve):
        self._pve = pve

    def collect(self): # pylint: disable=missing-docstring
        snapshots_metrics = GaugeMetricFamily(
            'pve_snapshots',
            'Proxmox VM Snapshot',
            labels=['id', 'node', 'description','name','vmstate','vmname'])#snaptime

        for node in self._pve.nodes.get():
            #print(node)
            for vmdata in self._pve.nodes(node['node']).qemu.get():
                #print(vmdata)
                snapshots = self._pve.nodes(node['node']).qemu(vmdata['vmid']).snapshot.get()
                for snapshot in snapshots:
                    #print (snapshot)
                    if snapshot['name'] != 'current':
                        label_values = [f'{vmdata["vmid"]}',node['node'],snapshot['description'],snapshot['name'],f'{snapshot["vmstate"]}',vmdata['name']]
                        #,f'{snapshot["snaptime"]}'
                        snapshots_metrics.add_metric(label_values,snapshot["snaptime"])
        return [snapshots_metrics]




class BackupStorageCollector:
    """
    Collects Proxmox VE backups from pbs storage,
    needs PVEDataStoreAdmin permission (maybe lower, but i stopped at this level) on said pbs storage

    # HELP pve_backups Backups info
    # TYPE pve_backups gauge
    pve_backups{id=;size=;state=;timestamp=;vmname=} 1.0

    """

    def __init__(self, pve):
        self._pve = pve

    def collect(self):# pylint: disable=too-many-branches
        cluster_min = int(self._pve.cluster.options.get()["next-id"]["lower"])
        cluster_max = int(self._pve.cluster.options.get()["next-id"]["upper"])
        pools_vmid = {}
        backups_vmid = []
        pools_vms=[]
        backup_storage_labels = ['avail','used','used_fraction','storage','shared','active']
        backups_labels = ['vmname','size','timestamp','id','state','storage','pool']
        info_missing_backups = GaugeMetricFamily(
            'pve_missing_backups',
            'VM is in pool but no backup finded',
            labels=['vmid','vmname','status','node','pool']
        )
        info_backup_storage = GaugeMetricFamily(
            'pve_backup_storage',
            'metrics for PBS',
            labels = backup_storage_labels)
        info_orphaned_backups = GaugeMetricFamily(
            'pve_orphaned_backups',
            'VM is with backup but not in pool',
            labels = backups_labels)
        info_backups_metrics = GaugeMetricFamily(
            'pve_backups',
            'Backups info',
            labels=backups_labels)
        for pool in self._pve.pools.get():
            for pool_vm in self._pve.pools(pool['poolid']).get()['members']:
                pools_vmid[pool_vm['vmid']]=pool['poolid']
                pools_vms.append(pool_vm)
        node = random.choice(self._pve.nodes.get())
        for pbs_storage in [entry for entry in self._pve.nodes(node['node']).storage.get() if entry['type'] == 'pbs']:# pylint: disable=too-many-nested-blocks
            if pbs_storage:
                #for label in info_backup_storage.labels:
                label_values = [str(pbs_storage[key]) for key in backup_storage_labels]
                if label_values:
                    info_backup_storage.add_metric(label_values,1)
                pbs_backups = self._pve.nodes(node['node']).storage(pbs_storage['storage']).content.get()
                if pbs_backups:
                    for pbs_backup in pbs_backups:
                        backups_vmid.append(pbs_backup['vmid'])
                        if pbs_backup["vmid"] < cluster_max and pbs_backup["vmid"] > cluster_min:
                            if 'notes' in pbs_backup.keys():
                                vm_backup_note = pbs_backup['notes']
                            else:
                                vm_backup_note = f'{pbs_backup["vmid"]}'
                            if 'verification' in pbs_backup:
                                verification = pbs_backup['verification']['state']
                            else:
                                verification = 'none'
                            if pbs_backup['vmid'] not in pools_vmid.keys():# pylint: disable=consider-iterating-dictionary
                                info_orphaned_backups.add_metric((vm_backup_note,f'{pbs_backup["size"]}',f'{pbs_backup["ctime"]}',f'{pbs_backup["vmid"]}',verification,pbs_storage['storage'],'none'), 1)
                            else:
                                info_backups_metrics.add_metric((vm_backup_note,f'{pbs_backup["size"]}',f'{pbs_backup["ctime"]}',f'{pbs_backup["vmid"]}',verification,pbs_storage['storage'],pools_vmid[pbs_backup["vmid"]]), 1)
        for pools_vm in pools_vms:
            if pools_vm['vmid'] not in backups_vmid:
                info_missing_backups.add_metric((f'{pools_vm["vmid"]}',pools_vm['name'],pools_vm['status'],pools_vm['node'],pools_vmid[pools_vm['vmid']]),1)
        bkp_metrics={
            'orphaned_backups': info_orphaned_backups, 
            'backup_storage': info_backup_storage,
            'missing_backups': info_missing_backups,
            'backups_metrics': info_backups_metrics
        }
        #bkp_metrics = itertools.chain(info_backups_metrics_2,info_backups_metrics)
        return bkp_metrics.values()#info_backups_metrics
