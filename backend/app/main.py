from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from kubernetes import client, config, dynamic
from kubernetes.client import ApiClient
import os
from typing import Dict, List
import glob

app = FastAPI(title="K8s Resource Viewer")

# 配置CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def load_all_configs():
    """加载所有kubeconfig文件"""
    configs = {}
    # 获取当前文件的绝对路径
    current_file = os.path.abspath(__file__)
    # 获取项目根目录
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(current_file)))
    # 构建kubeconfig目录的路径
    kubeconfig_dir = os.path.join(project_root, "kubeconfig")
    
    print(f"Project root: {project_root}")
    print(f"Looking for kubeconfig files in: {kubeconfig_dir}")
    
    if not os.path.exists(kubeconfig_dir):
        print(f"kubeconfig directory does not exist: {kubeconfig_dir}")
        os.makedirs(kubeconfig_dir, exist_ok=True)
        print(f"Created kubeconfig directory: {kubeconfig_dir}")
        return configs

    pattern_k8s = os.path.join(kubeconfig_dir, "k8s*")
    pattern_K8S = os.path.join(kubeconfig_dir, "K8S*")
    
    config_files = glob.glob(pattern_k8s) + glob.glob(pattern_K8S)
    print(f"Found config files: {config_files}")
    
    for config_file in config_files:
        try:
            cluster_name = os.path.basename(config_file)
            configs[cluster_name] = os.path.abspath(config_file)
            print(f"Loaded config for cluster: {cluster_name} at path: {configs[cluster_name]}")
        except Exception as e:
            print(f"Error loading {config_file}: {str(e)}")
    
    print(f"Total clusters loaded: {len(configs)}")
    return configs

def get_k8s_clients(kubeconfig_path: str):
    """获取k8s客户端"""
    try:
        config.load_kube_config(kubeconfig_path)
        api_client = ApiClient()
        dynamic_client = dynamic.DynamicClient(api_client)
        return (
            client.CoreV1Api(),
            client.AppsV1Api(),
            client.NetworkingV1Api(),
            client.BatchV1Api(),
            dynamic_client
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load kubeconfig: {str(e)}")

@app.get("/api/clusters")
async def get_clusters():
    """获取所有集群列表"""
    configs = load_all_configs()
    clusters = list(configs.keys())
    print(f"Returning clusters: {clusters}")
    return {"clusters": clusters}

@app.get("/api/resources/{cluster}")
async def get_cluster_resources(cluster: str):
    """获取指定集群的所有资源"""
    configs = load_all_configs()
    if cluster not in configs:
        raise HTTPException(status_code=404, detail="Cluster not found")
    
    core_v1, apps_v1, networking_v1, batch_v1, dynamic_client = get_k8s_clients(configs[cluster])
    
    try:
        # 获取各种资源
        resources = {
            "nodes": [],
            "pods": [],
            "deployments": [],
            "services": [],
            "ingresses": [],
            "gateways": [],
            "virtualservices": [],
            "jobs": [],
            "cronjobs": []
        }
        
        # 获取节点信息
        try:
            nodes = core_v1.list_node()
            for node in nodes.items:
                resources["nodes"].append({
                    "name": node.metadata.name,
                    "status": node.status.conditions[-1].type if node.status.conditions else "Unknown",
                    "kubelet_version": node.status.node_info.kubelet_version
                })
        except Exception as e:
            print(f"Error fetching nodes: {e}")
        
        # 获取所有命名空间的Pod
        try:
            pods = core_v1.list_pod_for_all_namespaces()
            for pod in pods.items:
                resources["pods"].append({
                    "name": pod.metadata.name,
                    "namespace": pod.metadata.namespace,
                    "status": pod.status.phase,
                    "node": pod.spec.node_name if pod.spec.node_name else "Unknown"
                })
        except Exception as e:
            print(f"Error fetching pods: {e}")
        
        # 获取所有命名空间的Deployment
        try:
            deployments = apps_v1.list_deployment_for_all_namespaces()
            for dep in deployments.items:
                resources["deployments"].append({
                    "name": dep.metadata.name,
                    "namespace": dep.metadata.namespace,
                    "replicas": f"{dep.status.ready_replicas or 0}/{dep.spec.replicas}"
                })
        except Exception as e:
            print(f"Error fetching deployments: {e}")
        
        # 获取所有命名空间的Service
        try:
            services = core_v1.list_service_for_all_namespaces()
            for svc in services.items:
                resources["services"].append({
                    "name": svc.metadata.name,
                    "namespace": svc.metadata.namespace,
                    "type": svc.spec.type,
                    "cluster_ip": svc.spec.cluster_ip
                })
        except Exception as e:
            print(f"Error fetching services: {e}")
        
        # 获取所有命名空间的Ingress
        try:
            ingresses = networking_v1.list_ingress_for_all_namespaces()
            for ing in ingresses.items:
                resources["ingresses"].append({
                    "name": ing.metadata.name,
                    "namespace": ing.metadata.namespace,
                    "hosts": [rule.host for rule in ing.spec.rules] if ing.spec.rules else []
                })
        except Exception as e:
            print(f"Error fetching ingresses: {e}")

        # 获取Istio Gateway
        try:
            gateway_api = dynamic_client.resources.get(
                api_version="networking.istio.io/v1beta1",
                kind="Gateway"
            )
            gateways = gateway_api.get()
            for gw in gateways.items:
                resources["gateways"].append({
                    "name": gw["metadata"]["name"],
                    "namespace": gw["metadata"]["namespace"],
                    "servers": len(gw["spec"].get("servers", [])) if "spec" in gw else 0
                })
        except Exception as e:
            print(f"Error fetching gateways: {e}")

        # 获取Istio VirtualService
        try:
            vs_api = dynamic_client.resources.get(
                api_version="networking.istio.io/v1beta1",
                kind="VirtualService"
            )
            virtual_services = vs_api.get()
            for vs in virtual_services.items:
                resources["virtualservices"].append({
                    "name": vs["metadata"]["name"],
                    "namespace": vs["metadata"]["namespace"],
                    "gateways": vs["spec"].get("gateways", []) if "spec" in vs else [],
                    "hosts": vs["spec"].get("hosts", []) if "spec" in vs else []
                })
        except Exception as e:
            print(f"Error fetching virtual services: {e}")
        
        # 获取所有命名空间的Job
        try:
            jobs = batch_v1.list_job_for_all_namespaces()
            for job in jobs.items:
                resources["jobs"].append({
                    "name": job.metadata.name,
                    "namespace": job.metadata.namespace,
                    "status": "Completed" if job.status.succeeded else "Active" if job.status.active else "Failed"
                })
        except Exception as e:
            print(f"Error fetching jobs: {e}")
        
        # 获取所有命名空间的CronJob
        try:
            cronjobs = batch_v1.list_cron_job_for_all_namespaces()
            for cronjob in cronjobs.items:
                resources["cronjobs"].append({
                    "name": cronjob.metadata.name,
                    "namespace": cronjob.metadata.namespace,
                    "schedule": cronjob.spec.schedule
                })
        except Exception as e:
            print(f"Error fetching cronjobs: {e}")
        
        return resources
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/resources/{cluster}/{resource_type}")
async def get_cluster_resource_type(cluster: str, resource_type: str):
    """获取指定集群的特定资源类型"""
    configs = load_all_configs()
    if cluster not in configs:
        raise HTTPException(status_code=404, detail="Cluster not found")
    
    core_v1, apps_v1, networking_v1, batch_v1, dynamic_client = get_k8s_clients(configs[cluster])
    
    try:
        resources = {resource_type: []}
        
        if resource_type == "nodes":
            try:
                nodes = core_v1.list_node()
                for node in nodes.items:
                    resources[resource_type].append({
                        "name": node.metadata.name,
                        "status": node.status.conditions[-1].type if node.status.conditions else "Unknown",
                        "kubelet_version": node.status.node_info.kubelet_version
                    })
            except Exception as e:
                print(f"Error fetching nodes: {e}")
                
        elif resource_type == "pods":
            try:
                pods = core_v1.list_pod_for_all_namespaces()
                for pod in pods.items:
                    resources[resource_type].append({
                        "name": pod.metadata.name,
                        "namespace": pod.metadata.namespace,
                        "status": pod.status.phase,
                        "node": pod.spec.node_name if pod.spec.node_name else "Unknown"
                    })
            except Exception as e:
                print(f"Error fetching pods: {e}")
                
        elif resource_type == "deployments":
            try:
                deployments = apps_v1.list_deployment_for_all_namespaces()
                for dep in deployments.items:
                    resources[resource_type].append({
                        "name": dep.metadata.name,
                        "namespace": dep.metadata.namespace,
                        "replicas": f"{dep.status.ready_replicas or 0}/{dep.spec.replicas}"
                    })
            except Exception as e:
                print(f"Error fetching deployments: {e}")
                
        elif resource_type == "services":
            try:
                services = core_v1.list_service_for_all_namespaces()
                for svc in services.items:
                    resources[resource_type].append({
                        "name": svc.metadata.name,
                        "namespace": svc.metadata.namespace,
                        "type": svc.spec.type,
                        "cluster_ip": svc.spec.cluster_ip
                    })
            except Exception as e:
                print(f"Error fetching services: {e}")
                
        elif resource_type == "ingresses":
            try:
                ingresses = networking_v1.list_ingress_for_all_namespaces()
                for ing in ingresses.items:
                    resources[resource_type].append({
                        "name": ing.metadata.name,
                        "namespace": ing.metadata.namespace,
                        "hosts": [rule.host for rule in ing.spec.rules] if ing.spec.rules else []
                    })
            except Exception as e:
                print(f"Error fetching ingresses: {e}")

        elif resource_type == "gateways":
            try:
                gateway_api = dynamic_client.resources.get(
                    api_version="networking.istio.io/v1beta1",
                    kind="Gateway"
                )
                gateways = gateway_api.get()
                for gw in gateways.items:
                    resources[resource_type].append({
                        "name": gw["metadata"]["name"],
                        "namespace": gw["metadata"]["namespace"],
                        "servers": len(gw["spec"].get("servers", [])) if "spec" in gw else 0
                    })
            except Exception as e:
                print(f"Error fetching gateways: {e}")

        elif resource_type == "virtualservices":
            try:
                vs_api = dynamic_client.resources.get(
                    api_version="networking.istio.io/v1beta1",
                    kind="VirtualService"
                )
                virtual_services = vs_api.get()
                for vs in virtual_services.items:
                    resources[resource_type].append({
                        "name": vs["metadata"]["name"],
                        "namespace": vs["metadata"]["namespace"],
                        "gateways": vs["spec"].get("gateways", []) if "spec" in vs else [],
                        "hosts": vs["spec"].get("hosts", []) if "spec" in vs else []
                    })
            except Exception as e:
                print(f"Error fetching virtual services: {e}")
                
        elif resource_type == "jobs":
            try:
                jobs = batch_v1.list_job_for_all_namespaces()
                for job in jobs.items:
                    resources[resource_type].append({
                        "name": job.metadata.name,
                        "namespace": job.metadata.namespace,
                        "status": "Completed" if job.status.succeeded else "Active" if job.status.active else "Failed"
                    })
            except Exception as e:
                print(f"Error fetching jobs: {e}")
                
        elif resource_type == "cronjobs":
            try:
                cronjobs = batch_v1.list_cron_job_for_all_namespaces()
                for cronjob in cronjobs.items:
                    resources[resource_type].append({
                        "name": cronjob.metadata.name,
                        "namespace": cronjob.metadata.namespace,
                        "schedule": cronjob.spec.schedule
                    })
            except Exception as e:
                print(f"Error fetching cronjobs: {e}")
        
        return resources[resource_type]
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) 